import { Connection, Keypair, Transaction, PublicKey, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { createHash } from "node:crypto";
import { decode } from "cbor-x";
import { AttestationVerifier } from "../attestation/verifier.js";
import { ThrottlePolicy } from "./throttle.js";
import { NonceManager } from "./nonce-manager.js";
import { AuditManager } from "../multisig/audit-manager.js";
import { 
  type AttestationObject, 
  SeedShieldErrorCode, 
  type VerificationResult,
  type SealedError,
  type AttestationStatus,
  AuditEventType
} from "../../core/types.js";
import { CONFIG } from "../../core/config.js";

export interface SubsidizedSignatureResult {
  success: boolean;
  signedTransaction?: string;
  error?: SealedError;
}

/**
 * FeePayerSubsidizer gates access to the server's fee payer account
 * based on hardware attestation and throttle policies.
 */
export class FeePayerSubsidizer {
  private readonly connection: Connection;

  constructor(
    private readonly verifier: AttestationVerifier = new AttestationVerifier(),
    private readonly throttle: ThrottlePolicy = new ThrottlePolicy(),
    private readonly nonceManager: NonceManager = new NonceManager(),
    private readonly auditManager: AuditManager = new AuditManager(),
    private readonly primaryFeePayer: Keypair = CONFIG.feePayerKeypair,
    private readonly secondaryFeePayer: Keypair | undefined = CONFIG.secondaryFeePayerKeypair,
    rpcEndpoint: string = CONFIG.RPC_ENDPOINT
  ) {
    this.connection = new Connection(rpcEndpoint, "confirmed");
  }

  /**
   * Processes a request to subsidize a transaction's fee.
   * 
   * @param transactionBase64 The base64-encoded Solana transaction.
   * @param attestation The hardware attestation object.
   * @param origin The expected RP origin.
   * @param challenge The challenge used for attestation.
   * @param clientVersion The client SDK version (from X-SeedShield-Version header).
   */
  async requestSubsidizedSignature(
    transactionBase64: string,
    attestation: AttestationObject,
    origin: string,
    challenge: string,
    clientVersion?: string
  ): Promise<SubsidizedSignatureResult> {
    const timestamp = Date.now();

    // 1. Hardware Attestation Gating (AC-4.2.1, AC-4.2.5, AC-5.3.1)
    const verification = await this.verifier.verify(attestation, origin, challenge, clientVersion);

    if (!verification.success || verification.attestationStatus !== "VALID_HARDWARE") {
      const error = this.createSealedError(
        verification.errorCode || SeedShieldErrorCode.SOFTWARE_ATTESTATION_REJECTED,
        verification.message || "Hardware attestation required for subsidized transactions",
        timestamp,
        verification.deviceId || verification.unverifiedDeviceId,
        verification.attestationStatus
      );
      
      const eventType = error.code === SeedShieldErrorCode.VERSION_DEPRECATED 
        ? AuditEventType.VERSION_REJECTION 
        : AuditEventType.SUBSIDIZER_REJECTION;
        
      this.auditManager.logRejection(error, eventType);
      return { success: false, error };
    }

    const deviceId = verification.deviceId!;

    // 2. Throttle Policy Enforcement (AC-4.2.2)
    if (!this.throttle.checkAndIncrement(deviceId)) {
      const error = this.createSealedError(
        SeedShieldErrorCode.THROTTLE_LIMIT_EXCEEDED,
        "Subsidized transaction limit exceeded for this device",
        timestamp,
        deviceId,
        verification.attestationStatus
      );
      this.auditManager.logRejection(error, AuditEventType.THROTTLE_REJECTION);
      return { success: false, error };
    }

    try {
      // 3. Transaction Decoding & Validation (AC-4.2.3, AC-4.2.5)
      const transaction = Transaction.from(Buffer.from(transactionBase64, "base64"));

      // 4. Instruction-set Validation (Security Hardening against Fund Drainage)
      // SECURITY: Ensure all instructions are authorized.
      const isAuthorized = transaction.instructions.every((ix) => 
        CONFIG.AUTHORIZED_PROGRAM_IDS.includes(ix.programId.toBase58())
      );
      if (!isAuthorized) {
        const error = this.createSealedError(
          SeedShieldErrorCode.INTERNAL_ERROR,
          "Transaction contains unauthorized instructions",
          timestamp,
          deviceId,
          verification.attestationStatus
        );
        this.auditManager.logRejection(error, AuditEventType.SUBSIDIZER_REJECTION);
        return { success: false, error };
      }

      // 5. Signer-to-DeviceId Binding & Cryptographic Verification (AC-4.2.5 Security)
      const userPublicKey = this.extractPublicKeyFromAttestation(attestation);
      if (!this.isSignerValid(transaction, userPublicKey)) {
         const error = this.createSealedError(
             SeedShieldErrorCode.USER_VERIFICATION_FAILED,
             "Transaction signer is invalid or cryptographic signature verification failed",
             timestamp,
             deviceId,
             verification.attestationStatus
         );
         this.auditManager.logRejection(error, AuditEventType.SUBSIDIZER_REJECTION);
         return { success: false, error };
      }

      // 6. Durable Nonce Support Validation (AC-4.2.3)
      const isValidNonce = await this.nonceManager.validateNonceUsage(transaction);
      if (!isValidNonce) {
        const error = this.createSealedError(
          SeedShieldErrorCode.INTERNAL_ERROR,
          "Invalid Durable Nonce account usage or blockhash mismatch",
          timestamp,
          deviceId,
          verification.attestationStatus
        );
        this.auditManager.logRejection(error, AuditEventType.SUBSIDIZER_REJECTION);
        return { success: false, error };
      }
      
      // 7. High Availability & Fallback (AC-4.2.4)
      const feePayer = await this.getAuthorizedFeePayer(transaction.feePayer);
      if (!feePayer) {
        const error = this.createSealedError(
            SeedShieldErrorCode.FEE_PAYER_EXHAUSTED,
            "Specified fee payer is unauthorized or has insufficient balance",
            timestamp,
            deviceId,
            verification.attestationStatus
        );
        this.auditManager.logRejection(error, AuditEventType.SUBSIDIZER_REJECTION);
        return { success: false, error };
      }

      // 8. Sign and return
      transaction.partialSign(feePayer);

      return {
        success: true,
        signedTransaction: transaction.serialize({ verifySignatures: false }).toString("base64"),
      };
    } catch (error) {
      console.error("Subsidizer transaction processing failed:", error);
      const sealedError = this.createSealedError(
        SeedShieldErrorCode.INTERNAL_ERROR,
        "Failed to process subsidized transaction signature",
        timestamp,
        deviceId,
        verification.attestationStatus
      );
      this.auditManager.logRejection(sealedError);
      return { success: false, error: sealedError };
    }
  }

  /**
   * Returns the authorized Keypair for the given fee payer public key if it has sufficient balance.
   */
  private async getAuthorizedFeePayer(requestedFeePayer: PublicKey | undefined): Promise<Keypair | undefined> {
    if (!requestedFeePayer) return undefined;

    const minBalance = CONFIG.MIN_FEE_PAYER_BALANCE_SOL * LAMPORTS_PER_SOL;

    let authorizedPair: Keypair | undefined;

    if (requestedFeePayer.equals(this.primaryFeePayer.publicKey)) {
      authorizedPair = this.primaryFeePayer;
    } else if (this.secondaryFeePayer && requestedFeePayer.equals(this.secondaryFeePayer.publicKey)) {
      authorizedPair = this.secondaryFeePayer;
    }

    if (!authorizedPair) return undefined;

    const balance = await this.connection.getBalance(authorizedPair.publicKey);
    return balance > minBalance ? authorizedPair : undefined;
  }

  /**
   * Extracts the public key from the FIDO2 attestation object.
   * TODO: Implement proper COSE key decoding for full FIDO2 compliance.
   */
  private extractPublicKeyFromAttestation(attestation: AttestationObject): PublicKey {
    const authData = decode(Buffer.from(attestation.attestationObject, "base64"));
    if (!authData.credentialPublicKey) {
      throw new Error("Missing credentialPublicKey in attestation");
    }
    return new PublicKey(Buffer.from(authData.credentialPublicKey));
  }

  /**
   * Verifies that the expected public key is a signer and has a valid cryptographic signature.
   */
  private isSignerValid(transaction: Transaction, expectedSigner: PublicKey): boolean {
    // 1. Ensure the expected signer is in the signatures list
    const hasSigner = transaction.signatures.some(sig => sig.publicKey.equals(expectedSigner));
    if (!hasSigner) return false;

    // 2. Cryptographically verify all present signatures (user signature)
    // requireAllSignatures=false because server hasn't signed yet.
    try {
      return transaction.verifySignatures(false);
    } catch (e) {
      return false;
    }
  }

  private createSealedError(
    code: SeedShieldErrorCode,
    message: string,
    timestamp: number,
    deviceId: string | undefined,
    attestationStatus: AttestationStatus
  ): SealedError {
    const error: SealedError = {
      code,
      message,
      timestamp,
      deviceId,
      attestationStatus,
    };

    // SECURITY: Generate a cryptographic proof (seal) for the error payload (Finding 8)
    const proofData = JSON.stringify(error);
    error.proof = createHash("sha256").update(proofData).digest("hex");

    return error;
  }
}
