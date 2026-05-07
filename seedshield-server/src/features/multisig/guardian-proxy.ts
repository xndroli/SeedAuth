import { Connection, Keypair, PublicKey, Transaction } from "@solana/web3.js";
import { createHash } from "node:crypto";
import * as multisig from "@sqds/multisig";
import { CONFIG } from "../../core/config.js";
import { SeedShieldErrorCode, type AttestationObject, type SealedError, AuditEventType } from "../../core/types.js";
import { AttestationVerifier } from "../attestation/verifier.js";
import { MultisigManager } from "./squads-manager.js";
import { ThrottlePolicy } from "../subsidizer/throttle.js";
import { AuditManager } from "./audit-manager.js";

export class InstitutionalGuardianProxy {
  private readonly connection: Connection;
  private readonly multisigManager: MultisigManager;
  private readonly verifier: AttestationVerifier;
  private readonly throttlePolicy: ThrottlePolicy;
  private readonly auditManager: AuditManager;

  constructor(
    connection: Connection = new Connection(CONFIG.RPC_ENDPOINT, "confirmed"),
    multisigManager: MultisigManager = new MultisigManager(),
    verifier: AttestationVerifier = new AttestationVerifier(),
    throttlePolicy: ThrottlePolicy = new ThrottlePolicy(),
    auditManager: AuditManager = new AuditManager()
  ) {
    this.connection = connection;
    this.multisigManager = multisigManager;
    this.verifier = verifier;
    this.throttlePolicy = throttlePolicy;
    this.auditManager = auditManager;
  }

  /**
   * Approves a rotation proposal after verifying identity and hardware attestation.
   * Implement AC-4.3.1, AC-4.3.2, AC-4.3.4, AC-4.3.5, AC-4.3.7.
   * @param multisigPda The multisig being rotated.
   * @param attestation The hardware attestation object.
   * @param transactionBase64 The rotation transaction.
   * @param guardianKeypair The guardian's signing key.
   * @param expectedChallenge The challenge nonce.
   * @param clientVersion The client SDK version (from X-SeedShield-Version header).
   */
  async approveRotation(
    multisigPda: PublicKey,
    attestation: AttestationObject,
    transactionBase64: string,
    guardianKeypair: Keypair,
    expectedChallenge: string,
    clientVersion?: string
  ): Promise<string> {
    const timestamp = Date.now();

    // 1. KYC Mock (Task 4)
    // Assume external KYC success for Phase 1. In production, this would hit a DB/KMS.
    const kycStatus = true;
    if (!kycStatus) {
      throw new Error("KYC_REQUIRED");
    }

    // 2. Identity & Hardware Verification (AC-4.3.2, AC-5.3.1)
    const verification = await this.verifier.verify(
      attestation,
      `https://${attestation.rpId}`, // RP ID from attestation normalized to origin
      expectedChallenge,
      clientVersion
    );

    if (!verification.success) {
      const error: SealedError = {
        code: verification.errorCode || SeedShieldErrorCode.INTERNAL_ERROR,
        message: verification.message || "Attestation verification failed",
        timestamp,
        deviceId: verification.deviceId || verification.unverifiedDeviceId,
        attestationStatus: verification.attestationStatus,
      };
      
      // SECURITY: Generate cryptographic proof of the rejection context (Finding 8)
      const proofData = JSON.stringify({ ...error, multisigPda: multisigPda.toBase58() });
      error.proof = createHash("sha256").update(proofData).digest("hex");

      this.auditManager.logRejection(error, AuditEventType.GUARDIAN_REJECTION);
      throw new Error(error.code);
    }

    // 4. Throttle Policy Check (Sybil Resistance)
    if (verification.deviceId && !this.throttlePolicy.checkAndIncrement(verification.deviceId)) {
      const error: SealedError = {
        code: SeedShieldErrorCode.THROTTLE_LIMIT_EXCEEDED,
        message: "Recovery attempt throttle exceeded",
        timestamp,
        deviceId: verification.deviceId,
        attestationStatus: verification.attestationStatus,
      };

      // SECURITY: Generate cryptographic proof for throttle rejection
      const proofData = JSON.stringify(error);
      error.proof = createHash("sha256").update(proofData).digest("hex");

      this.auditManager.logRejection(error, AuditEventType.THROTTLE_REJECTION);
      throw new Error(error.code);
    }

    // 5. Signer-to-Device Binding (AC-4.3.5)
    const tx = Transaction.from(Buffer.from(transactionBase64, "base64"));
    
    // Verify signatures (partial verify: do not check for all required signatures yet)
    // This ensures the transaction was signed by the key attested in the hardware check.
    if (!tx.verifySignatures(false)) {
      throw new Error(SeedShieldErrorCode.DEVICE_COMPROMISED_ANOMALY);
    }

    // Extract newUserKey from the first signature (the user's new key)
    const newUserKey = tx.signatures.find(s => s.signature !== null)?.publicKey;
    if (!newUserKey) {
      throw new Error("No valid signature found in transaction");
    }

    // 5.5 Signer-to-Device Binding (AC-4.3.5)
    // Verify that the key in the transaction matches the hardware-attested key
    if (verification.deviceId && newUserKey.toBase58() !== verification.deviceId) {
      throw new Error(SeedShieldErrorCode.DEVICE_COMPROMISED_ANOMALY);
    }

    // 6. Idempotency Check (AC-4.3.4)
    // SECURITY FIX: Double-check for existing proposal BEFORE creating a new one (Finding 6)
    let proposalPda = await this.multisigManager.findExistingRotationProposal(multisigPda, newUserKey);

    // 7. Propose if not already exists (Acting as the Guardian co-proposer)
    if (!proposalPda) {
      proposalPda = await this.multisigManager.createRotationProposal(
        multisigPda,
        newUserKey,
        guardianKeypair
      );
    }

    // 7.5 Timelock Verification (AC-4.3.3)
    // SECURITY FIX: Ensure the multisig HAS a timelock enabled (Finding 9)
    const multisigAccount = await multisig.accounts.Multisig.fromAccountAddress(this.connection, multisigPda);
    if (Number(multisigAccount.timeLock) < CONFIG.RECOVERY_TIMELOCK_SECONDS) {
        throw new Error(SeedShieldErrorCode.MULTISIG_CONFIGURATION_INVALID);
    }

    // 8. Co-sign (Vote Approve) (AC-4.3.1)
    const signature = await multisig.rpc.multisigVoteV2({
      connection: this.connection,
      feePayer: guardianKeypair,
      multisigPda,
      transactionPda: proposalPda,
      vote: multisig.types.Vote.Approve,
      programId: CONFIG.SQUADS_PROGRAM_ID,
    });

    // 9. Confirm Vote
    const latestBlockhash = await this.connection.getLatestBlockhash();
    await this.connection.confirmTransaction({
      signature,
      ...latestBlockhash
    }, "confirmed");

    return signature;
  }
}
