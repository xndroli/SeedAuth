import { Keypair, PublicKey } from "@solana/web3.js";
import { AttestationVerifier } from "../attestation/verifier.js";
import { MultisigManager } from "./squads-manager.js";
import { AttestationObject, SeedShieldErrorCode, VerificationResult } from "../../core/types.js";
import { decode } from "cbor-x";

export interface RegistrationOutcome extends VerificationResult {
  multisigAddress?: string;
}

export class RegistrationHandler {
  constructor(
    private readonly verifier: AttestationVerifier = new AttestationVerifier(),
    private readonly multisigManager: MultisigManager = new MultisigManager()
  ) {}

  /**
   * Orchestrates hardware-attested registration and multisig deployment.
   */
  async register(
    attestation: AttestationObject,
    origin: string,
    challenge: string,
    feePayer: Keypair
  ): Promise<RegistrationOutcome> {
    // 1. Guard: Ensure attestation exists
    if (!attestation?.attestationObject) {
      return {
        success: false,
        attestationStatus: "INVALID",
        timestamp: Date.now(),
        errorCode: SeedShieldErrorCode.INTERNAL_ERROR,
        message: "Malformed attestation: missing attestationObject",
      };
    }

    // 2. Verify Attestation
    const verification = await this.verifier.verify(attestation, origin, challenge);

    if (!verification.success || verification.attestationStatus !== "VALID_HARDWARE") {
      return verification;
    }

    // 3. Extract User Public Key from Attestation Object
    // In a real FIDO2 flow, the public key is in the authData
    try {
      const authData = decode(Buffer.from(attestation.attestationObject, "base64"));
      
      // SECURITY: Ensure we have a valid public key to seed the multisig
      // In this mock/Phase 1, we assume the public key is available in the decoded authData
      // or we use the deviceId as a proxy for testing if needed.
      // For Squads, we NEED the actual PublicKey.
      
      if (!authData.credentialPublicKey) {
        throw new Error("Missing credentialPublicKey in attestation");
      }

      // Check if credentialPublicKey is 32 bytes (raw Ed25519)
      const keyBuffer = Buffer.from(authData.credentialPublicKey);
      if (keyBuffer.length !== 32) {
         throw new Error(`Invalid public key length: expected 32, got ${keyBuffer.length}`);
      }

      const userPublicKey = new PublicKey(keyBuffer);

      // 4. Ensure Multisig
      const multisigPda = await this.multisigManager.ensureMultisig(
        userPublicKey,
        feePayer
      );

      return {
        ...verification,
        multisigAddress: multisigPda.toBase58(),
      };
    } catch (error) {
      console.error("Registration handler failed:", error);
      return {
        ...verification,
        success: false,
        errorCode: SeedShieldErrorCode.INTERNAL_ERROR,
        message: "Failed to deploy identity multisig",
      };
    }
  }
}
