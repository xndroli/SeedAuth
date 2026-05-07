import { Keypair, PublicKey } from "@solana/web3.js";
import { AttestationVerifier } from "../attestation/verifier.js";
import { MultisigManager } from "../multisig/squads-manager.js";
import {
  type AttestationObject,
  SeedShieldErrorCode,
  type VerificationResult,
} from "../../core/types.js";
import { decode } from "cbor-x";

/**
 * AC-5.2.1, AC-5.2.6: Migration Outcome including forensic and audit data.
 */
export interface MigrationOutcome extends VerificationResult {
  multisigAddress?: string;
  legacyUserId?: string;
}

/**
 * Interface for the platform's user database.
 * Enables the "SIM-swap Kill" wedge by atomically disabling legacy factors.
 */
export interface UserDb {
  /**
   * AC-5.2.1: Validates the legacy session token (e.g., JWT sub check).
   */
  getUserByLegacyToken(token: string): Promise<{ userId: string; smsEnabled: boolean } | null>;
  
  /**
   * AC-5.2.2, AC-5.2.5: Atomically links hardware and disables SMS.
   */
  updateUserMigration(userId: string, hardwarePublicKey: string, multisigPda: string): Promise<void>;
  
  /**
   * Enforcement: Replay and duplicate linkage protection.
   */
  isHardwareLinked(hardwarePublicKey: string): Promise<boolean>;
}

export class MigrationHandler {
  constructor(
    private readonly verifier: AttestationVerifier = new AttestationVerifier(),
    private readonly multisigManager: MultisigManager = new MultisigManager(),
    private readonly userDb: UserDb
  ) {}

  /**
   * AC-5.2.1: Enrollment Flow Implementation
   * AC-5.2.3: Verification of Legacy-to-Hardware Link
   * AC-5.2.5: Squads Multisig Mapping
   */
  async enroll(
    legacyToken: string,
    attestation: AttestationObject,
    origin: string,
    challenge: string,
    feePayer: Keypair
  ): Promise<MigrationOutcome> {
    const timestamp = new Date().toISOString();

    try {
      // 1. Validate Legacy Session Token (Legacy Identity Verification)
      const legacyUser = await this.userDb.getUserByLegacyToken(legacyToken);
      if (!legacyUser) {
        return {
          success: false,
          attestationStatus: "INVALID",
          timestamp,
          errorCode: SeedShieldErrorCode.INTERNAL_ERROR,
          message: "Invalid or expired legacy session token",
        };
      }

      // 2. Verify Hardware Attestation (FR7, AC-5.2.3)
      const verification = await this.verifier.verify(attestation, origin, challenge);

      if (!verification.success || verification.attestationStatus !== "VALID_HARDWARE") {
        return verification;
      }

      // 3. Extract User Public Key from Attestation Object (Hardware Identity Verification)
      const authData = decode(Buffer.from(attestation.attestationObject, "base64"));
      if (!authData.credentialPublicKey) {
        throw new Error("Missing credentialPublicKey in attestation");
      }
      
      const keyBuffer = Buffer.from(authData.credentialPublicKey);
      const userPublicKey = new PublicKey(keyBuffer);
      const hardwarePublicKeyStr = userPublicKey.toBase58();

      // 4. Enforcement: Replay Protection / Existing Linkage
      // AC-5.2.3 Logic: Bind legacy session to specific hardware key
      if (await this.userDb.isHardwareLinked(hardwarePublicKeyStr)) {
        return {
          ...verification,
          success: false,
          errorCode: SeedShieldErrorCode.DUPLICATE_DEVICE_ID,
          message: "This hardware key is already linked to an account",
        };
      }

      // 5. Deploy/Link Identity Multisig (AC-5.2.5, FR11)
      const multisigPda = await this.multisigManager.ensureMultisig(
        userPublicKey,
        feePayer
      );

      // 6. Atomic Transition (AC-5.2.2, Dev Notes)
      // AC-5.2.2: Programmatic way to disable legacy factors
      // updateMeta: sms_enabled = false
      await this.userDb.updateUserMigration(
        legacyUser.userId,
        hardwarePublicKeyStr,
        multisigPda.toBase58()
      );

      return {
        ...verification,
        multisigAddress: multisigPda.toBase58(),
        legacyUserId: legacyUser.userId,
      };
    } catch (error: any) {
      console.error("Migration handler failed:", error);
      return {
        success: false,
        attestationStatus: "INVALID",
        timestamp,
        errorCode: SeedShieldErrorCode.INTERNAL_ERROR,
        message: error.message || "Failed to process migration",
      };
    }
  }
}
