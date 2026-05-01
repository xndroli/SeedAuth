import { createHash } from "node:crypto";
import { GuardianRpcAdapter } from "../../core/guardian-rpc.js";
import { SOLANA_SEED_VAULT_AAGUID } from "../../core/test-utils/mock-tee.js";
import {
  type AttestationObject,
  SeedShieldErrorCode,
  type VerificationResult,
} from "../../core/types.js";

export class AttestationVerifier {
  private readonly guardianRpc: GuardianRpcAdapter;

  constructor(guardianRpc: GuardianRpcAdapter = new GuardianRpcAdapter()) {
    this.guardianRpc = guardianRpc;
  }

  /**
   * Verifies a hardware-attested passkey registration or authentication.
   * @param attestation The attestation object from the client SDK.
   * @param origin The expected Relying Party origin (e.g., 'https://exchange.com').
   */
  async verify(attestation: AttestationObject, origin: string): Promise<VerificationResult> {
    const timestamp = new Date().toISOString();

    try {
      // 1. Basic Origin Binding Check (FR8)
      if (attestation.rpId !== origin) {
        return this.createErrorResult(
          SeedShieldErrorCode.ORIGIN_MISMATCH,
          "Origin mismatch",
          timestamp,
        );
      }

      // 2. Decode and Parse AuthData
      // Note: Real FIDO2 uses CBOR, but our MockTEE uses JSON-in-Base64 for Phase 1.
      const authData = JSON.parse(Buffer.from(attestation.attestationObject, "base64").toString());

      // 3. Cryptographic Origin Binding Check (FR8)
      const expectedRpIdHash = createHash("sha256").update(origin).digest("base64");
      if (authData.rpIdHash !== expectedRpIdHash) {
        return this.createErrorResult(
          SeedShieldErrorCode.ORIGIN_MISMATCH,
          "Cryptographic RP ID mismatch",
          timestamp,
        );
      }

      // 4. AAGUID Enforcement (FR7)
      if (authData.aaguid !== SOLANA_SEED_VAULT_AAGUID) {
        return {
          success: false,
          errorCode: SeedShieldErrorCode.UNTRUSTED_AAGUID,
          message: "Hardware tier not trusted",
          attestationStatus: "SOFTWARE_BACKED",
          timestamp,
        };
      }

      // 5. Hardware Attestation Flag Check (bit 6 of flags)
      const isHardwareAttested = (authData.flags & 0x40) !== 0;
      if (!isHardwareAttested) {
        return {
          success: false,
          errorCode: SeedShieldErrorCode.UNTRUSTED_AAGUID,
          message: "Attestation flag missing",
          attestationStatus: "SOFTWARE_BACKED",
          timestamp,
        };
      }

      // 6. Guardian RPC Verification (SGT Quote Integrity)
      const guardianResponse = await this.guardianRpc.verifySgtQuote(
        attestation.attestationObject,
        attestation.sgtMetadata,
      );

      if (!guardianResponse.valid) {
        return this.createErrorResult(
          (guardianResponse.error as SeedShieldErrorCode) ||
            SeedShieldErrorCode.INVALID_TEEPIN_QUOTE,
          "Guardian verification failed",
          timestamp,
        );
      }

      // 7. Success!
      return {
        success: true,
        attestationStatus: "VALID_HARDWARE",
        timestamp,
        deviceId: guardianResponse.deviceId,
      };
    } catch (_error) {
      return this.createErrorResult(
        SeedShieldErrorCode.INTERNAL_ERROR,
        "Failed to process attestation",
        timestamp,
      );
    }
  }

  private createErrorResult(
    errorCode: SeedShieldErrorCode,
    message: string,
    timestamp: string,
  ): VerificationResult {
    return {
      success: false,
      errorCode,
      message,
      attestationStatus: "INVALID",
      timestamp,
    };
  }
}
