import { createHash } from "node:crypto";
import { AUTH_DATA_FLAGS, SOLANA_SEED_VAULT_AAGUID } from "../../core/constants.js";
import { GuardianRpcAdapter } from "../../core/guardian-rpc.js";
import {
  type AttestationObject,
  type AttestationStatus,
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
   * @param expectedChallenge The challenge/nonce provided by the server to prevent replay.
   */
  async verify(
    attestation: AttestationObject,
    origin: string,
    expectedChallenge: string,
  ): Promise<VerificationResult> {
    const timestamp = new Date().toISOString();

    try {
      // 1. Origin Normalization (Standard Compliance)
      const originUrl = new URL(origin);
      const rpId = originUrl.hostname;

      // 2. Challenge Verification (Anti-Replay)
      if (attestation.challenge !== expectedChallenge) {
        return this.createErrorResult(
          SeedShieldErrorCode.INVALID_TEEPIN_QUOTE,
          "Challenge mismatch / Replay attempt detected",
          timestamp,
        );
      }

      // 3. Basic Origin Binding Check (FR8)
      if (attestation.rpId !== rpId) {
        return this.createErrorResult(
          SeedShieldErrorCode.ORIGIN_MISMATCH,
          "Origin mismatch",
          timestamp,
        );
      }

      // 4. Decode and Parse AuthData
      // Note: Real FIDO2 uses CBOR. In Phase 1 we use Base64 wrapped simulation.
      const authData = JSON.parse(Buffer.from(attestation.attestationObject, "base64").toString());

      // 5. Cryptographic Origin Binding Check (FR8)
      const expectedRpIdHash = createHash("sha256").update(rpId).digest("base64");
      if (authData.rpIdHash !== expectedRpIdHash) {
        return this.createErrorResult(
          SeedShieldErrorCode.ORIGIN_MISMATCH,
          "Cryptographic RP ID mismatch",
          timestamp,
        );
      }

      // 6. AAGUID Enforcement (FR7)
      if (authData.aaguid !== SOLANA_SEED_VAULT_AAGUID) {
        return this.createResult(
          false,
          "SOFTWARE_BACKED",
          timestamp,
          SeedShieldErrorCode.UNTRUSTED_AAGUID,
          "Hardware tier not trusted",
        );
      }

      // 7. Hardware Attestation Flag Check (bit 6 of flags)
      const isHardwareAttested = (authData.flags & AUTH_DATA_FLAGS.AT) !== 0;
      if (!isHardwareAttested) {
        return this.createResult(
          false,
          "SOFTWARE_BACKED",
          timestamp,
          SeedShieldErrorCode.UNTRUSTED_AAGUID,
          "Attestation flag missing",
        );
      }

      // 8. Guardian RPC Verification (SGT Quote Integrity)
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

      // 9. Success!
      return this.createResult(
        true,
        "VALID_HARDWARE",
        timestamp,
        undefined,
        undefined,
        guardianResponse.deviceId,
      );
    } catch (_error) {
      return this.createErrorResult(
        SeedShieldErrorCode.INTERNAL_ERROR,
        "Failed to process attestation",
        timestamp,
      );
    }
  }

  private createResult(
    success: boolean,
    status: AttestationStatus,
    timestamp: string,
    errorCode?: SeedShieldErrorCode,
    message?: string,
    deviceId?: string,
  ): VerificationResult {
    return {
      success,
      attestationStatus: status,
      timestamp,
      errorCode,
      message,
      deviceId,
    };
  }

  private createErrorResult(
    errorCode: SeedShieldErrorCode,
    message: string,
    timestamp: string,
  ): VerificationResult {
    return this.createResult(false, "INVALID", timestamp, errorCode, message);
  }
}
