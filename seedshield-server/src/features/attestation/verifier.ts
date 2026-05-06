import { createHash } from "node:crypto";
import { decode } from "cbor-x";
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
    let unverifiedDeviceId: string | undefined;

    try {
      // 1. Origin Normalization (Standard Compliance)
      const originUrl = new URL(origin);
      const rpId = originUrl.hostname;

      // 2. Proactive Binary Decoding for Forensic Tracking (AC-1.4.3)
      // SECURITY FIX: Now using proper CBOR decoding
      try {
        const authData = decode(Buffer.from(attestation.attestationObject, "base64"));
        unverifiedDeviceId = authData.deviceId;
      } catch (_e) {
        // Continue to validation; unverifiedDeviceId remains undefined
      }

      // 3. Challenge Verification (Anti-Replay)
      // SECURITY FIX: Verify challenge against both property and clientDataJSON (WebAuthn Standard)
      // AC-4.3.7: Implement 15-minute challenge expiry check
      const [challengeTs] = expectedChallenge.split(":");
      if (challengeTs) {
        const ts = parseInt(challengeTs, 10);
        const now = Date.now();
        const fifteenMinutes = 15 * 60 * 1000;
        if (now - ts > fifteenMinutes) {
          return this.createErrorResult(
            SeedShieldErrorCode.CHALLENGE_EXPIRED,
            "Challenge has expired (15-minute window)",
            timestamp,
            unverifiedDeviceId,
          );
        }
      }

      if (attestation.challenge !== expectedChallenge) {
        return this.createErrorResult(
          SeedShieldErrorCode.CHALLENGE_MISMATCH,
          "Challenge mismatch / Replay attempt detected",
          timestamp,
          unverifiedDeviceId,
        );
      }

      try {
        const clientData = JSON.parse(Buffer.from(attestation.clientDataJSON, "base64").toString("utf-8"));
        
        if (clientData.challenge !== expectedChallenge) {
          return this.createErrorResult(
            SeedShieldErrorCode.CHALLENGE_MISMATCH,
            "Cryptographic challenge mismatch in clientDataJSON",
            timestamp,
            unverifiedDeviceId,
          );
        }

        if (clientData.origin !== origin) {
           return this.createErrorResult(
             SeedShieldErrorCode.ORIGIN_MISMATCH,
             "Origin mismatch in clientDataJSON",
             timestamp,
             unverifiedDeviceId,
           );
        }

        // Standard WebAuthn type for registration is 'webauthn.create'
        if (clientData.type !== "webauthn.create" && clientData.type !== "webauthn.get") {
           return this.createErrorResult(
             SeedShieldErrorCode.INTERNAL_ERROR,
             "Invalid WebAuthn type in clientDataJSON",
             timestamp,
             unverifiedDeviceId,
           );
        }
      } catch (_e) {
        return this.createErrorResult(
          SeedShieldErrorCode.INTERNAL_ERROR,
          "Failed to parse or validate clientDataJSON",
          timestamp,
          unverifiedDeviceId,
        );
      }

      // 4. Basic Origin Binding Check (FR8)
      if (attestation.rpId !== rpId) {
        return this.createErrorResult(
          SeedShieldErrorCode.ORIGIN_MISMATCH,
          "Origin mismatch",
          timestamp,
          unverifiedDeviceId,
        );
      }

      // 5. Binary Validation
      const authData = decode(Buffer.from(attestation.attestationObject, "base64"));

      // 6. Cryptographic Origin Binding Check (FR8)
      const expectedRpIdHash = createHash("sha256").update(rpId).digest("base64");
      const actualRpIdHash = Buffer.from(authData.rpIdHash).toString("base64");
      if (actualRpIdHash !== expectedRpIdHash) {
        return this.createErrorResult(
          SeedShieldErrorCode.ORIGIN_MISMATCH,
          "Cryptographic RP ID mismatch",
          timestamp,
          unverifiedDeviceId,
        );
      }

      // 7. AAGUID Enforcement (FR7)
      if (authData.aaguid !== SOLANA_SEED_VAULT_AAGUID) {
        return this.createResult(
          false,
          "SOFTWARE_BACKED",
          timestamp,
          SeedShieldErrorCode.UNTRUSTED_AAGUID,
          "Hardware tier not trusted",
          undefined,
          unverifiedDeviceId,
        );
      }

      // 8. Hardware Attestation Flag Check (bit 6 of flags)
      const isHardwareAttested = (authData.flags & AUTH_DATA_FLAGS.AT) !== 0;
      if (!isHardwareAttested) {
        return this.createResult(
          false,
          "SOFTWARE_BACKED",
          timestamp,
          SeedShieldErrorCode.UNTRUSTED_AAGUID,
          "Attestation flag missing",
          undefined,
          unverifiedDeviceId,
        );
      }

      // 9. Guardian RPC Verification (SGT Quote Integrity)
      const guardianResponse = await this.guardianRpc.verifySgtQuote(
        attestation.attestationObject,
        attestation.sgtMetadata,
      );

      if (!guardianResponse.valid) {
        // SECURITY FIX: Sanitize upstream errors to prevent leakage
        const sanitizedError = this.mapGuardianError(guardianResponse.error);
        return this.createErrorResult(
          sanitizedError,
          "Guardian verification failed",
          timestamp,
          unverifiedDeviceId,
        );
      }

      // 10. Success! (Verified Identity)
      return this.createResult(
        true,
        "VALID_HARDWARE",
        timestamp,
        undefined,
        undefined,
        guardianResponse.deviceId || unverifiedDeviceId,
      );
    } catch (_error) {
      return this.createErrorResult(
        SeedShieldErrorCode.INTERNAL_ERROR,
        "Failed to process attestation",
        timestamp,
        unverifiedDeviceId,
      );
    }
  }

  private mapGuardianError(error?: string): SeedShieldErrorCode {
    // SECURITY FIX: Allow-list of valid error codes
    const validCodes = Object.values(SeedShieldErrorCode);
    if (error && (validCodes as string[]).includes(error)) {
      return error as SeedShieldErrorCode;
    }
    return SeedShieldErrorCode.INVALID_TEEPIN_QUOTE;
  }

  private createResult(
    success: boolean,
    status: AttestationStatus,
    timestamp: string,
    errorCode?: SeedShieldErrorCode,
    message?: string,
    deviceId?: string,
    unverifiedDeviceId?: string,
  ): VerificationResult {
    return {
      success,
      attestationStatus: status,
      timestamp,
      errorCode,
      message,
      deviceId,
      unverifiedDeviceId,
    };
  }

  private createErrorResult(
    errorCode: SeedShieldErrorCode,
    message: string,
    timestamp: string,
    unverifiedDeviceId?: string,
  ): VerificationResult {
    return this.createResult(
      false,
      "INVALID",
      timestamp,
      errorCode,
      message,
      undefined,
      unverifiedDeviceId,
    );
  }
}
