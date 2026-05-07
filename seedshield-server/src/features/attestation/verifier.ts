import { createHash } from "node:crypto";
import { decode } from "cbor-x";
import semver from "semver";
import { CONFIG } from "../../core/config.js";
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
   * @param clientVersion The client SDK version (from X-SeedShield-Version header).
   */
  async verify(
    attestation: AttestationObject,
    origin: string,
    expectedChallenge: string,
    clientVersion?: string,
  ): Promise<VerificationResult> {
    const timestamp = Date.now();
    let unverifiedDeviceId: string | undefined;

    try {
      // 1. Input Validation Guards (Finding 1, 2)
      if (!origin || typeof origin !== "string") {
        return this.createErrorResult(SeedShieldErrorCode.INVALID_INPUT, "Invalid origin provided", timestamp);
      }
      
      let originUrl: URL;
      try {
        originUrl = new URL(origin);
      } catch (_e) {
        return this.createErrorResult(SeedShieldErrorCode.INVALID_INPUT, "Malformed origin URL", timestamp);
      }
      const rpId = originUrl.hostname;

      // SECURITY: Strictly validate rpId against CONFIG.RP_ID (Finding 1)
      if (rpId !== CONFIG.RP_ID) {
        return this.createErrorResult(SeedShieldErrorCode.ORIGIN_MISMATCH, "Unauthorized RP ID", timestamp);
      }

      if (!attestation || !attestation.attestationObject || !attestation.clientDataJSON) {
        return this.createErrorResult(SeedShieldErrorCode.INVALID_INPUT, "Malformed attestation object", timestamp);
      }

      // 2. Proactive Binary Decoding for Forensic Tracking (AC-1.4.3)
      try {
        const authData = decode(Buffer.from(attestation.attestationObject, "base64"));
        unverifiedDeviceId = authData.deviceId;
      } catch (_e) {
        // Continue to validation
      }

      // 3. SDK Version Deprecation Check (Kill Switch - FR9)
      // AC-5.3.2, AC-5.3.4, AC-5.3.5
      // Prioritize version check before expensive Guardian RPC calls (NFR5)
      if (clientVersion) {
        // SECURITY: Validate clientVersion format to prevent crashes
        if (!semver.valid(clientVersion)) {
          return this.createErrorResult(
            SeedShieldErrorCode.INVALID_INPUT,
            "Invalid client version format",
            timestamp,
            unverifiedDeviceId,
          );
        }

        // SECURITY: Validate MIN_CLIENT_VERSION to prevent server crashes
        const minVer = semver.valid(CONFIG.MIN_CLIENT_VERSION) || "0.0.0";
        if (semver.lt(clientVersion, minVer)) {
          return this.createErrorResult(
            SeedShieldErrorCode.VERSION_DEPRECATED,
            `SDK version ${clientVersion} is deprecated. Minimum required: ${minVer}`,
            timestamp,
            unverifiedDeviceId,
          );
        }
      } else {
        // If version is missing and a minimum is required, reject
        if (CONFIG.MIN_CLIENT_VERSION !== "0.0.0") {
          return this.createErrorResult(
            SeedShieldErrorCode.VERSION_DEPRECATED,
            "Client SDK version header missing",
            timestamp,
            unverifiedDeviceId,
          );
        }
      }

      // 4. Challenge Verification (Anti-Replay)
      // SECURITY FIX: Prioritize signed clientDataJSON challenge (Finding 4)
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

      // 5. Secondary Challenge Check (Anti-Replay)
      // AC-4.3.7: Implement 15-minute challenge expiry check
      const parts = expectedChallenge.split(":");
      if (parts.length > 1) {
        const ts = Number.parseInt(parts[0], 10);
        const now = Date.now();
        const fifteenMinutes = 15 * 60 * 1000;
        
        // SECURITY FIX: Prevent NaN injection and enforce 15-minute window if timestamp is present (Finding 3)
        if (Number.isNaN(ts) || now - ts > fifteenMinutes) {
          return this.createErrorResult(
            SeedShieldErrorCode.CHALLENGE_EXPIRED,
            "Challenge has expired or is invalid (15-minute window)",
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

      // 6. Binary Validation
      const authData = decode(Buffer.from(attestation.attestationObject, "base64"));

      // 7. Cryptographic Origin Binding Check (FR8)
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

      // 9. AAGUID Enforcement (FR7)
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

      // 10. Hardware Attestation Flag Check (bit 6 of flags)
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

      // 11. Guardian RPC Verification (SGT Quote Integrity)
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

      // 12. Success! (Verified Identity)
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
    timestamp: number,
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
    timestamp: number,
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
