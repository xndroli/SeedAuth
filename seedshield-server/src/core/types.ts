/**
 * Rosetta Stone: Shared Type Definitions
 * Aligns Kotlin models and TypeScript types for SeedShield.
 */

export interface AttestationObject {
  /** Attestation statement format (e.g., 'android-safetynet') */
  fmt: string;
  /** Base64-encoded FIDO2 attestation object */
  attestationObject: string;
  /** Relying Party Identifier (Origin Domain) */
  rpId: string;
  /** The challenge/nonce provided by the server to prevent replay */
  challenge: string;
  /** Seeker Genesis Token metadata (optional for mock) */
  sgtMetadata?: string;
}

export interface VerificationResult {
  success: boolean;
  errorCode?: SeedShieldErrorCode;
  message?: string;
  attestationStatus: AttestationStatus;
  timestamp: string;
  deviceId?: string;
}

export type AttestationStatus = "VALID_HARDWARE" | "SOFTWARE_BACKED" | "INVALID" | "REVOKED";

export enum SeedShieldErrorCode {
  INVALID_TEEPIN_QUOTE = "INVALID_TEEPIN_QUOTE",
  ORIGIN_MISMATCH = "ORIGIN_MISMATCH",
  UNTRUSTED_AAGUID = "UNTRUSTED_AAGUID",
  VERSION_DEPRECATED = "VERSION_DEPRECATED",
  USER_VERIFICATION_FAILED = "USER_VERIFICATION_FAILED",
  INTERNAL_ERROR = "INTERNAL_ERROR",
}
