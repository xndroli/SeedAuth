/**
 * Rosetta Stone: Shared Type Definitions
 * Aligns Kotlin models and TypeScript types for SeedShield.
 */

export interface AttestationObject {
  /** Attestation statement format (e.g., 'android-safetynet') */
  fmt: string;
  /** Base64-encoded FIDO2 attestation object */
  attestationObject: string;
  /** Base64-encoded client data JSON containing challenge and origin */
  clientDataJSON: string;
  /** Relying Party Identifier (Origin Domain) */
  rpId: string;
  /** The Authenticator Attestation GUID (Hardware ID) */
  aaguid: string;
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
  /** Epoch milliseconds */
  timestamp: number;
  /** Cryptographically verified device ID */
  deviceId?: string;
  /** Extracted but NOT YET verified device ID (Forensic use only) */
  unverifiedDeviceId?: string;
}

/**
 * Sealed-Error Pattern: Audit-ready error payload with structural metadata.
 */
export interface SealedError {
  code: SeedShieldErrorCode;
  message: string;
  /** Epoch milliseconds */
  timestamp: number;
  deviceId?: string;
  attestationStatus: AttestationStatus;
  /** Cryptographic proof or signature of the error payload (for forensic use) */
  proof?: string;
}

export type AttestationStatus = "VALID_HARDWARE" | "SOFTWARE_BACKED" | "INVALID" | "REVOKED";

export enum SeedShieldErrorCode {
  CERTIFICATE_EXPIRED = "CERTIFICATE_EXPIRED",
  CERTIFICATE_REVOKED = "CERTIFICATE_REVOKED",
  CHALLENGE_EXPIRED = "CHALLENGE_EXPIRED",
  CHALLENGE_MISMATCH = "CHALLENGE_MISMATCH",
  DEVICE_COMPROMISED_ANOMALY = "DEVICE_COMPROMISED_ANOMALY",
  DEVICE_TAMPERED = "DEVICE_TAMPERED",
  DUPLICATE_DEVICE_ID = "DUPLICATE_DEVICE_ID",
  ENCLAVE_BUSY = "ENCLAVE_BUSY",
  ENCLAVE_UNAVAILABLE = "ENCLAVE_UNAVAILABLE",
  FEE_PAYER_EXHAUSTED = "FEE_PAYER_EXHAUSTED",
  GUARDIAN_RPC_FAILED = "GUARDIAN_RPC_FAILED",
  INTERNAL_ERROR = "INTERNAL_ERROR",
  INVALID_INPUT = "INVALID_INPUT",
  INVALID_TEEPIN_QUOTE = "INVALID_TEEPIN_QUOTE",
  INVALID_VAULT_PDA = "INVALID_VAULT_PDA",
  KEY_NOT_FOUND = "KEY_NOT_FOUND",
  MULTISIG_ALREADY_EXECUTED = "MULTISIG_ALREADY_EXECUTED",
  MULTISIG_ALREADY_EXISTS = "MULTISIG_ALREADY_EXISTS",
  MULTISIG_CONFIGURATION_INVALID = "MULTISIG_CONFIGURATION_INVALID",
  MULTISIG_INSUFFICIENT_SIGNERS = "MULTISIG_INSUFFICIENT_SIGNERS",
  MULTISIG_THRESHOLD_DEADLOCK = "MULTISIG_THRESHOLD_DEADLOCK",
  MULTISIG_THRESHOLD_NOT_MET = "MULTISIG_THRESHOLD_NOT_MET",
  MULTISIG_TIMELOCK_ACTIVE = "MULTISIG_TIMELOCK_ACTIVE",
  NON_SEEKER_DEVICE = "NON_SEEKER_DEVICE",
  ORIGIN_MISMATCH = "ORIGIN_MISMATCH",
  SOFTWARE_ATTESTATION_REJECTED = "SOFTWARE_ATTESTATION_REJECTED",
  THROTTLE_LIMIT_EXCEEDED = "THROTTLE_LIMIT_EXCEEDED",
  UNTRUSTED_AAGUID = "UNTRUSTED_AAGUID",
  USER_VERIFICATION_FAILED = "USER_VERIFICATION_FAILED",
  VERSION_DEPRECATED = "VERSION_DEPRECATED",
  ZERO_AAGUID = "ZERO_AAGUID",
}

/**
 * Audit Event Types for forensic categorization and on-chain tracking.
 */
export enum AuditEventType {
  // On-chain Success Events
  REGISTRATION = "REGISTRATION",
  ROTATION = "ROTATION",
  
  // Rejection Events
  SUBSIDIZER_REJECTION = "SUBSIDIZER_REJECTION",
  GUARDIAN_REJECTION = "GUARDIAN_REJECTION",
  THROTTLE_REJECTION = "THROTTLE_REJECTION",
  VERSION_REJECTION = "VERSION_REJECTION",
  
  // Generic/Error
  INTERNAL_ERROR = "INTERNAL_ERROR",
  UNKNOWN = "UNKNOWN",
}
