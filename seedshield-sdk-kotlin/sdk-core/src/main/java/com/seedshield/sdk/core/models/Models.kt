package com.seedshield.sdk.core.models

/**
 * Rosetta Stone: Shared Type Definitions
 * Aligns Kotlin models and TypeScript types for SeedShield.
 */

data class AttestationObject(
    /** Attestation statement format (e.g., 'android-safetynet') */
    val fmt: String,
    /** Base64-encoded FIDO2 attestation object */
    val attestationObject: String,
    /** Relying Party Identifier (Origin) */
    val rpId: String,
    /** Seeker Genesis Token metadata */
    val sgtMetadata: String? = null
)

enum class AttestationStatus {
    VALID_HARDWARE, SOFTWARE_BACKED, INVALID, REVOKED
}

enum class SeedShieldErrorCode {
    INVALID_TEEPIN_QUOTE,
    ORIGIN_MISMATCH,
    UNTRUSTED_AAGUID,
    VERSION_DEPRECATED,
    USER_VERIFICATION_FAILED,
    INTERNAL_ERROR
}

data class VerificationResult(
    val success: Boolean,
    val errorCode: SeedShieldErrorCode? = null,
    val message: String? = null,
    val attestationStatus: AttestationStatus,
    val timestamp: String,
    val deviceId: String? = null
)
