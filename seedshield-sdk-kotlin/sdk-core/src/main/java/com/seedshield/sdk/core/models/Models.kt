package com.seedshield.sdk.core.models

import kotlinx.serialization.Serializable

/**
 * Rosetta Stone: Shared Type Definitions
 * Aligns Kotlin models and TypeScript types for SeedShield.
 */

@Serializable
data class AttestationObject(
    /** Attestation statement format (e.g., 'android-safetynet') */
    val fmt: String,
    /** Base64-encoded FIDO2 attestation object */
    val attestationObject: String,
    /** Base64-encoded client data JSON */
    val clientDataJSON: String,
    /** Relying Party Identifier (Origin) */
    val rpId: String,
    /** The Authenticator Attestation GUID (Hardware ID) */
    val aaguid: String,
    /** The challenge/nonce provided by the server to prevent replay */
    val challenge: String,
    /** Seeker Genesis Token metadata */
    val sgtMetadata: String
)

@Serializable
enum class AttestationStatus {
    VALID_HARDWARE, SOFTWARE_BACKED, INVALID, REVOKED
}

@Serializable
enum class SeedShieldErrorCode {
    INVALID_TEEPIN_QUOTE,
    CHALLENGE_MISMATCH,
    ORIGIN_MISMATCH,
    UNTRUSTED_AAGUID,
    VERSION_DEPRECATED,
    USER_VERIFICATION_FAILED,
    INTERNAL_ERROR
}

@Serializable
data class VerificationResult(
    val success: Boolean,
    val errorCode: SeedShieldErrorCode? = null,
    val message: String? = null,
    val attestationStatus: AttestationStatus,
    val timestamp: String,
    val deviceId: String? = null,
    val unverifiedDeviceId: String? = null
)

/**
 * Result of the registration flow.
 */
@Serializable
sealed class AttestationResult {
    @Serializable
    data class Success(val attestationObject: AttestationObject) : AttestationResult()

    @Serializable
    data class Failure(
        val errorCode: SeedShieldErrorCode,
        val message: String? = null
    ) : AttestationResult()

    @Serializable
    data object Cancellation : AttestationResult()

    @Serializable
    data object NoPlatformAuthenticator : AttestationResult()
}
