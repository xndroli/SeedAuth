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
    CERTIFICATE_EXPIRED,
    CERTIFICATE_REVOKED,
    CHALLENGE_EXPIRED,
    CHALLENGE_MISMATCH,
    DEVICE_COMPROMISED_ANOMALY,
    DEVICE_TAMPERED,
    DUPLICATE_DEVICE_ID,
    ENCLAVE_BUSY,
    ENCLAVE_UNAVAILABLE,
    FEE_PAYER_EXHAUSTED,
    GUARDIAN_RPC_FAILED,
    INTERNAL_ERROR,
    INVALID_TEEPIN_QUOTE,
    INVALID_VAULT_PDA,
    KEY_NOT_FOUND,
    MULTISIG_ALREADY_EXECUTED,
    MULTISIG_ALREADY_EXISTS,
    MULTISIG_INSUFFICIENT_SIGNERS,
    MULTISIG_THRESHOLD_DEADLOCK,
    MULTISIG_THRESHOLD_NOT_MET,
    MULTISIG_TIMELOCK_ACTIVE,
    NON_SEEKER_DEVICE,
    ORIGIN_MISMATCH,
    SOFTWARE_ATTESTATION_REJECTED,
    THROTTLE_LIMIT_EXCEEDED,
    UNTRUSTED_AAGUID,
    USER_VERIFICATION_FAILED,
    VERSION_DEPRECATED,
    ZERO_AAGUID
}

@Serializable
data class VerificationResult(
    val success: Boolean,
    val errorCode: SeedShieldErrorCode? = null,
    val message: String? = null,
    val attestationStatus: AttestationStatus,
    /** Epoch milliseconds */
    val timestamp: Long,
    val deviceId: String? = null,
    val unverifiedDeviceId: String? = null
)

/**
 * Sealed-Error Pattern: Audit-ready error payload with structural metadata.
 */
@Serializable
data class SealedError(
    val code: SeedShieldErrorCode,
    val message: String,
    /** Epoch milliseconds */
    val timestamp: Long,
    val deviceId: String? = null,
    val attestationStatus: AttestationStatus,
    /** Cryptographic proof or signature of the error payload (for forensic use) */
    val proof: String? = null
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
