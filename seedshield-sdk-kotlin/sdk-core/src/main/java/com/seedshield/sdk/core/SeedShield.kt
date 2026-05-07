package com.seedshield.sdk.core

import android.app.Activity
import com.seedshield.sdk.core.features.registration.RegistrationManager
import com.seedshield.sdk.core.models.AttestationResult

/**
 * SeedShield SDK: Hardware-Attested Security for Solana.
 */
class SeedShield private constructor(
    private val activity: Activity,
    private val testMode: Boolean = false,
    private val simulateUvFailure: Boolean = false
) {
    private val registrationManager = RegistrationManager(testMode, simulateUvFailure)

    /**
     * Triggers the hardware-bound passkey generation flow.
     */
    suspend fun register(
        rpId: String,
        userId: String,
        challenge: String
    ): Result<AttestationResult> {
        return runCatching {
            registrationManager.register(activity, rpId, userId, challenge)
        }
    }

    companion object {
        /**
         * Initializes the SeedShield SDK.
         * @param activity The current activity (required for Credential Manager UI).
         * @param testMode If true, the SDK will use mock attestations for testing.
         * @param simulateUvFailure If true (and testMode is true), registration will simulate a biometric failure.
         */
        fun initialize(
            activity: Activity,
            testMode: Boolean = false,
            simulateUvFailure: Boolean = false
        ): SeedShield {
            return SeedShield(activity, testMode, simulateUvFailure)
        }
    }
}
