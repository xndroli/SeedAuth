package com.seedshield.sdk.core.features.migration

import android.app.Activity
import com.seedshield.sdk.core.features.registration.RegistrationManager
import com.seedshield.sdk.core.models.AttestationObject
import com.seedshield.sdk.core.models.AttestationResult
import com.seedshield.sdk.core.models.SeedShieldErrorCode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * AC-5.2.1: Enrollment Flow Implementation
 * Orchestrates legacy auth check -> Hardware registration -> Server linkage.
 */
class MigrationManager(
    private val registrationManager: RegistrationManager = RegistrationManager()
) {
    /**
     * Start the 3-click migration flow.
     * Click 1: User initiates (handled by UI)
     * Click 2: User provides legacy credentials (handled by platform, passed as legacyToken)
     * Click 3: User approves hardware registration (handled here)
     */
    suspend fun startMigration(
        activity: Activity,
        legacyToken: String,
        rpId: String,
        userId: String,
        challenge: String,
        onServerLink: suspend (String, AttestationObject) -> MigrationResult
    ): MigrationResult = withContext(Dispatchers.IO) {
        // Step 1: Hardware registration (Click 3)
        // We reuse RegistrationManager to ensure hardware-bound keys are created in the Seed Vault.
        val registrationResult = registrationManager.register(activity, rpId, userId, challenge)

        when (registrationResult) {
            is AttestationResult.Success -> {
                // Step 2: Link with server (programmatically retire legacy factor on success)
                onServerLink(legacyToken, registrationResult.attestationObject)
            }
            is AttestationResult.Failure -> {
                MigrationResult.Failure(registrationResult.errorCode, registrationResult.message)
            }
            AttestationResult.Cancellation -> MigrationResult.Cancellation
            AttestationResult.NoPlatformAuthenticator -> MigrationResult.NoPlatformAuthenticator
        }
    }
}

/**
 * Result of the migration flow.
 */
sealed class MigrationResult {
    data class Success(val multisigAddress: String) : MigrationResult()
    data class Failure(val errorCode: SeedShieldErrorCode, val message: String? = null) : MigrationResult()
    object Cancellation : MigrationResult()
    object NoPlatformAuthenticator : MigrationResult()
}
