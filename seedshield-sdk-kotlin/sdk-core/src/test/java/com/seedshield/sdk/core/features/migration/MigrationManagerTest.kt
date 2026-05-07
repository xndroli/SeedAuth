package com.seedshield.sdk.core.features.migration

import android.app.Activity
import com.seedshield.sdk.core.features.registration.RegistrationManager
import com.seedshield.sdk.core.models.AttestationObject
import com.seedshield.sdk.core.models.AttestationResult
import com.seedshield.sdk.core.models.SeedShieldErrorCode
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito

class MigrationManagerTest {

    private lateinit var registrationManager: RegistrationManager
    private lateinit var migrationManager: MigrationManager
    private val mockActivity = Mockito.mock(Activity::class.java)

    @Before
    fun setUp() {
        // Use real RegistrationManager in testMode to avoid Mockito suspend issues
        registrationManager = RegistrationManager(testMode = true)
        migrationManager = MigrationManager(registrationManager)
    }

    @Test
    fun `successfully orchestrates migration flow`() = runBlocking {
        val result = migrationManager.startMigration(
            mockActivity,
            "legacy-token",
            "rp",
            "user",
            "chal"
        ) { token, att ->
            assertEquals("legacy-token", token)
            assertEquals("chal", att.challenge)
            MigrationResult.Success("multisig-addr")
        }

        assertTrue(result is MigrationResult.Success)
        assertEquals("multisig-addr", (result as MigrationResult.Success).multisigAddress)
    }

    @Test
    fun `fails migration if hardware registration fails`() = runBlocking {
        // Force failure via RegistrationManager simulation
        val failingRegManager = RegistrationManager(testMode = true, simulateUvFailure = true)
        val migrationManagerWithFailure = MigrationManager(failingRegManager)

        val result = migrationManagerWithFailure.startMigration(
            mockActivity,
            "legacy-token",
            "rp",
            "user",
            "chal"
        ) { _, _ ->
            MigrationResult.Success("should-not-reach")
        }

        assertTrue(result is MigrationResult.Failure)
        assertEquals(SeedShieldErrorCode.USER_VERIFICATION_FAILED, (result as MigrationResult.Failure).errorCode)
    }
}
