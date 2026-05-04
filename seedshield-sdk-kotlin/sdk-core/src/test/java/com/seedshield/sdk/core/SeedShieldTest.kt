package com.seedshield.sdk.core

import android.app.Activity
import com.seedshield.sdk.core.models.AttestationResult
import com.seedshield.sdk.core.models.SeedShieldErrorCode
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.mock

class SeedShieldTest {

    private lateinit var activity: Activity

    @Before
    fun setUp() {
        activity = mock(Activity::class.java)
    }

    @Test
    fun `initialize with simulateUvFailure propagates to registration`() = runBlocking {
        val rpId = "exchange.com"
        val userId = "user-123"
        val challenge = "random-challenge"

        val seedShield = SeedShield.initialize(activity, testMode = true, simulateUvFailure = true)
        val result = seedShield.register(rpId, userId, challenge)

        assertTrue(result.isSuccess)
        val attestationResult = result.getOrNull()
        assertTrue(attestationResult is AttestationResult.Failure)
        val failure = attestationResult as AttestationResult.Failure
        assertEquals(SeedShieldErrorCode.USER_VERIFICATION_FAILED, failure.errorCode)
        assertTrue(failure.message?.contains("Simulated biometric") == true)
    }

    @Test
    fun `initialize without simulateUvFailure returns success in testMode`() = runBlocking {
        val rpId = "exchange.com"
        val userId = "user-123"
        val challenge = "random-challenge"

        val seedShield = SeedShield.initialize(activity, testMode = true, simulateUvFailure = false)
        val result = seedShield.register(rpId, userId, challenge)

        assertTrue(result.isSuccess)
        val attestationResult = result.getOrNull()
        assertTrue(attestationResult is AttestationResult.Success)
    }
}
