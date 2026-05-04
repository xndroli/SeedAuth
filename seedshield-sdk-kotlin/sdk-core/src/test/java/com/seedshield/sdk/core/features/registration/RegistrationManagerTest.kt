package com.seedshield.sdk.core.features.registration

import android.app.Activity
import com.seedshield.sdk.core.models.AttestationResult
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.mock

class RegistrationManagerTest {

    private lateinit var activity: Activity
    private lateinit var registrationManager: RegistrationManager

    @Before
    fun setUp() {
        activity = mock(Activity::class.java)
        // No activity in constructor anymore
        registrationManager = RegistrationManager(testMode = true)
    }

    @Test
    fun `parseRegistrationResponse extracts aaguid and sgtMetadata correctly`() {
        val rpId = "exchange.com"
        val challenge = "random-challenge"
        val registrationResponse = """
            {
                "response": {
                    "attestationObject": "REAL_ATTESTATION_OBJECT",
                    "clientDataJSON": "REAL_CLIENT_DATA",
                    "userVerified": true,
                    "aaguid": "ead6890d-274e-4cd9-bc22-38ef3d39994c",
                    "sgtMetadata": "DEVICE_TYPE=SEEKER_V1;VERSION=1.0"
                }
            }
        """.trimIndent()

        val result = registrationManager.parseRegistrationResponse(registrationResponse, rpId, challenge)

        assertTrue(result is AttestationResult.Success)
        val success = result as AttestationResult.Success
        assertEquals("ead6890d-274e-4cd9-bc22-38ef3d39994c", success.attestationObject.aaguid)
        assertEquals("DEVICE_TYPE=SEEKER_V1;VERSION=1.0", success.attestationObject.sgtMetadata)
        assertEquals("REAL_ATTESTATION_OBJECT", success.attestationObject.attestationObject)
    }

    @Test
    fun `parseRegistrationResponse fails on missing mandatory fields`() {
        val rpId = "exchange.com"
        val challenge = "random-challenge"
        val registrationResponse = """
            {
                "response": {
                    "attestationObject": "REAL_ATTESTATION_OBJECT",
                    "clientDataJSON": "REAL_CLIENT_DATA",
                    "userVerified": true
                }
            }
        """.trimIndent()

        val result = registrationManager.parseRegistrationResponse(registrationResponse, rpId, challenge)

        assertTrue(result is AttestationResult.Failure)
        val failure = result as AttestationResult.Failure
        assertEquals(com.seedshield.sdk.core.models.SeedShieldErrorCode.INTERNAL_ERROR, failure.errorCode)
        assertTrue(failure.message?.contains("Missing 'aaguid'") == true)
    }

    @Test
    fun `register in testMode returns success with mock data`() = runBlocking {
        val rpId = "exchange.com"
        val userId = "user-123"
        val challenge = "random-challenge"

        val result = registrationManager.register(activity, rpId, userId, challenge)

        assertTrue(result is AttestationResult.Success)
        val success = result as AttestationResult.Success
        assertEquals("packed", success.attestationObject.fmt)
        assertEquals(rpId, success.attestationObject.rpId)
        assertEquals(challenge, success.attestationObject.challenge)
        assertEquals("MOCK_ATTESTATION_OBJECT_BASE64", success.attestationObject.attestationObject)
        assertEquals("00000000-0000-0000-0000-000000000000", success.attestationObject.aaguid)
        assertEquals("MOCK_SGT_METADATA", success.attestationObject.sgtMetadata)
    }

    @Test
    fun `register in testMode with simulateUvFailure returns USER_VERIFICATION_FAILED`() = runBlocking {
        val rpId = "exchange.com"
        val userId = "user-123"
        val challenge = "random-challenge"

        // Create a new manager with UV failure simulation enabled
        val managerWithFailure = RegistrationManager(testMode = true, simulateUvFailure = true)
        val result = managerWithFailure.register(activity, rpId, userId, challenge)

        assertTrue(result is AttestationResult.Failure)
        val failure = result as AttestationResult.Failure
        assertEquals(com.seedshield.sdk.core.models.SeedShieldErrorCode.USER_VERIFICATION_FAILED, failure.errorCode)
        assertTrue(failure.message?.contains("Simulated biometric") == true)
    }
}
