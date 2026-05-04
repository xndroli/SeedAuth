package com.seedshield.sdk.core.models

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Test

class ModelsSerializationTest {

    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun `serialize AttestationObject to JSON`() {
        val attestation = AttestationObject(
            fmt = "packed",
            attestationObject = "BASE64",
            rpId = "exchange.com",
            aaguid = "00000000-0000-0000-0000-000000000000",
            challenge = "nonce123"
        )

        val jsonString = json.encodeToString(attestation)
        
        // Verify it contains expected keys
        assert(jsonString.contains("\"fmt\":\"packed\""))
        assert(jsonString.contains("\"rpId\":\"exchange.com\""))
        assert(jsonString.contains("\"aaguid\":\"00000000-0000-0000-0000-000000000000\""))
        assert(jsonString.contains("\"challenge\":\"nonce123\""))
    }

    @Test
    fun `deserialize AttestationResult Success`() {
        val jsonString = """
            {
                "type": "com.seedshield.sdk.core.models.AttestationResult.Success",
                "attestationObject": {
                    "fmt": "packed",
                    "attestationObject": "BASE64",
                    "rpId": "exchange.com",
                    "aaguid": "00000000-0000-0000-0000-000000000000",
                    "challenge": "nonce123"
                }
            }
        """.trimIndent()

        val success = AttestationResult.Success(
            AttestationObject("packed", "BASE64", "exchange.com", "00000000-0000-0000-0000-000000000000", "nonce123")
        )
        val serialized = json.encodeToString(success)
        val deserialized = json.decodeFromString<AttestationResult.Success>(serialized)

        assertEquals(success, deserialized)
    }
}
