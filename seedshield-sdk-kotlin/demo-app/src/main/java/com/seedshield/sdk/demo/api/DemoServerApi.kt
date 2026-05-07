package com.seedshield.sdk.demo.api

import com.seedshield.sdk.demo.BuildConfig
import com.seedshield.sdk.core.models.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Serializable
data class ChallengeResponse(val challenge: String)

@Serializable
data class RegisterRequest(val attestation: AttestationObject, val userId: String)

@Serializable
data class MigrateRequest(val legacyToken: String, val attestation: AttestationObject, val userId: String)

@Serializable
data class RegisterResponse(
    val success: Boolean,
    val multisigPda: String? = null,
    val message: String? = null,
    val errorCode: SeedShieldErrorCode? = null,
    val attestationStatus: AttestationStatus? = null
)

class DemoServerApi(private val baseUrl: String = "http://10.0.2.2:3000") {
    private val client = OkHttpClient()
    private val json = Json { ignoreUnknownKeys = true }
    private val mediaType = "application/json; charset=utf-8".toMediaType()

    // AC-5.3.6: Extract version from BuildConfig
    private val sdkVersion = BuildConfig.VERSION_NAME

    suspend fun getChallenge(userId: String): String = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$baseUrl/challenge/$userId")
            .addHeader("X-SeedShield-Version", sdkVersion)
            .build()

        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw Exception("Failed to get challenge")
            val body = response.body?.string() ?: throw Exception("Empty response")
            json.decodeFromString<ChallengeResponse>(body).challenge
        }
    }

    suspend fun register(userId: String, attestation: AttestationObject): RegisterResponse = withContext(Dispatchers.IO) {
        val requestBody = json.encodeToString(RegisterRequest(attestation, userId))
            .toRequestBody(mediaType)

        val request = Request.Builder()
            .url("$baseUrl/register")
            .addHeader("X-SeedShield-Version", sdkVersion)
            .post(requestBody)
            .build()

        client.newCall(request).execute().use { response ->
            val body = response.body?.string() ?: throw Exception("Empty response")
            json.decodeFromString<RegisterResponse>(body)
        }
    }

    suspend fun migrateEnroll(userId: String, legacyToken: String, attestation: AttestationObject): RegisterResponse = withContext(Dispatchers.IO) {
        val requestBody = json.encodeToString(MigrateRequest(legacyToken, attestation, userId))
            .toRequestBody(mediaType)

        val request = Request.Builder()
            .url("$baseUrl/migrate/enroll")
            .addHeader("X-SeedShield-Version", sdkVersion)
            .post(requestBody)
            .build()

        client.newCall(request).execute().use { response ->
            val body = response.body?.string() ?: throw Exception("Empty response")
            json.decodeFromString<RegisterResponse>(body)
        }
    }
}
