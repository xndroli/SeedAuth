package com.seedshield.sdk.core.features.registration

import android.app.Activity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CredentialManager
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialInterruptedException
import androidx.credentials.exceptions.CreateCredentialNoCreateOptionException
import androidx.credentials.exceptions.CreateCredentialProviderConfigurationException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import com.seedshield.sdk.core.models.AttestationObject
import com.seedshield.sdk.core.models.AttestationResult
import com.seedshield.sdk.core.models.SeedShieldErrorCode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.booleanOrNull

/**
 * Manages the FIDO2 passkey registration flow using Android Credential Manager.
 */
class RegistrationManager(
    private val testMode: Boolean = false,
    private val simulateUvFailure: Boolean = false
) {
    /**
     * Triggers the hardware-bound passkey generation flow.
     */
    suspend fun register(
        activity: Activity,
        rpId: String,
        userId: String,
        challenge: String
    ): AttestationResult = withContext(Dispatchers.IO) {
        val credentialManager = CredentialManager.create(activity)

        if (testMode) {
            if (simulateUvFailure) {
                return@withContext AttestationResult.Failure(
                    errorCode = SeedShieldErrorCode.USER_VERIFICATION_FAILED,
                    message = "Simulated biometric verification failure"
                )
            }
            return@withContext AttestationResult.Success(
                AttestationObject(
                    fmt = "packed",
                    attestationObject = "MOCK_ATTESTATION_OBJECT_BASE64",
                    clientDataJSON = "MOCK_CLIENT_DATA_JSON_BASE64",
                    aaguid = "00000000-0000-0000-0000-000000000000",
                    rpId = rpId,
                    challenge = challenge,
                    sgtMetadata = "MOCK_SGT_METADATA"
                )
            )
        }

        try {
            val requestJson = buildJsonObject {
                put("challenge", challenge)
                putJsonObject("rp") {
                    put("id", rpId)
                    put("name", "SeedShield Protected App")
                }
                putJsonObject("user") {
                    put("id", userId)
                    put("name", "user_identifier") // Avoid using PII (userId) in 'name'
                    put("displayName", "SeedShield User") 
                }
                putJsonArray("pubKeyCredParams") {
                    addJsonObject {
                        put("type", "public-key")
                        put("alg", -7) // ES256
                    }
                }
                putJsonObject("authenticatorSelection") {
                    put("authenticatorAttachment", "platform")
                    put("residentKey", "required")
                    put("userVerification", "required")
                }
                put("attestation", "direct")
            }

            val request = CreatePublicKeyCredentialRequest(requestJson.toString())
            val result = credentialManager.createCredential(activity, request)

            // Extract the attestation object from the credential result
            val registrationResponse = result.data.getString("androidx.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON")
                ?: return@withContext AttestationResult.Failure(
                    errorCode = SeedShieldErrorCode.INTERNAL_ERROR,
                    message = "Credential Manager returned an empty response bundle"
                )

            parseRegistrationResponse(registrationResponse, rpId, challenge)
            } catch (e: CreateCredentialCancellationException) {
            AttestationResult.Cancellation
            } catch (e: CreateCredentialNoCreateOptionException) {
            AttestationResult.NoPlatformAuthenticator
            } catch (e: CreatePublicKeyCredentialDomException) {
            // AC-2.2.3: Implement robust handling for DomException mapping
            val errorStr = e.domError.toString()
            if (errorStr.contains("NotAllowedError", ignoreCase = true) || 
                errorStr.contains("ConstraintError", ignoreCase = true)) {
                AttestationResult.Failure(
                    errorCode = SeedShieldErrorCode.USER_VERIFICATION_FAILED,
                    message = "User verification failed or was denied ($errorStr)"
                )
            } else {
                AttestationResult.Failure(
                    errorCode = SeedShieldErrorCode.INTERNAL_ERROR,
                    message = "DOM Exception: ${e.message}"
                )
            }        } catch (e: CreateCredentialInterruptedException) {
            AttestationResult.Failure(
                errorCode = SeedShieldErrorCode.INTERNAL_ERROR,
                message = "Flow interrupted by user or system"
            )
        } catch (e: CreateCredentialProviderConfigurationException) {
            AttestationResult.Failure(
                errorCode = SeedShieldErrorCode.INTERNAL_ERROR,
                message = "Credential provider misconfigured"
            )
        } catch (e: CreateCredentialUnknownException) {
            AttestationResult.Failure(
                errorCode = SeedShieldErrorCode.INTERNAL_ERROR,
                message = "Unknown error: ${e.message}"
            )
        } catch (e: Exception) {
            AttestationResult.Failure(
                errorCode = SeedShieldErrorCode.INTERNAL_ERROR,
                message = e.message ?: "An unexpected error occurred"
            )
        }
    }

    /**
     * Internal helper to parse the JSON response from Credential Manager.
     */
    internal fun parseRegistrationResponse(
        registrationResponse: String,
        rpId: String,
        challenge: String
    ): AttestationResult {
        val root = Json.parseToJsonElement(registrationResponse).jsonObject
        val response = root["response"]?.jsonObject ?: return AttestationResult.Failure(
            errorCode = SeedShieldErrorCode.INTERNAL_ERROR,
            message = "Invalid registration response: Missing 'response' object"
        )

        // AC-2.2.2: Verify userVerified flag in the response JSON
        val isUserVerified = response["userVerified"]?.jsonPrimitive?.booleanOrNull ?: false // Fail-closed

        if (!isUserVerified) {
            return AttestationResult.Failure(
                errorCode = SeedShieldErrorCode.USER_VERIFICATION_FAILED,
                message = "User verification failed: Authenticator reported userVerified=false"
            )
        }

        val attestationObjectBase64 = response["attestationObject"]?.jsonPrimitive?.content ?: return AttestationResult.Failure(
            errorCode = SeedShieldErrorCode.INTERNAL_ERROR,
            message = "Invalid registration response: Missing 'attestationObject'"
        )

        val clientDataJSONBase64 = response["clientDataJSON"]?.jsonPrimitive?.content ?: return AttestationResult.Failure(
            errorCode = SeedShieldErrorCode.INTERNAL_ERROR,
            message = "Invalid registration response: Missing 'clientDataJSON'"
        )

        // AC-2.3.2: Extract aaguid (MUST be present per AC, so we fail if missing)
        val aaguid = response["aaguid"]?.jsonPrimitive?.content ?: return AttestationResult.Failure(
            errorCode = SeedShieldErrorCode.INTERNAL_ERROR,
            message = "Hardware attestation failed: Missing 'aaguid'"
        )
        
        // AC-2.3.3: Extract sgtMetadata (MUST be present per AC, so we fail if missing)
        val sgtMetadata = response["sgtMetadata"]?.jsonPrimitive?.content ?: return AttestationResult.Failure(
            errorCode = SeedShieldErrorCode.INTERNAL_ERROR,
            message = "Hardware attestation failed: Missing 'sgtMetadata'"
        )

        return AttestationResult.Success(
            AttestationObject(
                fmt = "packed", // Default for Seed Vault
                attestationObject = attestationObjectBase64,
                rpId = rpId,
                challenge = challenge,
                aaguid = aaguid,
                sgtMetadata = sgtMetadata
            )
        )
    }
}
