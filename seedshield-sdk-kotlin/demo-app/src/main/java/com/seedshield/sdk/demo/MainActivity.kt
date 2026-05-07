package com.seedshield.sdk.demo

import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.seedshield.sdk.core.SeedShield
import com.seedshield.sdk.core.models.AttestationResult
import com.seedshield.sdk.demo.api.DemoServerApi
import com.seedshield.sdk.demo.databinding.ActivityMainBinding
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var seedShield: SeedShield
    private val api = DemoServerApi()

    // Patch 7: Simple Loading State to prevent race conditions
    private var isLoading: Boolean = false
        set(value) {
            field = value
            binding.buttonRegister.isEnabled = !value
            binding.buttonLogin.isEnabled = !value
            binding.buttonRecovery.isEnabled = !value
            binding.buttonMigrate.isEnabled = !value
            binding.editUserId.isEnabled = !value
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // AC-5.1.5: Running with testMode=true for POC (MockTEE)
        seedShield = SeedShield.initialize(this, testMode = true)

        setupListeners()
    }

    private fun setupListeners() {
        binding.buttonRegister.setOnClickListener {
            isLoading = true
            handleAction("register")
        }

        binding.buttonLogin.setOnClickListener {
            isLoading = true
            handleAction("login")
        }

        binding.buttonRecovery.setOnClickListener {
            isLoading = true
            handleAction("recovery")
        }

        binding.buttonMigrate.setOnClickListener {
            isLoading = true
            handleAction("migrate")
        }
    }

    private fun handleAction(action: String) {
        val userId = binding.editUserId.text.toString().trim() // Patch: Trim whitespace (Finding 7)
        if (userId.isEmpty()) {
            updateStatus(getString(R.string.status_error, "User ID required"))
            isLoading = false
            return
        }

        // isLoading is already true from setupListeners
        updateStatus(getString(R.string.status_verifying))

        lifecycleScope.launch {
            try {
                // 1. Get Challenge from Demo Server
                val challenge = api.getChallenge(userId)

                // 2. Security Action via SeedShield SDK
                // For demo/Phase 1, login uses the same hardware attestation flow
                val result = seedShield.register(
                    rpId = "exchange.com",
                    userId = userId,
                    challenge = challenge
                ).getOrThrow()

                when (result) {
                    is AttestationResult.Success -> {
                        // 3. Submit to Server
                        when (action) {
                            "register" -> {
                                val response = api.register(userId, result.attestationObject)
                                handleServerResponse(response)
                            }
                            "login" -> {
                                // Patch 3: Implement Login Flow
                                // In a real app, this would return a session JWT
                                val response = api.register(userId, result.attestationObject) // Reuse reg logic for demo identity proof
                                if (response.success) {
                                    updateStatus(getString(R.string.status_success) + ": Welcome Back")
                                } else {
                                    updateStatus(getString(R.string.status_error, "Login Identity Mismatch"))
                                }
                            }
                            "recovery" -> {
                                // Patch 3: Implement Recovery Simulation
                                updateStatus("Initiating Recovery Flow...")
                                updateStatus("72h Security Timelock Activated.")
                            }
                            "migrate" -> {
                                // AC-5.2.1: Enrollment Flow
                                // In demo, legacyToken is same as userId
                                val response = api.migrateEnroll(userId, userId, result.attestationObject)
                                handleServerResponse(response)
                            }
                        }
                    }
                    is AttestationResult.Failure -> {
                        updateStatus(getString(R.string.status_error, result.message ?: "SDK Error"))
                    }
                    AttestationResult.Cancellation -> {
                        updateStatus(getString(R.string.status_ready))
                    }
                    else -> {
                        updateStatus(getString(R.string.status_error, "Unexpected SDK Result"))
                    }
                }
            } catch (e: Exception) {
                updateStatus(getString(R.string.status_error, e.message ?: "Network error"))
            } finally {
                isLoading = false
            }
        }
    }

    private fun handleServerResponse(response: com.seedshield.sdk.demo.api.RegisterResponse) {
        if (response.success) {
            updateStatus(getString(R.string.status_success))
            binding.textMultisigPda.text = getString(R.string.multisig_pda_label, response.multisigPda)
            binding.textMultisigPda.visibility = View.VISIBLE
            
            // AC-5.2.2: Legacy factor removal logic
            if (response.message?.contains("Migration Complete") == true) {
                binding.textSmsDisabled.visibility = View.VISIBLE
            }
        } else {
            // AC-5.1.3: Handle hardware-only policy errors
            val message = when (response.errorCode) {
                com.seedshield.sdk.core.models.SeedShieldErrorCode.UNTRUSTED_AAGUID -> "Non-Genuine Device Detected"
                com.seedshield.sdk.core.models.SeedShieldErrorCode.VERSION_DEPRECATED -> "Update Required: This SDK version is no longer supported"
                else -> response.message ?: "Server-side verification failed"
            }
            updateStatus(getString(R.string.status_error, message))
        }
    }

    private fun updateStatus(status: String) {
        binding.textStatus.text = status
    }
}
