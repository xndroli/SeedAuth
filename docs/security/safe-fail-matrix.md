# SeedAuth Safe-Fail Matrix

This document maps all identified failure modes across the hardware and on-chain boundaries to system actions and machine-readable error codes.

## 1. Hardware & Attestation Failure Modes (Mobile/TEE)

| Failure Mode | Action | Error Code | Description |
| :--- | :--- | :--- | :--- |
| **Software-Generated Attestation** | `HARD_REJECT` | `SOFTWARE_ATTESTATION_REJECTED` | Key attestation security level is `KM_SECURITY_LEVEL_SOFTWARE`. |
| **Origin Mismatch** | `HARD_REJECT` | `ORIGIN_MISMATCH` | `rpId` in attestation does not match the requesting server's origin. |
| **Challenge Mismatch** | `HARD_REJECT` | `CHALLENGE_MISMATCH` | Challenge in attestation does not match the server-provided nonce. |
| **Untrusted AAGUID** | `HARD_REJECT` | `UNTRUSTED_AAGUID` | AAGUID does not match Solana Seed Vault (Seeker) trust anchors. |
| **Revoked Certificate** | `HARD_REJECT` | `CERTIFICATE_REVOKED` | Any certificate in the hardware attestation chain has been revoked. |
| **Expired Certificate** | `HARD_REJECT` | `CERTIFICATE_EXPIRED` | Hardware attestation certificate has expired. |
| **Device Tampered** | `HARD_REJECT` | `DEVICE_TAMPERED` | Root of trust validation failed (e.g., unlocked bootloader). |
| **Enclave Unavailable** | `RETRY` (Exponential, Max 3) | `ENCLAVE_UNAVAILABLE` | TEE is temporarily unavailable or busy. |
| **Enclave Busy** | `RETRY` (Immediate) | `ENCLAVE_BUSY` | TEE is busy; immediate retry allowed. |
| **Key Not Found** | `HARD_REJECT` | `KEY_NOT_FOUND` | Requested key handle does not exist in the TEE/Enclave. |
| **User Verification Failed** | `HARD_REJECT` | `USER_VERIFICATION_FAILED` | Biometric check failed or was bypassed by the user. |
| **Version Deprecated** | `HARD_REJECT` | `VERSION_DEPRECATED` | SDK version is below the mandatory `minClientVersion`. |

## 2. On-Chain & Multisig Failure Modes (Solana/Squads)

| Failure Mode | Action | Error Code | Description |
| :--- | :--- | :--- | :--- |
| **MULTISIG_ALREADY_EXISTS** | `LOG_ONLY` (Return Existing) | `MULTISIG_ALREADY_EXISTS` | Attempted to deploy a multisig for a public key that already has one. |
| **MULTISIG_THRESHOLD_NOT_MET** | `HARD_REJECT` | `MULTISIG_THRESHOLD_NOT_MET` | Fewer than 2 valid signatures for a 2-of-2 multisig rotation. |
| **MULTISIG_THRESHOLD_DEADLOCK** | `HARD_REJECT` | `MULTISIG_THRESHOLD_DEADLOCK` | Threshold configuration makes the account unrecoverable. |
| **MULTISIG_TIMELOCK_ACTIVE** | `HARD_REJECT` | `MULTISIG_TIMELOCK_ACTIVE` | Attempted to execute a rotation before the 72h timelock expired. |
| **MULTISIG_ALREADY_EXECUTED** | `HARD_REJECT` | `MULTISIG_ALREADY_EXECUTED` | Transaction proposal has already been executed. |
| **MULTISIG_INSUFFICIENT_SIGNERS** | `HARD_REJECT` | `MULTISIG_INSUFFICIENT_SIGNERS` | Transaction proposal lacks enough signatures. |
| **MULTISIG_CONFIGURATION_INVALID** | `HARD_REJECT` | `MULTISIG_CONFIGURATION_INVALID` | Multisig settings (e.g. timelock) do not meet security requirements. |
| **FEE_PAYER_EXHAUSTED** | `RETRY` (Secondary Payer) | `FEE_PAYER_EXHAUSTED` | Primary subsidizer account has insufficient funds. |
| **INVALID_VAULT_PDA** | `HARD_REJECT` | `INVALID_VAULT_PDA` | Derived Vault PDA address does not match expected configuration. |
| **GUARDIAN_RPC_FAILED** | `RETRY` (Secondary Fallback) | `GUARDIAN_RPC_FAILED` | TEEPIN/SGT quote verification via Guardian RPC failed. |

## 3. Subsidizer & Fee Payer Failure Modes

| Failure Mode | Action | Error Code | Description |
| :--- | :--- | :--- | :--- |
| **Throttle Limit Exceeded** | `HARD_REJECT` | `THROTTLE_LIMIT_EXCEEDED` | Device has exceeded the allowed number of subsidized transactions in the window. |
| **Payer Account Exhausted** | `RETRY` (Secondary Payer) | `FEE_PAYER_EXHAUSTED` | Primary subsidizer account has insufficient funds. |
| **Nonce Account Unfunded** | `RETRY` (Provision) | `INTERNAL_ERROR` | Durable nonce account is not initialized or lacks rent-exempt balance. |
| **Signer-Device Mismatch** | `LOG_CRITICAL` | `DEVICE_COMPROMISED_ANOMALY` | Transaction signer does not match the public key in the hardware attestation. |

## 4. Hardware-Attestation Anomalies

| Anomaly | Forensic Action | Error Code | Description |
| :--- | :--- | :--- | :--- |
| **Valid Signature, Non-Seeker AAGUID** | `LOG_CRITICAL` | `NON_SEEKER_DEVICE` | A valid FIDO2 signature from a non-Seeker device. |
| **Valid Quote, Revoked Certificate** | `BLOCK_ACCOUNT` | `DEVICE_COMPROMISED_ANOMALY` | Previously genuine device has been compromised. |
| **Zero AAGUID** | `HARD_REJECT` | `ZERO_AAGUID` | Generic authenticator attempting to spoof a hardware-bound device. |
| **Duplicate Device ID Registration** | `HARD_REJECT` | `DUPLICATE_DEVICE_ID` | Multiple user accounts attempting to bind to the same physical `device_id`. |

## 5. Enforcement Strategy (FR7)

As per **Functional Requirement 7**, the system enforces a strict "Hardware-Only" policy.
1. Any verification that returns `success: false` or `attestationStatus: SOFTWARE_BACKED` MUST result in a `HARD_REJECT`.
2. The user interface MUST NOT offer a fallback to SMS or non-hardware methods for Seeker-enabled accounts.
3. Every rejection MUST return the machine-readable `errorCode` within a `SealedError` payload for client-side routing and forensic logging.
4. **Secondary Fallback:** If a transient failure occurs (e.g., `GUARDIAN_RPC_FAILED`), the system may attempt one secondary RPC endpoint. If the secondary fails, it must `HARD_REJECT`.
5. **Forensic Auditing:** Per FR10, all failures including anomalies must be logged with `device_id` (if available) and `errorCode` using the `SealedError` structure.
