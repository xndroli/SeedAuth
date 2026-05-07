# SMS-to-SeedShield Migration Guide

This guide details how to migrate existing users from legacy authentication (SMS/Email) to SeedShield hardware-bound protection.

## The "SIM-swap Kill" Wedge

The primary goal of this migration is to explicitly retire vulnerable telecom-dependent recovery factors. Once a user migrates to SeedShield, their legacy SMS factor is programmatically disabled.

### The 3-Click Enrollment Flow

1.  **Initiation**: User clicks "Upgrade to Hardware Security" in the application settings.
2.  **Legacy Verification**: User performs a standard legacy login (SMS/Email) to prove ownership of the existing account.
3.  **Hardware Binding**: User approves the creation of a hardware-bound passkey in the Seeker's Seed Vault.

## Server-Side Implementation

The migration is handled by the MigrationHandler on the server.

### Atomic Transition

It is critical that the linkage of the hardware identity and the removal of the legacy factor are **atomic**. This prevents accounts from entering a state with zero valid recovery factors.

`	ypescript
// Example Implementation (Reference Pattern)
async function enroll(legacyToken, attestation) {
    // 1. Verify legacy session (JWT sub check)
    const userId = await verifyLegacySession(legacyToken);
    
    // 2. Verify hardware attestation (FR7 compliance)
    const outcome = await verifier.verify(attestation, origin, challenge);
    if (!outcome.success || outcome.attestationStatus !== 'VALID_HARDWARE') {
        throw new Error("Hardware verification failed: SOFTWARE_BACKED or INVALID");
    }

    // 3. Atomic Database Update (SIM-swap Kill Switch)
    await db.transaction(async (tx) => {
        await tx.users.update(userId, { 
            hardwarePublicKey: outcome.deviceId,
            smsEnabled: false,
            seedshieldProtected: true
        });
        // Deploy Squads v4 multisig immediately
        await multisigManager.ensureMultisig(outcome.deviceId, feePayer);
    });
}
`

## Security Guardrails

*   **One-Way Upgrade**: Once SeedShield is enabled, SMS cannot be re-enabled without full **Institutional Recovery** (Story 4.3). This prevents downgrade attacks.
*   **Safe-Fail**: If hardware attestation fails during migration (e.g., SOFTWARE_ATTESTATION_REJECTED), the system MUST return a HARD_REJECT and **preserve the legacy SMS factor**.
*   **Replay Protection**: Migration endpoints must bind the legacy session to the specific hardware key provided to prevent token reuse on different devices.

## User Communication

When the migration is complete, inform the user clearly:
> "Your account is now protected by SeedShield Silicon Identity. SMS recovery has been disabled to protect you from SIM-swap attacks. Your identity is now anchored to your Seeker hardware."

## References

- **PRD**: FR7, FR9, FR11.
- **Architecture**: Decoupled core, Squads v4 Factory.
- **Security**: Safe-Fail Matrix.
