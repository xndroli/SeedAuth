/**
 * SeedShield Security Constants
 */

/**
 * The official AAGUID for the Solana Seeker Seed Vault.
 * Proves the key was generated in the hardware Trusted Execution Environment.
 */
export const SOLANA_SEED_VAULT_AAGUID = "534f4c41-4e41-4d4f-4249-4c4553563031";

/**
 * Standard FIDO2/WebAuthn hardware attestation flags.
 */
export const AUTH_DATA_FLAGS = {
  UP: 0x01, // User Presence
  UV: 0x04, // User Verified (Biometric)
  AT: 0x40, // Attestation Data Present
  ED: 0x80, // Extension Data Present
};
