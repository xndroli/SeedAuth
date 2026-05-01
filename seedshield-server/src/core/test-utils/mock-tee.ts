import { createHash } from "node:crypto";
import type { AttestationObject } from "../types.js";

export const SOLANA_SEED_VAULT_AAGUID = "534f4c41-4e41-4d4f-4249-4c4553563031";

export class MockTEE {
  /**
   * Generates a mock attestation object for testing.
   * @param rpId The Relying Party ID to embed.
   * @param aaguid The AAGUID to simulate (defaults to Solana Seed Vault).
   * @param isHardware Toggle for hardware vs software attestation.
   */
  static generateMockAttestation(
    rpId: string,
    aaguid: string = SOLANA_SEED_VAULT_AAGUID,
    isHardware: boolean = true,
  ): AttestationObject {
    // Standard WebAuthn mandates SHA-256 of RP ID
    const rpIdHash = createHash("sha256").update(rpId).digest("base64");

    const mockAuthData = {
      rpIdHash: rpIdHash,
      flags: isHardware ? 0x41 : 0x01, // 0x41 = UP + AT (Attested), 0x01 = UP only
      counter: 1,
      aaguid: aaguid,
    };

    const mockPayload: AttestationObject = {
      fmt: isHardware ? "android-safetynet" : "none",
      attestationObject: Buffer.from(JSON.stringify(mockAuthData)).toString("base64"),
      rpId: rpId,
      sgtMetadata: isHardware ? "seeker-genesis-token-v1-mock" : undefined,
    };

    return mockPayload;
  }
}
