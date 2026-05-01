import { createHash } from "node:crypto";
import { SOLANA_SEED_VAULT_AAGUID } from "../constants.js";
import type { AttestationObject } from "../types.js";

export class MockTEE {
  /**
   * Generates a standards-compliant mock attestation object.
   * @param rpId The Relying Party ID (domain).
   * @param challenge The challenge to sign.
   * @param aaguid The AAGUID to simulate.
   * @param isHardware Toggle for hardware vs software attestation.
   */
  static generateMockAttestation(
    rpId: string,
    challenge: string,
    aaguid: string = SOLANA_SEED_VAULT_AAGUID,
    isHardware: boolean = true,
  ): AttestationObject {
    // 1. RP ID Hash (SHA-256 of the domain)
    const rpIdHash = createHash("sha256").update(rpId).digest("base64");

    // 2. Mock authData
    const mockAuthData = {
      rpIdHash: rpIdHash,
      flags: isHardware ? 0x41 : 0x01,
      counter: 1,
      aaguid: aaguid,
    };

    return {
      fmt: isHardware ? "android-safetynet" : "none",
      attestationObject: Buffer.from(JSON.stringify(mockAuthData)).toString("base64"),
      rpId: rpId,
      challenge: challenge,
      sgtMetadata: isHardware ? "seeker-genesis-token-v1-mock" : undefined,
    };
  }
}
