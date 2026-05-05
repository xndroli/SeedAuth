import { createHash } from "node:crypto";
import { encode } from "cbor-x";
import { SOLANA_SEED_VAULT_AAGUID } from "../constants.js";
import type { AttestationObject } from "../types.js";

export class MockTEE {
  /**
   * Generates a standards-compliant binary mock attestation object.
   * @param rpId The Relying Party ID (domain).
   * @param challenge The challenge to sign.
   * @param aaguid The AAGUID to simulate.
   * @param isHardware Toggle for hardware vs software attestation.
   * @param deviceId Optional device ID to embed.
   */
  static generateMockAttestation(
    rpId: string,
    challenge: string,
    aaguid: string = SOLANA_SEED_VAULT_AAGUID,
    isHardware: boolean = true,
    deviceId: string = "mock-device-id-999",
  ): AttestationObject {
    const rpIdHash = createHash("sha256").update(rpId).digest();

    // Simulating FIDO2 authData binary structure using CBOR
    const mockAuthData = {
      rpIdHash,
      flags: isHardware ? 0x41 : 0x01,
      signCount: 1,
      aaguid,
      deviceId,
      // Mock credential public key (32 bytes for Ed25519)
      credentialPublicKey: Buffer.alloc(32, 1), 
    };

    return {
      fmt: isHardware ? "android-safetynet" : "none",
      attestationObject: encode(mockAuthData).toString("base64"),
      rpId: rpId,
      challenge: challenge,
      sgtMetadata: isHardware ? "seeker-genesis-token-v1-mock" : undefined,
    };
  }
}
