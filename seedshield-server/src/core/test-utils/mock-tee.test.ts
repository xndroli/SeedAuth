import { createHash } from "node:crypto";
import { decode } from "cbor-x";
import { describe, expect, it } from "vitest";
import { SOLANA_SEED_VAULT_AAGUID } from "../constants.js";
import { MockTEE } from "./mock-tee.js";

describe("MockTEE", () => {
  const TEST_RP_ID = "exchange.com";
  const TEST_CHALLENGE = "random-challenge-nonce";

  it("AC-1.2.1: returns a validly-formatted mock attestation object", () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    expect(attestation.attestationObject).toBeDefined();
    expect(typeof attestation.attestationObject).toBe("string");

    // Verify binary decodeable (CBOR)
    const decoded = decode(Buffer.from(attestation.attestationObject, "base64"));
    expect(decoded.signCount).toBe(1);
  });

  it("AC-1.2.2: embeds the provided RP ID (SHA-256 hash)", () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    expect(attestation.rpId).toBe(TEST_RP_ID);

    const expectedHash = createHash("sha256").update(TEST_RP_ID).digest();
    const decoded = decode(Buffer.from(attestation.attestationObject, "base64"));
    expect(Buffer.from(decoded.rpIdHash).toString("hex")).toBe(expectedHash.toString("hex"));
  });

  it("AC-1.2.3: includes the test AAGUID", () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    const decoded = decode(Buffer.from(attestation.attestationObject, "base64"));
    expect(decoded.aaguid).toBe(SOLANA_SEED_VAULT_AAGUID);
  });

  it("AC-1.2.4: supports toggling hardware vs software attestation", () => {
    // Hardware path (default)
    const hwAttestation = MockTEE.generateMockAttestation(
      TEST_RP_ID,
      TEST_CHALLENGE,
      undefined,
      true,
    );
    const hwDecoded = decode(Buffer.from(hwAttestation.attestationObject, "base64"));
    expect(hwDecoded.flags).toBe(0x41); // UP + AT
    expect(hwAttestation.sgtMetadata).toBeDefined();
    expect(hwAttestation.fmt).toBe("android-safetynet");

    // Software path
    const swAttestation = MockTEE.generateMockAttestation(
      TEST_RP_ID,
      TEST_CHALLENGE,
      undefined,
      false,
    );
    const swDecoded = decode(Buffer.from(swAttestation.attestationObject, "base64"));
    expect(swDecoded.flags).toBe(0x01); // UP only
    expect(swAttestation.sgtMetadata).toBeUndefined();
    expect(swAttestation.fmt).toBe("none");
  });
});
