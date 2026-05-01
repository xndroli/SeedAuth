import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { MockTEE, SOLANA_SEED_VAULT_AAGUID } from "./mock-tee.js";

describe("MockTEE", () => {
  const TEST_RP_ID = "https://exchange.com";

  it("AC-1.2.1: returns a validly-formatted mock attestation object", () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID);
    expect(attestation.attestationObject).toBeDefined();
    expect(typeof attestation.attestationObject).toBe("string");

    // Verify base64 decodeable
    const decoded = JSON.parse(Buffer.from(attestation.attestationObject, "base64").toString());
    expect(decoded.counter).toBe(1);
  });

  it("AC-1.2.2: embeds the provided RP ID (SHA-256 hash)", () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID);
    expect(attestation.rpId).toBe(TEST_RP_ID);

    const expectedHash = createHash("sha256").update(TEST_RP_ID).digest("base64");
    const decoded = JSON.parse(Buffer.from(attestation.attestationObject, "base64").toString());
    expect(decoded.rpIdHash).toBe(expectedHash);
  });

  it("AC-1.2.3: includes the test AAGUID", () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID);
    const decoded = JSON.parse(Buffer.from(attestation.attestationObject, "base64").toString());
    expect(decoded.aaguid).toBe(SOLANA_SEED_VAULT_AAGUID);
  });

  it("AC-1.2.4: supports toggling hardware vs software attestation", () => {
    // Hardware path (default)
    const hwAttestation = MockTEE.generateMockAttestation(TEST_RP_ID, undefined, true);
    const hwDecoded = JSON.parse(Buffer.from(hwAttestation.attestationObject, "base64").toString());
    expect(hwDecoded.flags).toBe(0x41); // UP + AT
    expect(hwAttestation.sgtMetadata).toBeDefined();
    expect(hwAttestation.fmt).toBe("android-safetynet");

    // Software path
    const swAttestation = MockTEE.generateMockAttestation(TEST_RP_ID, undefined, false);
    const swDecoded = JSON.parse(Buffer.from(swAttestation.attestationObject, "base64").toString());
    expect(swDecoded.flags).toBe(0x01); // UP only
    expect(swAttestation.sgtMetadata).toBeUndefined();
    expect(swAttestation.fmt).toBe("none");
  });
});
