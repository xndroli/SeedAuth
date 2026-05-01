import { beforeEach, describe, expect, it } from "vitest";
import { GuardianRpcAdapter } from "../../core/guardian-rpc.js";
import { MockTEE } from "../../core/test-utils/mock-tee.js";
import { SeedShieldErrorCode } from "../../core/types.js";
import { AttestationVerifier } from "./verifier.js";

describe("AttestationVerifier", () => {
  const TEST_ORIGIN = "https://exchange.com";
  const TEST_RP_ID = "exchange.com";
  const TEST_CHALLENGE = "random-challenge-nonce";

  let verifier: AttestationVerifier;
  let mockGuardian: GuardianRpcAdapter;

  beforeEach(() => {
    mockGuardian = new GuardianRpcAdapter("mock://sas.helius.dev");
    verifier = new AttestationVerifier(mockGuardian);
  });

  it("successfully verifies a valid hardware attestation with challenge", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE);

    expect(result.success).toBe(true);
    expect(result.attestationStatus).toBe("VALID_HARDWARE");
  });

  it("rejects if challenge does not match", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, "wrong-challenge");
    const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.INVALID_TEEPIN_QUOTE);
    expect(result.message).toContain("Challenge mismatch");
  });

  it("rejects attestation if RP ID does not match normalized origin", async () => {
    const attestation = MockTEE.generateMockAttestation("wrong-domain.com", TEST_CHALLENGE);
    const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.ORIGIN_MISMATCH);
  });

  it("rejects attestation with untrusted AAGUID", async () => {
    const attestation = MockTEE.generateMockAttestation(
      TEST_RP_ID,
      TEST_CHALLENGE,
      "untrusted-aaguid",
    );
    const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.UNTRUSTED_AAGUID);
    expect(result.attestationStatus).toBe("SOFTWARE_BACKED");
  });

  it("rejects hardware call if guardian verification fails", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    attestation.attestationObject += "INVALID_QUOTE"; // Trigger mock guardian error

    const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.INVALID_TEEPIN_QUOTE);
  });
});
