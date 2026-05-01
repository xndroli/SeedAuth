import { beforeEach, describe, expect, it } from "vitest";
import { GuardianRpcAdapter } from "../../core/guardian-rpc.js";
import { MockTEE } from "../../core/test-utils/mock-tee.js";
import { SeedShieldErrorCode } from "../../core/types.js";
import { AttestationVerifier } from "./verifier.js";

describe("AttestationVerifier", () => {
  const TEST_ORIGIN = "https://exchange.com";
  let verifier: AttestationVerifier;
  let mockGuardian: GuardianRpcAdapter;

  beforeEach(() => {
    // Inject a mock Guardian adapter to bypass actual network calls
    mockGuardian = new GuardianRpcAdapter("mock://sas.helius.dev");
    verifier = new AttestationVerifier(mockGuardian);
  });

  it("AC-1.3.1: successfully verifies a valid hardware attestation", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_ORIGIN);
    const result = await verifier.verify(attestation, TEST_ORIGIN);

    expect(result.success).toBe(true);
    expect(result.attestationStatus).toBe("VALID_HARDWARE");
    expect(result.deviceId).toBeDefined();
  });

  it("AC-1.3.2: rejects attestation if RP ID does not match origin", async () => {
    const attestation = MockTEE.generateMockAttestation("https://fake-exchange.com");
    const result = await verifier.verify(attestation, TEST_ORIGIN);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.ORIGIN_MISMATCH);
    expect(result.attestationStatus).toBe("INVALID");
  });

  it("AC-1.3.3: rejects attestation with untrusted AAGUID", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_ORIGIN, "untrusted-aaguid");
    const result = await verifier.verify(attestation, TEST_ORIGIN);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.UNTRUSTED_AAGUID);
    expect(result.attestationStatus).toBe("SOFTWARE_BACKED");
  });

  it("rejects attestation if hardware flag is missing", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_ORIGIN, undefined, false);
    const result = await verifier.verify(attestation, TEST_ORIGIN);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.UNTRUSTED_AAGUID);
    expect(result.attestationStatus).toBe("SOFTWARE_BACKED");
  });

  it("AC-1.3.5: returns error if Guardian RPC verification fails", async () => {
    // Simulate invalid quote via mock guardian logic
    const attestation = MockTEE.generateMockAttestation(TEST_ORIGIN);
    // Force invalid quote by tampering with base64 string for the mock guardian's check
    attestation.attestationObject += "INVALID_QUOTE";

    const result = await verifier.verify(attestation, TEST_ORIGIN);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.INVALID_TEEPIN_QUOTE);
  });

  it("AC-1.3.6: returns standardized error result on internal failure", async () => {
    // Pass malformed JSON to trigger catch block
    const attestation = MockTEE.generateMockAttestation(TEST_ORIGIN);
    attestation.attestationObject = Buffer.from("{malformed}").toString("base64");

    const result = await verifier.verify(attestation, TEST_ORIGIN);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.INTERNAL_ERROR);
    expect(result.attestationStatus).toBe("INVALID");
  });
});
