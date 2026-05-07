import { beforeEach, describe, expect, it, vi } from "vitest";
import { GuardianRpcAdapter } from "../../core/guardian-rpc.js";
import { MockTEE } from "../../core/test-utils/mock-tee.js";
import { SeedShieldErrorCode } from "../../core/types.js";
import { AttestationVerifier } from "./verifier.js";

describe("AttestationVerifier", () => {
  const TEST_ORIGIN = "https://exchange.com";
  const TEST_RP_ID = "exchange.com";
  const TEST_CHALLENGE = "random-challenge-nonce";
  const MOCK_DEVICE_ID = "mock-device-id-999";
  const GUARDIAN_DEVICE_ID = "seeker-device-123";
  const CURRENT_VERSION = "0.1.0";

  let verifier: AttestationVerifier;
  let mockGuardian: GuardianRpcAdapter;

  beforeEach(() => {
    mockGuardian = new GuardianRpcAdapter("mock://sas.helius.dev");
    verifier = new AttestationVerifier(mockGuardian);
  });

  it("successfully verifies a valid hardware attestation with challenge and CBOR encoding", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE, CURRENT_VERSION);

    expect(result.success).toBe(true);
    expect(result.attestationStatus).toBe("VALID_HARDWARE");
    expect(result.deviceId).toBe(GUARDIAN_DEVICE_ID);
    expect(result.timestamp).toBeDefined();
  });

  it("rejects if challenge in clientDataJSON does not match", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    // Tamper with clientDataJSON but keep the outer challenge property
    const clientData = JSON.parse(Buffer.from(attestation.clientDataJSON, "base64").toString());
    clientData.challenge = "tampered-challenge";
    attestation.clientDataJSON = Buffer.from(JSON.stringify(clientData)).toString("base64");

    const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE, CURRENT_VERSION);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.CHALLENGE_MISMATCH);
    expect(result.message).toContain("Cryptographic challenge mismatch");
  });

  describe("SDK Version Deprecation (Story 5.3)", () => {
    const DEPRECATED_VERSION = "0.0.9";
    const INVALID_VERSION = "not-a-version";

    it("AC-5.3.2: allows requests from current SDK version", async () => {
      const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
      const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE, CURRENT_VERSION);

      expect(result.success).toBe(true);
    });

    it("AC-5.3.2: rejects requests from deprecated SDK version", async () => {
      const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
      const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE, DEPRECATED_VERSION);

      expect(result.success).toBe(false);
      expect(result.errorCode).toBe(SeedShieldErrorCode.VERSION_DEPRECATED);
      expect(result.message).toContain("deprecated");
    });

    it("AC-5.3.2: rejects requests with invalid version format", async () => {
      const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
      const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE, INVALID_VERSION);

      expect(result.success).toBe(false);
      expect(result.errorCode).toBe(SeedShieldErrorCode.INTERNAL_ERROR);
      expect(result.message).toContain("Invalid client version format");
    });

    it("AC-5.3.4: rejects requests with missing version header", async () => {
      const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
      const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE, undefined);

      expect(result.success).toBe(false);
      expect(result.errorCode).toBe(SeedShieldErrorCode.VERSION_DEPRECATED);
      expect(result.message).toContain("missing");
    });
  });

  it("rejects if origin in clientDataJSON does not match", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    const clientData = JSON.parse(Buffer.from(attestation.clientDataJSON, "base64").toString());
    clientData.origin = "https://malicious.com";
    attestation.clientDataJSON = Buffer.from(JSON.stringify(clientData)).toString("base64");

    const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE, CURRENT_VERSION);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.ORIGIN_MISMATCH);
    expect(result.message).toContain("Origin mismatch in clientDataJSON");
  });

  it("AC-1.4.3: extracts unverifiedDeviceId even when challenge does not match", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, "wrong-challenge");
    const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE, CURRENT_VERSION);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.CHALLENGE_MISMATCH);
    expect(result.unverifiedDeviceId).toBe(MOCK_DEVICE_ID);
  });

  it("sanitizes upstream Guardian errors to prevent leakage", async () => {
    mockGuardian = new GuardianRpcAdapter("mock://sas.helius.dev");
    verifier = new AttestationVerifier(mockGuardian);

    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE, CURRENT_VERSION);

    expect(result.success).toBe(true);
  });

  it("returns INTERNAL_ERROR for malformed CBOR", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    attestation.attestationObject = Buffer.from("not-cbor").toString("base64");

    const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE, CURRENT_VERSION);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.INTERNAL_ERROR);
    expect(result.unverifiedDeviceId).toBeUndefined();
  });

  it("rejects attestation if RP ID does not match normalized origin", async () => {
    const attestation = MockTEE.generateMockAttestation("wrong-domain.com", TEST_CHALLENGE);
    const result = await verifier.verify(attestation, TEST_ORIGIN, TEST_CHALLENGE, CURRENT_VERSION);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.ORIGIN_MISMATCH);
    expect(result.unverifiedDeviceId).toBe(MOCK_DEVICE_ID);
  });

  it("AC-4.3.7: rejects stale attestations (Challenge Expiry)", async () => {
    const staleTime = Date.now() - (20 * 60 * 1000); // 20 minutes ago
    const staleChallenge = `${staleTime}:expired-nonce`;
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, staleChallenge);
    
    const result = await verifier.verify(attestation, TEST_ORIGIN, staleChallenge, CURRENT_VERSION);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.CHALLENGE_EXPIRED);
    expect(result.message).toContain("Challenge has expired");
  });

  it("accepts challenges within the 15-minute window", async () => {
    const freshTime = Date.now() - (5 * 60 * 1000); // 5 minutes ago
    const freshChallenge = `${freshTime}:valid-nonce`;
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, freshChallenge);
    
    const result = await verifier.verify(attestation, TEST_ORIGIN, freshChallenge, CURRENT_VERSION);

    expect(result.success).toBe(true);
  });
});
