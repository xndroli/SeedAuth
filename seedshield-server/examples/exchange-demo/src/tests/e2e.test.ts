import { describe, it, expect, beforeAll } from "vitest";
import { MockTEE } from "../../../src/core/test-utils/mock-tee.js";
import { SOLANA_SEED_VAULT_AAGUID } from "../../../src/core/constants.js";
import axios from "axios";

const BASE_URL = "http://localhost:3000";

describe("Exchange Demo E2E (AC-5.1.1, AC-5.1.5, AC-5.2.1)", () => {
  const userId = "test-user-" + Math.random().toString(36).substring(7);
  let firstMultisigPda: string;

  it("should successfully register with a genuine Seeker device", async () => {
    // 1. Get Challenge
    const challengeRes = await axios.get(`${BASE_URL}/challenge/${userId}`);
    const challenge = challengeRes.data.challenge;

    // 2. Generate Genuine Hardware Attestation (AC-5.1.5)
    const attestation = MockTEE.generateMockAttestation(
      "exchange.com",
      challenge,
      SOLANA_SEED_VAULT_AAGUID,
      true
    );

    // 3. Register
    const registerRes = await axios.post(`${BASE_URL}/register`, {
      userId,
      attestation
    });

    expect(registerRes.data.success).toBe(true);
    expect(registerRes.data.multisigPda).toBeDefined();
    firstMultisigPda = registerRes.data.multisigPda;
    expect(registerRes.data.message).toContain("SeedShield Silicon Identity");
  });

  it("should reject registration from a non-Seeker AAGUID (AC-5.1.3, FR7)", async () => {
    const userId2 = "fake-user-" + Math.random().toString(36).substring(7);
    const challengeRes = await axios.get(`${BASE_URL}/challenge/${userId2}`);
    const challenge = challengeRes.data.challenge;

    // 4. Generate Fake Hardware Attestation (Software AAGUID)
    const fakeAttestation = MockTEE.generateMockAttestation(
      "exchange.com",
      challenge,
      "00000000-0000-0000-0000-000000000000",
      false
    );

    try {
      await axios.post(`${BASE_URL}/register`, {
        userId: userId2,
        attestation: fakeAttestation
      });
      throw new Error("Should have rejected fake attestation");
    } catch (error: any) {
      expect(error.response.status).toBe(403);
      expect(error.response.data.errorCode).toBe("UNTRUSTED_AAGUID");
      expect(error.response.data.attestationStatus).toBe("SOFTWARE_BACKED");
    }
  });

  it("should demonstrate idempotent registration (AC-5.1.7)", async () => {
    // Re-register same user
    const challengeRes = await axios.get(`${BASE_URL}/challenge/${userId}`);
    const challenge = challengeRes.data.challenge;

    const attestation = MockTEE.generateMockAttestation(
      "exchange.com",
      challenge,
      SOLANA_SEED_VAULT_AAGUID,
      true
    );

    const registerRes = await axios.post(`${BASE_URL}/register`, {
      userId,
      attestation
    });

    expect(registerRes.data.success).toBe(true);
    // Patch 6: Assert same PDA is returned for idempotency
    expect(registerRes.data.multisigPda).toBe(firstMultisigPda);
  });

  it("should successfully migrate a legacy user (AC-5.2.1)", async () => {
    const userId3 = "legacy-user-" + Math.random().toString(36).substring(7);
    
    const challengeRes = await axios.get(`${BASE_URL}/challenge/${userId3}`);
    const challenge = challengeRes.data.challenge;

    const attestation = MockTEE.generateMockAttestation(
      "exchange.com",
      challenge,
      SOLANA_SEED_VAULT_AAGUID,
      true
    );

    const migrateRes = await axios.post(`${BASE_URL}/migrate/enroll`, {
      userId: userId3,
      legacyToken: userId3,
      attestation
    });

    expect(migrateRes.data.success).toBe(true);
    expect(migrateRes.data.multisigAddress).toBeDefined();
    expect(migrateRes.data.message).toContain("Migration Complete");
  });
});
