import { Keypair, PublicKey } from "@solana/web3.js";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MockTEE } from "../../core/test-utils/mock-tee.js";
import { AttestationVerifier } from "../attestation/verifier.js";
import { MultisigManager } from "../multisig/squads-manager.js";
import { MigrationHandler, type UserDb } from "./migration-handler.js";
import { SeedShieldErrorCode } from "../../core/types.js";

// Mock dependencies
vi.mock("../attestation/verifier.js");
vi.mock("../multisig/squads-manager.js");

describe("MigrationHandler", () => {
  let handler: MigrationHandler;
  let mockVerifier: any;
  let mockMultisigManager: any;
  let mockUserDb: UserDb;

  const TEST_RP_ID = "exchange.com";
  const TEST_ORIGIN = "https://exchange.com";
  const TEST_CHALLENGE = "random-challenge";
  const TEST_LEGACY_TOKEN = "valid-legacy-token";
  const TEST_USER_ID = "user-123";
  const feePayer = Keypair.generate();
  const multisigPda = new PublicKey("11111111111111111111111111111114");

  beforeEach(() => {
    vi.clearAllMocks();
    mockVerifier = new AttestationVerifier();
    mockMultisigManager = new MultisigManager();
    mockUserDb = {
      getUserByLegacyToken: vi.fn(),
      updateUserMigration: vi.fn(),
      isHardwareLinked: vi.fn(),
    };
    handler = new MigrationHandler(mockVerifier, mockMultisigManager, mockUserDb);
  });

  it("successfully migrates a legacy user to SeedShield", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);

    vi.mocked(mockUserDb.getUserByLegacyToken).mockResolvedValue({ userId: TEST_USER_ID, smsEnabled: true });
    vi.mocked(mockUserDb.isHardwareLinked).mockResolvedValue(false);

    mockVerifier.verify.mockResolvedValue({
      success: true,
      attestationStatus: "VALID_HARDWARE",
      timestamp: new Date().toISOString(),
    });

    mockMultisigManager.ensureMultisig.mockResolvedValue(multisigPda);

    const result = await handler.enroll(TEST_LEGACY_TOKEN, attestation, TEST_ORIGIN, TEST_CHALLENGE, feePayer);

    expect(result.success).toBe(true);
    expect(result.legacyUserId).toBe(TEST_USER_ID);
    expect(result.multisigAddress).toBe(multisigPda.toBase58());
    expect(mockUserDb.updateUserMigration).toHaveBeenCalledWith(
      TEST_USER_ID,
      expect.any(String),
      multisigPda.toBase58()
    );
  });

  it("rejects migration if legacy token is invalid", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    vi.mocked(mockUserDb.getUserByLegacyToken).mockResolvedValue(null);

    const result = await handler.enroll("invalid-token", attestation, TEST_ORIGIN, TEST_CHALLENGE, feePayer);

    expect(result.success).toBe(false);
    expect(result.message).toContain("Invalid or expired legacy session token");
    expect(mockVerifier.verify).not.toHaveBeenCalled();
  });

  it("rejects migration if hardware attestation fails (Safe-Fail)", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE, "SOFTWARE_AAGUID", false);
    vi.mocked(mockUserDb.getUserByLegacyToken).mockResolvedValue({ userId: TEST_USER_ID, smsEnabled: true });

    mockVerifier.verify.mockResolvedValue({
      success: false,
      attestationStatus: "SOFTWARE_BACKED",
      errorCode: SeedShieldErrorCode.SOFTWARE_ATTESTATION_REJECTED,
      timestamp: new Date().toISOString(),
    });

    const result = await handler.enroll(TEST_LEGACY_TOKEN, attestation, TEST_ORIGIN, TEST_CHALLENGE, feePayer);

    expect(result.success).toBe(false);
    expect(result.attestationStatus).toBe("SOFTWARE_BACKED");
    expect(mockUserDb.updateUserMigration).not.toHaveBeenCalled();
  });

  it("prevents double-linking the same hardware key", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    vi.mocked(mockUserDb.getUserByLegacyToken).mockResolvedValue({ userId: TEST_USER_ID, smsEnabled: true });
    vi.mocked(mockUserDb.isHardwareLinked).mockResolvedValue(true);

    mockVerifier.verify.mockResolvedValue({
      success: true,
      attestationStatus: "VALID_HARDWARE",
      timestamp: new Date().toISOString(),
    });

    const result = await handler.enroll(TEST_LEGACY_TOKEN, attestation, TEST_ORIGIN, TEST_CHALLENGE, feePayer);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.DUPLICATE_DEVICE_ID);
    expect(mockMultisigManager.ensureMultisig).not.toHaveBeenCalled();
  });
});
