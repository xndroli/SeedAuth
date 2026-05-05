import { Keypair, PublicKey } from "@solana/web3.js";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MockTEE } from "../../core/test-utils/mock-tee.js";
import { AttestationVerifier } from "../attestation/verifier.js";
import { RegistrationHandler } from "./registration-handler.js";
import { MultisigManager } from "./squads-manager.js";

// Mock dependencies
vi.mock("../attestation/verifier.js");
vi.mock("./squads-manager.js");

describe("RegistrationHandler", () => {
  let handler: RegistrationHandler;
  let mockVerifier: any;
  let mockMultisigManager: any;

  const TEST_RP_ID = "exchange.com";
  const TEST_ORIGIN = "https://exchange.com";
  const TEST_CHALLENGE = "random-challenge";
  const feePayer = Keypair.generate();
  const multisigPda = new PublicKey("11111111111111111111111111111114");

  beforeEach(() => {
    vi.clearAllMocks();
    mockVerifier = new AttestationVerifier();
    mockMultisigManager = new MultisigManager();
    handler = new RegistrationHandler(mockVerifier, mockMultisigManager);
  });

  it("successfully orchestrates registration and multisig deployment", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    
    mockVerifier.verify.mockResolvedValue({
      success: true,
      attestationStatus: "VALID_HARDWARE",
      timestamp: new Date().toISOString(),
    });

    mockMultisigManager.ensureMultisig.mockResolvedValue(multisigPda);

    const result = await handler.register(attestation, TEST_ORIGIN, TEST_CHALLENGE, feePayer);

    expect(result.success).toBe(true);
    expect(result.multisigAddress).toBe(multisigPda.toBase58());
    expect(mockMultisigManager.ensureMultisig).toHaveBeenCalledWith(
      expect.any(PublicKey),
      feePayer
    );
  });

  it("blocks multisig deployment if attestation is not valid hardware", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE, "SOFTWARE_AAGUID", false);
    
    mockVerifier.verify.mockResolvedValue({
      success: true,
      attestationStatus: "SOFTWARE_BACKED",
      timestamp: new Date().toISOString(),
    });

    const result = await handler.register(attestation, TEST_ORIGIN, TEST_CHALLENGE, feePayer);

    expect(result.success).toBe(true);
    expect(result.multisigAddress).toBeUndefined();
    expect(mockMultisigManager.ensureMultisig).not.toHaveBeenCalled();
  });
});
