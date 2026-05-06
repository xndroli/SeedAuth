import { Connection, Keypair, PublicKey, Transaction } from "@solana/web3.js";
import * as multisig from "@sqds/multisig";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CONFIG } from "../../core/config.js";
import { SeedShieldErrorCode } from "../../core/types.js";
import { InstitutionalGuardianProxy } from "./guardian-proxy.js";
import { MockTEE } from "../../core/test-utils/mock-tee.js";
import { AttestationVerifier } from "../attestation/verifier.js";
import { GuardianRpcAdapter } from "../../core/guardian-rpc.js";

// Use vi.hoisted to allow access inside vi.mock
const { mockConnectionInstance } = vi.hoisted(() => ({
  mockConnectionInstance: {
    getAccountInfo: vi.fn(),
    getBalance: vi.fn().mockResolvedValue(1e9),
    getLatestBlockhash: vi.fn().mockResolvedValue({ blockhash: "hash", lastValidBlockHeight: 100 }),
    confirmTransaction: vi.fn().mockResolvedValue({}),
    getProgramAccounts: vi.fn().mockResolvedValue([]),
    getSignaturesForAddress: vi.fn().mockResolvedValue([]),
    getParsedTransaction: vi.fn(),
  }
}));

// Mock dependencies
vi.mock("@sqds/multisig", () => ({
  rpc: {
    multisigVoteV2: vi.fn(),
    configTransactionCreateV2: vi.fn(),
  },
  accounts: {
    Multisig: {
      fromAccountAddress: vi.fn(),
    },
    ConfigTransaction: {
      fromAccountInfo: vi.fn(() => [{ actions: [] }]),
    },
    Proposal: {
      fromAccountAddress: vi.fn(),
    },
  },
  getProposalPda: vi.fn(() => [new PublicKey("11111111111111111111111111111114")]),
  getMultisigPda: vi.fn(() => [new PublicKey("11111111111111111111111111111111"), 255]),
  types: {
    Vote: {
      Approve: { __kind: "Approve" },
    },
    Permissions: {
        all: vi.fn(() => ({ mask: 7 })),
        fromPermissions: vi.fn(() => ({ mask: 3 })),
    },
    Permission: {
      Propose: 1,
      Vote: 2,
    },
  },
}));

vi.mock("@solana/web3.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@solana/web3.js")>();
  return {
    ...actual,
    Connection: vi.fn().mockImplementation(function() {
        return mockConnectionInstance;
    }),
  };
});

describe("InstitutionalGuardianProxy", () => {
  let proxy: InstitutionalGuardianProxy;
  const guardianKeypair = Keypair.generate();
  const multisigPda = new PublicKey("11111111111111111111111111111111");
  const challenge = `${Date.now()}:challenge`;

  beforeEach(() => {
    vi.clearAllMocks();
    
    // Reset connection mock behaviors
    mockConnectionInstance.getAccountInfo.mockReset();
    mockConnectionInstance.getProgramAccounts.mockResolvedValue([]);
    mockConnectionInstance.getLatestBlockhash.mockResolvedValue({ blockhash: "hash", lastValidBlockHeight: 100 });

    const mockGuardian = new GuardianRpcAdapter("mock://sas.helius.dev");
    const verifier = new AttestationVerifier(mockGuardian);
    proxy = new InstitutionalGuardianProxy(undefined, undefined, verifier);

    // Mock Multisig State
    (multisig.accounts.Multisig.fromAccountAddress as any).mockResolvedValue({
      members: [
        { key: CONFIG.INSTITUTIONAL_GUARDIAN_PUBKEY },
        { key: Keypair.generate().publicKey }, // Old user key
      ],
      transactionIndex: 0n,
      timeLock: 259200,
    });
  });

  it("AC-4.3.1 & AC-4.3.2: co-signs rotation after successful attestation", async () => {
    const challenge = `${Date.now()}:fresh-challenge`;
    const attestation = MockTEE.generateMockAttestation("exchange.com", challenge);
    
    const mockSeed = Buffer.alloc(32, 1);
    const mockKeyPair = Keypair.fromSeed(mockSeed);
    
    const tx = new Transaction().add({
        keys: [],
        programId: PublicKey.default,
        data: Buffer.alloc(0),
    });
    tx.recentBlockhash = "11111111111111111111111111111111";
    tx.feePayer = mockKeyPair.publicKey;
    tx.partialSign(mockKeyPair);
    const txBase64 = tx.serialize({ verifySignatures: false }).toString("base64");

    // Mock verification
    vi.spyOn((proxy as any).verifier, "verify").mockResolvedValue({
        success: true,
        attestationStatus: "VALID_HARDWARE",
        timestamp: new Date().toISOString(),
        deviceId: mockKeyPair.publicKey.toBase58(),
    });

    mockConnectionInstance.getAccountInfo.mockResolvedValue({
        owner: CONFIG.SQUADS_PROGRAM_ID,
        data: Buffer.alloc(224)
    });

    (multisig.rpc.multisigVoteV2 as any).mockResolvedValue("vote-sig");
    (multisig.rpc.configTransactionCreateV2 as any).mockResolvedValue("prop-sig");

    const result = await proxy.approveRotation(
      multisigPda,
      attestation,
      txBase64,
      guardianKeypair,
      challenge
    );

    expect(result).toBe("vote-sig");
    expect(multisig.rpc.multisigVoteV2).toHaveBeenCalled();
  });

  it("AC-4.3.5: rejects if transaction is not signed by the new user key (Binding mismatch)", async () => {
    const attestation = MockTEE.generateMockAttestation("exchange.com", challenge);
    const maliciousKey = Keypair.generate();
    
    const tx = new Transaction().add({
        keys: [],
        programId: PublicKey.default,
        data: Buffer.alloc(0),
    });
    tx.recentBlockhash = "11111111111111111111111111111111";
    tx.feePayer = maliciousKey.publicKey;
    tx.partialSign(maliciousKey);
    const txBase64 = tx.serialize({ verifySignatures: false }).toString("base64");

    vi.spyOn((proxy as any).verifier, "verify").mockResolvedValue({
        success: true,
        attestationStatus: "VALID_HARDWARE",
        timestamp: new Date().toISOString(),
        deviceId: "some-other-key",
    });

    await expect(proxy.approveRotation(multisigPda, attestation, txBase64, guardianKeypair, challenge))
      .rejects.toThrow(SeedShieldErrorCode.DEVICE_COMPROMISED_ANOMALY);
  });

  it("AC-4.3.7: rejects if challenge has expired", async () => {
    const staleTime = Date.now() - (20 * 60 * 1000);
    const staleChallenge = `${staleTime}:expired`;
    const attestation = MockTEE.generateMockAttestation("exchange.com", staleChallenge);
    
    await expect(proxy.approveRotation(multisigPda, attestation, "any-tx", guardianKeypair, staleChallenge))
      .rejects.toThrow(SeedShieldErrorCode.CHALLENGE_EXPIRED);
  });
});
