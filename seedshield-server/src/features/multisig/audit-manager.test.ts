import { Connection, PublicKey } from "@solana/web3.js";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, AuditManager } from "./audit-manager.js";
import { SeedShieldErrorCode } from "../../core/types.js";

// Mock @solana/web3.js Connection
vi.mock("@solana/web3.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@solana/web3.js")>();
  return {
    ...actual,
    Connection: vi.fn().mockImplementation(function (this: any) {
      this.getSignaturesForAddress = vi.fn();
      this.getParsedTransaction = vi.fn();
      return this;
    }),
  };
});

describe("AuditManager", () => {
  let manager: AuditManager;
  let mockConnection: any;
  const multisigAddress = "11111111111111111111111111111113";

  beforeEach(() => {
    vi.clearAllMocks();
    manager = new AuditManager("http://localhost:8899");
    mockConnection = (manager as any).connection;
  });

  it("AC-3.2.2 & AC-3.2.3: returns formatted audit trail events (Parallel Fetching)", async () => {
    const mockSignatures = [
      { signature: "sig1", memo: "memo1" },
      { signature: "sig2", memo: null },
    ];
    mockConnection.getSignaturesForAddress.mockResolvedValue(mockSignatures);

    const mockTx1 = {
      blockTime: 1625097600,
      slot: 12345,
      meta: {
        logMessages: ["Instruction: MultisigCreateV2"],
      },
    };
    const mockTx2 = {
      blockTime: 1625184000,
      slot: 12346,
      meta: {
        logMessages: ["Instruction: ConfigProposalCreate"],
      },
    };

    mockConnection.getParsedTransaction.mockImplementation((sig: string) => {
      if (sig === "sig1") return Promise.resolve(mockTx1);
      if (sig === "sig2") return Promise.resolve(mockTx2);
      return Promise.resolve(null);
    });

    const result = await manager.getAuditTrail(multisigAddress);

    expect(result.success).toBe(true);
    expect(result.data).toHaveLength(2);
    // Signatures are mapped in parallel; verify both exist
    const sig1Event = result.data?.find(e => e.txSignature === "sig1");
    const sig2Event = result.data?.find(e => e.txSignature === "sig2");

    expect(sig1Event).toEqual({
      txSignature: "sig1",
      eventType: AuditEventType.REGISTRATION,
      timestamp: 1625097600,
      details: expect.objectContaining({ slot: 12345, memo: "memo1" }),
    });
    expect(sig2Event).toEqual({
      txSignature: "sig2",
      eventType: AuditEventType.ROTATION,
      timestamp: 1625184000,
      details: expect.objectContaining({ slot: 12346 }),
    });
  });

  it("handles pruned transactions by returning UNKNOWN with error detail", async () => {
    mockConnection.getSignaturesForAddress.mockResolvedValue([{ signature: "pruned_sig" }]);
    mockConnection.getParsedTransaction.mockResolvedValue(null);

    const result = await manager.getAuditTrail(multisigAddress);

    expect(result.data![0]).toEqual(expect.objectContaining({
      txSignature: "pruned_sig",
      eventType: AuditEventType.UNKNOWN,
      details: { error: "Transaction data not available (possibly pruned)" }
    }));
  });

  it("fails early for invalid multisig addresses", async () => {
    const result = await manager.getAuditTrail("invalid-address");

    expect(result.success).toBe(false);
    expect(result.message).toBe("Invalid multisig address format");
  });

  it("AC-3.2.5: follows Sealed-Error pattern on RPC failure", async () => {
    mockConnection.getSignaturesForAddress.mockRejectedValue(new Error("RPC Timeout"));

    const result = await manager.getAuditTrail(multisigAddress);

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SeedShieldErrorCode.INTERNAL_ERROR);
    expect(result.message).toBe("Failed to fetch on-chain audit trail");
  });

  it("identifies UNKNOWN events for non-Squads transactions", async () => {
    mockConnection.getSignaturesForAddress.mockResolvedValue([{ signature: "sig3" }]);
    mockConnection.getParsedTransaction.mockResolvedValue({
      blockTime: 1625270400,
      meta: { logMessages: ["Instruction: SomeOtherAction"] },
    });

    const result = await manager.getAuditTrail(multisigAddress);

    expect(result.data![0].eventType).toBe(AuditEventType.UNKNOWN);
  });
});
