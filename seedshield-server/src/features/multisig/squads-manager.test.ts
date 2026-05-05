import * as multisig from "@sqds/multisig";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CONFIG } from "../../core/config.js";
import { MultisigManager } from "./squads-manager.js";

// Mock @sqds/multisig
vi.mock("@sqds/multisig", () => ({
  getMultisigPda: vi.fn(),
  rpc: {
    multisigCreateV2: vi.fn(),
  },
  types: {
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

// Mock @solana/web3.js Connection
vi.mock("@solana/web3.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@solana/web3.js")>();
  return {
    ...actual,
    Connection: vi.fn().mockImplementation(function (this: any) {
      this.getAccountInfo = vi.fn();
      this.getBalance = vi.fn().mockResolvedValue(1e9); // Default 1 SOL
      this.getLatestBlockhash = vi.fn().mockResolvedValue({ blockhash: "hash", lastValidBlockHeight: 100 });
      this.confirmTransaction = vi.fn().mockResolvedValue({});
      return this;
    }),
  };
});

describe("MultisigManager", () => {
  let manager: MultisigManager;
  let mockConnection: any;
  const userPublicKey = new PublicKey("11111111111111111111111111111112");
  const multisigPda = new PublicKey("11111111111111111111111111111113");
  const feePayer = Keypair.generate();

  beforeEach(() => {
    vi.clearAllMocks();
    manager = new MultisigManager("http://localhost:8899");
    mockConnection = (manager as any).connection;

    (multisig.getMultisigPda as any).mockReturnValue([multisigPda, 255]);
  });

  it("AC-3.1.4: derives PDA deterministically from user public key", () => {
    const [pda] = manager.deriveMultisigPda(userPublicKey);
    expect(pda).toBe(multisigPda);
    expect(multisig.getMultisigPda).toHaveBeenCalledWith({
      createKey: userPublicKey,
      programId: CONFIG.SQUADS_PROGRAM_ID,
    });
  });

  it("AC-3.1.5: returns existing PDA if account already exists and is valid (Idempotency)", async () => {
    mockConnection.getAccountInfo.mockResolvedValue({ 
      data: Buffer.from([]),
      owner: CONFIG.SQUADS_PROGRAM_ID 
    });

    const result = await manager.ensureMultisig(userPublicKey, feePayer);

    expect(result).toBe(multisigPda);
    expect(multisig.rpc.multisigCreateV2).not.toHaveBeenCalled();
  });

  it("throws error if PDA is occupied by non-Squads account (Collision)", async () => {
    mockConnection.getAccountInfo.mockResolvedValue({ 
      data: Buffer.from([]),
      owner: PublicKey.default 
    });

    await expect(manager.ensureMultisig(userPublicKey, feePayer))
      .rejects.toThrow("INTERNAL_ERROR"); // Sanitized error
  });

  it("fails if fee payer has insufficient funds", async () => {
    mockConnection.getAccountInfo.mockResolvedValue(null);
    mockConnection.getBalance.mockResolvedValue(1000); // Very low balance

    await expect(manager.ensureMultisig(userPublicKey, feePayer))
      .rejects.toThrow("INTERNAL_ERROR");
  });

  it("AC-3.1.2 & AC-3.1.3: creates a new multisig with correct threshold and timelock", async () => {
    mockConnection.getAccountInfo.mockResolvedValue(null);
    (multisig.rpc.multisigCreateV2 as any).mockResolvedValue("signature");

    const result = await manager.ensureMultisig(userPublicKey, feePayer);

    expect(result).toBe(multisigPda);
    expect(multisig.rpc.multisigCreateV2).toHaveBeenCalledWith(
      expect.objectContaining({
        multisigPda,
        createKey: userPublicKey,
        timeLock: CONFIG.RECOVERY_TIMELOCK_SECONDS,
        threshold: 1,
      })
    );
    expect(mockConnection.confirmTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ signature: "signature" }),
      "confirmed"
    );
  });
});
