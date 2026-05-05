import { describe, it, expect, beforeEach, vi } from "vitest";
import { NonceManager } from "./nonce-manager.js";
import { 
  Keypair, 
  Transaction, 
  SystemProgram, 
  PublicKey,
  NonceAccount,
  LAMPORTS_PER_SOL
} from "@solana/web3.js";

describe("NonceManager", () => {
  let nonceManager: NonceManager;
  const RPC_URL = "http://localhost";

  beforeEach(() => {
    nonceManager = new NonceManager(RPC_URL);
  });

  it("should allow standard transactions without nonces", async () => {
    const tx = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: Keypair.generate().publicKey,
        toPubkey: Keypair.generate().publicKey,
        lamports: 1000,
      })
    );
    expect(await nonceManager.validateNonceUsage(tx)).toBe(true);
  });

  it("should reject nonces not managed by the pool", async () => {
    const noncePubkey = Keypair.generate().publicKey;
    const tx = new Transaction().add(
      SystemProgram.nonceAdvance({
        noncePubkey,
        authorizedPubkey: Keypair.generate().publicKey,
      })
    );
    expect(await nonceManager.validateNonceUsage(tx)).toBe(false);
  });

  it("should validate managed nonces against on-chain state", async () => {
    const nonceKeyPair = Keypair.generate();
    nonceManager.registerNonceAccount(nonceKeyPair.publicKey);
    
    const mockNonce = "11111111111111111111111111111111";
    const tx = new Transaction().add(
      SystemProgram.nonceAdvance({
        noncePubkey: nonceKeyPair.publicKey,
        authorizedPubkey: Keypair.generate().publicKey,
      })
    );
    tx.recentBlockhash = mockNonce;

    // Mock getAccountInfo to return a valid nonce account with matching blockhash
    // NonceAccount data structure is roughly 80 bytes
    const mockAccountData = Buffer.alloc(80);
    // This is a bit simplified, but let's see if we can mock NonceAccount.fromAccountData
    vi.spyOn(NonceAccount, 'fromAccountData').mockReturnValue({
        nonce: mockNonce,
        authorizedPubkey: Keypair.generate().publicKey,
        feeCalculator: { lamportsPerSignature: 5000 }
    } as any);

    vi.spyOn((nonceManager as any).connection, 'getAccountInfo').mockResolvedValue({
      data: mockAccountData
    } as any);

    expect(await nonceManager.validateNonceUsage(tx)).toBe(true);
    
    // Test blockhash mismatch
    tx.recentBlockhash = "22221111111111111111111111111111";
    expect(await nonceManager.validateNonceUsage(tx)).toBe(false);
  });
});
