import { describe, it, expect, beforeEach, vi } from "vitest";
import { FeePayerSubsidizer } from "./subsidizer.js";
import { MockTEE } from "../../core/test-utils/mock-tee.js";
import { Keypair, Transaction, SystemProgram, PublicKey } from "@solana/web3.js";
import { SeedShieldErrorCode } from "../../core/types.js";
import { GuardianRpcAdapter } from "../../core/guardian-rpc.js";
import { AttestationVerifier } from "../attestation/verifier.js";
import { ThrottlePolicy } from "./throttle.js";
import { NonceManager } from "./nonce-manager.js";

import { AuditManager } from "../multisig/audit-manager.js";

describe("FeePayerSubsidizer", () => {
  const TEST_ORIGIN = "https://exchange.com";
  const TEST_RP_ID = "exchange.com";
  const TEST_CHALLENGE = "random-challenge-nonce";
  const CURRENT_VERSION = "0.1.0";
  
  let subsidizer: FeePayerSubsidizer;
  let verifier: AttestationVerifier;
  let throttle: ThrottlePolicy;
  let nonceManager: NonceManager;
  let auditManager: AuditManager;
  let primaryFeePayer: Keypair;

  beforeEach(() => {
    primaryFeePayer = Keypair.generate();
    const mockGuardian = new GuardianRpcAdapter("mock://sas.helius.dev");
    verifier = new AttestationVerifier(mockGuardian);
    throttle = new ThrottlePolicy(5, 1000 * 60 * 60 * 24);
    nonceManager = new NonceManager("http://localhost");
    auditManager = new AuditManager("http://localhost");
    subsidizer = new FeePayerSubsidizer(
      verifier,
      throttle,
      nonceManager,
      auditManager,
      primaryFeePayer,
      undefined,
      "http://localhost"
    );
    
    // Mock getBalance to return high balance for primary
    vi.spyOn((subsidizer as any).connection, 'getBalance').mockResolvedValue(1e9);
  });

  it("successfully subsidizes a valid request", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    
    // Create a transaction signed by the user
    const userKeyPair = Keypair.fromSeed(Buffer.alloc(32, 1));
    const transaction = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: userKeyPair.publicKey,
        toPubkey: Keypair.generate().publicKey,
        lamports: 1000,
      })
    );
    transaction.recentBlockhash = "11111111111111111111111111111111";
    transaction.feePayer = primaryFeePayer.publicKey;
    
    // Real signature from the user
    transaction.partialSign(userKeyPair);

    const result = await subsidizer.requestSubsidizedSignature(
      transaction.serialize({ verifySignatures: false }).toString("base64"),
      attestation,
      TEST_ORIGIN,
      TEST_CHALLENGE,
      CURRENT_VERSION
    );

    expect(result.success).toBe(true);
    expect(result.signedTransaction).toBeDefined();
    
    const signedTx = Transaction.from(Buffer.from(result.signedTransaction!, "base64"));
    expect(signedTx.signatures.some(s => s.publicKey.equals(primaryFeePayer.publicKey))).toBe(true);
    // Verify user signature is still there and valid
    expect(signedTx.verifySignatures(false)).toBe(true);
  });

  it("rejects software attestation", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE, undefined, false);
    const result = await subsidizer.requestSubsidizedSignature(
      "base64tx",
      attestation,
      TEST_ORIGIN,
      TEST_CHALLENGE,
      CURRENT_VERSION
    );

    expect(result.success).toBe(false);
    expect(result.error?.code).toBe(SeedShieldErrorCode.UNTRUSTED_AAGUID);
  });

  it("enforces throttle limits", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    const userKeyPair = Keypair.fromSeed(Buffer.alloc(32, 1));
    const transaction = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: userKeyPair.publicKey,
        toPubkey: userKeyPair.publicKey,
        lamports: 0,
      })
    );
    transaction.recentBlockhash = "11111111111111111111111111111111";
    transaction.feePayer = primaryFeePayer.publicKey;
    transaction.partialSign(userKeyPair);
    const txBase64 = transaction.serialize({ verifySignatures: false }).toString("base64");

    // Use up 5 limit
    for (let i = 0; i < 5; i++) {
      await subsidizer.requestSubsidizedSignature(txBase64, attestation, TEST_ORIGIN, TEST_CHALLENGE, CURRENT_VERSION);
    }

    const result = await subsidizer.requestSubsidizedSignature(txBase64, attestation, TEST_ORIGIN, TEST_CHALLENGE, CURRENT_VERSION);
    expect(result.success).toBe(false);
    expect(result.error?.code).toBe(SeedShieldErrorCode.THROTTLE_LIMIT_EXCEEDED);
  });

  it("rejects invalid transaction signatures", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    const userKeyPair = Keypair.fromSeed(Buffer.alloc(32, 1));
    const transaction = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: userKeyPair.publicKey,
        toPubkey: userKeyPair.publicKey,
        lamports: 10,
      })
    );
    transaction.recentBlockhash = "11111111111111111111111111111111";
    transaction.feePayer = primaryFeePayer.publicKey;
    
    // Add a manual invalid signature (junk data)
    transaction.addSignature(userKeyPair.publicKey, Buffer.alloc(64, 1));
    
    const txBase64 = transaction.serialize({ verifySignatures: false }).toString("base64");

    const result = await subsidizer.requestSubsidizedSignature(txBase64, attestation, TEST_ORIGIN, TEST_CHALLENGE, CURRENT_VERSION);
    expect(result.success).toBe(false);
    expect(result.error?.code).toBe(SeedShieldErrorCode.USER_VERIFICATION_FAILED);
  });

  it("rejects unauthorized program instructions (Finding 11)", async () => {
    const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
    const userKeyPair = Keypair.generate();
    
    // Malicious program ID
    const maliciousProgramId = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"); // Token Program
    const transaction = new Transaction().add({
      keys: [{ pubkey: userKeyPair.publicKey, isSigner: true, isWritable: false }],
      programId: maliciousProgramId,
      data: Buffer.alloc(0),
    });
    transaction.recentBlockhash = "11111111111111111111111111111111";
    transaction.feePayer = primaryFeePayer.publicKey;
    transaction.partialSign(userKeyPair);

    const txBase64 = transaction.serialize({ verifySignatures: false }).toString("base64");

    const result = await subsidizer.requestSubsidizedSignature(
      txBase64,
      attestation,
      TEST_ORIGIN,
      TEST_CHALLENGE,
      CURRENT_VERSION
    );

    expect(result.success).toBe(false);
    expect(result.error?.code).toBe(SeedShieldErrorCode.INTERNAL_ERROR);
    expect(result.error?.message).toContain("unauthorized instructions");
  });

  describe("SDK Version Deprecation (Story 5.3)", () => {
    it("AC-5.3.1: rejects subsidized signature if SDK version is deprecated", async () => {
      const attestation = MockTEE.generateMockAttestation(TEST_RP_ID, TEST_CHALLENGE);
      const userKeyPair = Keypair.generate();
      const transaction = new Transaction().add(
        SystemProgram.transfer({
          fromPubkey: userKeyPair.publicKey,
          toPubkey: userKeyPair.publicKey,
          lamports: 0,
        })
      );
      transaction.recentBlockhash = "11111111111111111111111111111111";
      transaction.feePayer = primaryFeePayer.publicKey;
      transaction.partialSign(userKeyPair);
      const txBase64 = transaction.serialize({ verifySignatures: false }).toString("base64");

      const result = await subsidizer.requestSubsidizedSignature(
        txBase64,
        attestation,
        TEST_ORIGIN,
        TEST_CHALLENGE,
        "0.0.9" // Deprecated version
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe(SeedShieldErrorCode.VERSION_DEPRECATED);
    });
  });
});
