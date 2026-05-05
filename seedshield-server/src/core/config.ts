import { Keypair, PublicKey } from "@solana/web3.js";
import bs58 from "bs58";

/**
 * SeedShield Server Configuration
 */
export const CONFIG = {
  /**
   * Solana RPC Endpoint.
   * Matches the default in GuardianRpcAdapter to ensure network alignment.
   */
  RPC_ENDPOINT: process.env.RPC_ENDPOINT || "https://mainnet.helius-rpc.com/",

  /**
   * The official Squads v4 Program ID.
   */
  SQUADS_PROGRAM_ID: new PublicKey("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"),

  /**
   * Institutional Guardian Public Key.
   * For Phase 1, this is a placeholder.
   */
  INSTITUTIONAL_GUARDIAN_PUBKEY: new PublicKey(
    process.env.GUARDIAN_PUBKEY || "11111111111111111111111111111111"
  ),

  /**
   * System Fee Payer Secret Key (Base58 encoded).
   * Used to pay for multisig deployments.
   * WARNING: In production, use a secure KMS.
   */
  SYSTEM_FEE_PAYER_SECRET: process.env.SYSTEM_FEE_PAYER_SECRET || "",

  /**
   * Fee Payer Secret Key (Base58 encoded) for subsidized transactions.
   * Defaults to SYSTEM_FEE_PAYER_SECRET if not provided.
   */
  FEE_PAYER_SECRET: process.env.FEE_PAYER_SECRET || process.env.SYSTEM_FEE_PAYER_SECRET || "",

  /**
   * Secondary Fee Payer Secret Key (Base58 encoded) for high availability fallback.
   */
  SECONDARY_FEE_PAYER_SECRET: process.env.SECONDARY_FEE_PAYER_SECRET || "",

  /**
   * Mandatory timelock for Guardian-initiated rotations (in seconds).
   * 72 hours = 259200 seconds.
   */
  RECOVERY_TIMELOCK_SECONDS: 259200,

  /**
   * Returns the Keypair for the fee payer.
   * Throws if no secret is configured.
   */
  get feePayerKeypair(): Keypair {
    const secret = this.FEE_PAYER_SECRET || this.SYSTEM_FEE_PAYER_SECRET;
    if (!secret) {
      throw new Error("FEE_PAYER_SECRET or SYSTEM_FEE_PAYER_SECRET not configured");
    }
    return Keypair.fromSecretKey(bs58.decode(secret));
  },

  /**
   * Returns the Keypair for the secondary fee payer, if configured.
   */
  get secondaryFeePayerKeypair(): Keypair | undefined {
    if (!this.SECONDARY_FEE_PAYER_SECRET) return undefined;
    return Keypair.fromSecretKey(bs58.decode(this.SECONDARY_FEE_PAYER_SECRET));
  },
};
