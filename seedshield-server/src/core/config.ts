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
   * Minimum balance (in SOL) required for a fee payer to be considered available.
   */
  MIN_FEE_PAYER_BALANCE_SOL: 0.05,

  /**
   * Maximum number of subsidized transactions per device per 24h window.
   */
  MAX_SUBSIDIZED_TX_PER_DEVICE: 5,

  /**
   * Authorized Program IDs that the subsidizer is allowed to sign for.
   * By default, only the Squads v4 program and System Program are authorized.
   */
  AUTHORIZED_PROGRAM_IDS: [
    "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf", // Squads v4
    "11111111111111111111111111111111", // System Program
  ],

  /**
   * Minimum SDK version required for all hardware-attested requests.
   * Requests with version < this will be rejected with VERSION_DEPRECATED.
   */
  MIN_CLIENT_VERSION: process.env.MIN_CLIENT_VERSION || "0.1.0",

  /**
   * Authorized Relying Party ID (Domain).
   * Used to prevent origin spoofing.
   */
  RP_ID: process.env.RP_ID || "exchange.com",

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
