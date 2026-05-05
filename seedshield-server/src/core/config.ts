import { PublicKey } from "@solana/web3.js";

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
   * Mandatory timelock for Guardian-initiated rotations (in seconds).
   * 72 hours = 259200 seconds.
   */
  RECOVERY_TIMELOCK_SECONDS: 259200,
};
