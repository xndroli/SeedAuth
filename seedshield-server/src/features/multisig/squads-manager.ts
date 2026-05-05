import * as multisig from "@sqds/multisig";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import { CONFIG } from "../../core/config.js";
import { SeedShieldErrorCode } from "../../core/types.js";

export class MultisigManager {
  private readonly connection: Connection;
  private readonly programId: PublicKey;

  constructor(
    rpcEndpoint: string = CONFIG.RPC_ENDPOINT,
    programId: PublicKey = CONFIG.SQUADS_PROGRAM_ID
  ) {
    this.connection = new Connection(rpcEndpoint, "confirmed");
    this.programId = programId;
  }

  /**
   * Derives the Multisig PDA deterministically from the user's hardware public key.
   * Using the user's public key as the createKey ensures 1:1 mapping.
   */
  deriveMultisigPda(userPublicKey: PublicKey): [PublicKey, number] {
    return multisig.getMultisigPda({
      createKey: userPublicKey,
      programId: this.programId,
    });
  }

  /**
   * Checks if a multisig account already exists on-chain and is valid.
   */
  async checkAccountExists(multisigPda: PublicKey): Promise<boolean> {
    const accountInfo = await this.connection.getAccountInfo(multisigPda);
    if (!accountInfo) return false;

    // Guard: Ensure PDA is owned by Squads program (Fixes Multisig PDA Ownership Check)
    if (!accountInfo.owner.equals(this.programId)) {
      throw new Error(`PDA collision: account at ${multisigPda.toBase58()} not owned by Squads`);
    }

    return true;
  }

  /**
   * Deploys a new 1-of-2 Squads v4 multisig.
   * Idempotent: returns existing PDA if already deployed.
   */
  async ensureMultisig(
    userPublicKey: PublicKey,
    feePayer: Keypair,
    guardianPublicKey: PublicKey = CONFIG.INSTITUTIONAL_GUARDIAN_PUBKEY
  ): Promise<PublicKey> {
    const [multisigPda] = this.deriveMultisigPda(userPublicKey);

    try {
      if (await this.checkAccountExists(multisigPda)) {
        return multisigPda;
      }

      // 1. Guard: Check fee payer balance (Fixes Insufficient Fee Payer Funds)
      const balance = await this.connection.getBalance(feePayer.publicKey);
      if (balance < 1e7) { // 0.01 SOL safety threshold
        throw new Error("Insufficient funds in fee payer account for multisig deployment");
      }

      const signature = await multisig.rpc.multisigCreateV2({
        connection: this.connection,
        feePayer,
        multisigPda,
        createKey: userPublicKey,
        configAuthority: null,
        timeLock: CONFIG.RECOVERY_TIMELOCK_SECONDS,
        members: [
          {
            key: userPublicKey,
            permissions: multisig.types.Permissions.all(),
          },
          {
            key: guardianPublicKey,
            permissions: multisig.types.Permissions.fromPermissions([
              multisig.types.Permission.Propose,
              multisig.types.Permission.Vote,
            ]),
          },
        ],
        threshold: 1,
        programId: this.programId,
      });

      // 2. Hardened Confirmation (Fixes Confirmation Hang)
      const latestBlockhash = await this.connection.getLatestBlockhash();
      await this.connection.confirmTransaction({
        signature,
        ...latestBlockhash
      }, "confirmed");

      return multisigPda;
    } catch (error) {
      console.error("Failed to create Squads multisig:", error);
      throw new Error(SeedShieldErrorCode.INTERNAL_ERROR);
    }
  }
}
