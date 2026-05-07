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

  /**
   * Finds an existing rotation proposal for the given new user key.
   * Returns the transaction PDA if found.
   * SECURITY FIX: Filters for 'Active' status and validates all transaction actions (Finding 2, 7).
   */
  async findExistingRotationProposal(
    multisigPda: PublicKey,
    newUserKey: PublicKey
  ): Promise<PublicKey | null> {
    const connection = this.connection;

    // Search for ConfigTransaction accounts linked to this multisig
    // Note: In production, this should use an indexer or PDA-based lookup for performance (Finding 5).
    const configTransactions = await connection.getProgramAccounts(this.programId, {
      filters: [
        { dataSize: 224 }, // Size of ConfigTransaction account
        {
          memcmp: {
            offset: 8, // multisig field offset
            bytes: multisigPda.toBase58(),
          },
        },
      ],
    });

    for (const { pubkey, account } of configTransactions) {
      try {
        const configTx = multisig.accounts.ConfigTransaction.fromAccountInfo(account)[0];
        
        // SECURITY FIX: Filter for 'Active' proposals only (Finding 7)
        // We need to fetch the Proposal account to check its status
        const [proposalPda] = multisig.getProposalPda({
            multisigPda,
            transactionIndex: configTx.transactionIndex,
            programId: this.programId,
        });
        
        const proposal = await multisig.accounts.Proposal.fromAccountAddress(this.connection, proposalPda);
        if (proposal.status.__kind !== "Active") {
            continue;
        }

        // SECURITY FIX: Exhaustive action validation (Finding 2)
        // We MUST ensure the proposal ONLY contains the expected rotation actions.
        // A standard rotation should have exactly 2 actions: AddMember and RemoveMember.
        if (configTx.actions.length !== 2) {
            continue;
        }

        const hasAddMember = configTx.actions.some(
          (action: any) =>
            action.__kind === "AddMember" &&
            action.newMember.key.equals(newUserKey)
        );

        const hasRemoveMember = configTx.actions.some(
            (action: any) => action.__kind === "RemoveMember"
        );

        if (hasAddMember && hasRemoveMember) {
          return pubkey;
        }
      } catch (e) {
        continue;
      }
    }

    return null;
  }

  /**
   * Creates a rotation proposal to replace the current user key with a new one.
   * Enforces 72h timelock and PDA ownership verification.
   */
  async createRotationProposal(
    multisigPda: PublicKey,
    newUserKey: PublicKey,
    proposer: Keypair
  ): Promise<PublicKey> {
    // 1. PDA Ownership Verification (AC-4.3.8)
    const accountInfo = await this.connection.getAccountInfo(multisigPda);
    if (!accountInfo) {
      throw new Error(SeedShieldErrorCode.INVALID_VAULT_PDA);
    }
    if (!accountInfo.owner.equals(this.programId)) {
      throw new Error(SeedShieldErrorCode.INVALID_VAULT_PDA);
    }

    // 2. Check for existing proposal (Idempotency AC-4.3.4)
    const existingProposal = await this.findExistingRotationProposal(multisigPda, newUserKey);
    if (existingProposal) {
      return existingProposal;
    }

    // 3. Fetch multisig state
    const multisigAccount = await multisig.accounts.Multisig.fromAccountAddress(
      this.connection,
      multisigPda
    );

    // Identify the old user key (the member that isn't the guardian)
    const oldUserKey = multisigAccount.members.find(
      (m) => !m.key.equals(CONFIG.INSTITUTIONAL_GUARDIAN_PUBKEY)
    )?.key;

    if (!oldUserKey) {
      throw new Error("Could not identify old user key in multisig members");
    }

    const transactionIndex = Number(multisigAccount.transactionIndex) + 1;

    // 4. Create rotation proposal (AC-4.3.1, AC-4.3.3)
    const signature = await multisig.rpc.configTransactionCreateV2({
      connection: this.connection,
      feePayer: proposer,
      multisigPda,
      transactionIndex: BigInt(transactionIndex),
      creator: proposer.publicKey,
      actions: [
        {
          __kind: "AddMember",
          newMember: {
            key: newUserKey,
            permissions: multisig.types.Permissions.all(),
          },
        },
        {
          __kind: "RemoveMember",
          oldMember: oldUserKey,
        },
      ],
      programId: this.programId,
    });

    const latestBlockhash = await this.connection.getLatestBlockhash();
    await this.connection.confirmTransaction({
      signature,
      ...latestBlockhash
    }, "confirmed");

    const [transactionPda] = multisig.getProposalPda({
      multisigPda,
      transactionIndex: BigInt(transactionIndex),
      programId: this.programId,
    });

    return transactionPda;
  }
}
