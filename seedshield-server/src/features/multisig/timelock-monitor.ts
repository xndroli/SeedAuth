import { Connection, PublicKey } from "@solana/web3.js";
import * as multisig from "@sqds/multisig";
import { CONFIG } from "../../core/config.js";

export class TimelockMonitor {
  private readonly connection: Connection;

  constructor(rpcEndpoint: string = CONFIG.RPC_ENDPOINT) {
    this.connection = new Connection(rpcEndpoint, "confirmed");
  }

  /**
   * Returns the remaining time in seconds for a proposal's timelock.
   * Returns 0 if timelock has expired or is not active.
   */
  async getRemainingTimelock(proposalPda: PublicKey): Promise<number> {
    try {
      const proposal = await multisig.accounts.Proposal.fromAccountAddress(
        this.connection,
        proposalPda
      );

      // Status 1 is Active in Squads v4
      if (proposal.status.__kind !== "Active") {
        return 0;
      }

      const now = Math.floor(Date.now() / 1000);
      const creationTime = Number(proposal.createdAt);
      
      const multisigAccount = await multisig.accounts.Multisig.fromAccountAddress(
        this.connection,
        proposal.multisig
      );
      
      const timeLock = Number(multisigAccount.timeLock);
      const readyTime = creationTime + timeLock;
      
      return Math.max(0, readyTime - now);
    } catch (error) {
      console.error("Failed to fetch timelock status:", error);
      return 0;
    }
  }

  /**
   * Checks if a proposal is ready for execution.
   */
  async isReadyForExecution(proposalPda: PublicKey): Promise<boolean> {
    const remaining = await this.getRemainingTimelock(proposalPda);
    return remaining === 0;
  }
}
