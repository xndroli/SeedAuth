import { Connection, PublicKey } from "@solana/web3.js";
import { CONFIG } from "../../core/config.js";
import { SeedShieldErrorCode } from "../../core/types.js";

/**
 * Unique on-chain audit artifact types.
 */
export enum AuditEventType {
  REGISTRATION = "REGISTRATION",
  ROTATION = "ROTATION",
  UNKNOWN = "UNKNOWN",
}

/**
 * Shape of a single audit trail event as per AC-3.2.3.
 */
export interface AuditTrailEvent {
  txSignature: string;
  eventType: AuditEventType;
  timestamp: number;
  details: any;
}

/**
 * Async Result pattern for audit trail responses.
 */
export interface AuditTrailResult {
  success: boolean;
  errorCode?: SeedShieldErrorCode;
  message?: string;
  data?: AuditTrailEvent[];
}

export class AuditManager {
  private readonly connection: Connection;

  constructor(rpcEndpoint: string = CONFIG.RPC_ENDPOINT) {
    this.connection = new Connection(rpcEndpoint, "confirmed");
  }

  /**
   * Fetches the audit trail for a given multisig address directly from the blockchain.
   * Implementation follows AC-3.2.2 and AC-3.2.4.
   */
  async getAuditTrail(multisigAddress: string): Promise<AuditTrailResult> {
    try {
      // 1. Validation: Ensure valid Solana Public Key
      let pubkey: PublicKey;
      try {
        pubkey = new PublicKey(multisigAddress);
      } catch (e) {
        return {
          success: false,
          errorCode: SeedShieldErrorCode.INTERNAL_ERROR,
          message: "Invalid multisig address format",
        };
      }
      
      // AC-3.2.1 & AC-3.2.4: Fetch signatures with pagination (limit 100 for safety)
      const signatures = await this.connection.getSignaturesForAddress(pubkey, { limit: 100 });

      // Parallel fetching for performance (Fixes Sequential Fetch Performance)
      const eventPromises = signatures.map(async (sigInfo) => {
        const tx = await this.connection.getParsedTransaction(sigInfo.signature, {
          maxSupportedTransactionVersion: 0,
        });

        // Handle pruned or missing transactions
        if (!tx) {
          return {
            txSignature: sigInfo.signature,
            eventType: AuditEventType.UNKNOWN,
            timestamp: 0,
            details: { error: "Transaction data not available (possibly pruned)" },
          };
        }

        const eventType = this.parseEventType(tx);
        
        return {
          txSignature: sigInfo.signature,
          eventType,
          timestamp: tx.blockTime || 0,
          details: {
            slot: tx.slot,
            memo: sigInfo.memo,
            blockTime: tx.blockTime,
          },
        };
      });

      const events = await Promise.all(eventPromises);

      return {
        success: true,
        data: events,
      };
    } catch (error) {
      // Sealed-Error pattern: sanitize and return internal error
      console.error("Audit trail fetch failed:", error);
      return {
        success: false,
        errorCode: SeedShieldErrorCode.INTERNAL_ERROR,
        message: "Failed to fetch on-chain audit trail",
      };
    }
  }

  /**
   * Identifies the type of multisig event from transaction data.
   * Compatible with Squads v4 transaction structures.
   */
  private parseEventType(tx: any): AuditEventType {
    const logs = tx.meta?.logMessages || [];
    const logString = logs.join("\n");

    // Detect Registration (Story 3.1)
    if (logString.includes("Instruction: MultisigCreateV2")) {
      return AuditEventType.REGISTRATION;
    }
    
    // Detect Rotation (Epic 4 / Future)
    // Squads v4 uses ConfigProposal instructions for threshold/member changes
    if (
      logString.includes("Instruction: ConfigProposalCreate") ||
      logString.includes("Instruction: ConfigProposalExecute")
    ) {
      return AuditEventType.ROTATION;
    }

    return AuditEventType.UNKNOWN;
  }
}
