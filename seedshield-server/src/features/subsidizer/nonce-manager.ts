import { 
  Connection, 
  Keypair,
  PublicKey, 
  Transaction, 
  SystemProgram,
  NonceAccount,
  NONCE_ACCOUNT_LENGTH
} from "@solana/web3.js";
import { CONFIG } from "../../core/config.js";

/**
 * NonceManager handles the provisioning and validation of Durable Nonce Accounts
 * to ensure recovery transactions don't expire during out-of-band windows.
 * 
 * TODO: For production, migrate memory-based `activeNonces` to a database table
 * to support horizontal scaling and ensure nonces are not lost on server restart.
 */
export class NonceManager {
  private readonly connection: Connection;
  
  // In a real implementation, this would be a database table
  private readonly activeNonces = new Set<string>();

  constructor(rpcEndpoint: string = CONFIG.RPC_ENDPOINT) {
    this.connection = new Connection(rpcEndpoint, "confirmed");
  }

  /**
   * Validates if a transaction is correctly using a durable nonce from the managed pool.
   * 
   * @param transaction The decoded Solana transaction.
   * @returns boolean true if valid nonce usage or no nonce used (if allowed).
   */
  public async validateNonceUsage(transaction: Transaction): Promise<boolean> {
    const nonceInstruction = transaction.instructions[0];
    
    // Check if it's a SystemProgram.nonceAdvance instruction
    if (
      nonceInstruction &&
      nonceInstruction.programId.equals(SystemProgram.programId) &&
      this.isNonceAdvance(nonceInstruction.data)
    ) {
      const noncePubkey = nonceInstruction.keys[0].pubkey;
      
      // Verify the nonce account is one we manage
      if (!this.activeNonces.has(noncePubkey.toBase58())) {
         // For Phase 1, we might just trust it if it's a valid nonce account
         // but AC-4.2.3 implies "provision and maintain a pool".
         return false;
      }

      // Verify the nonce is still valid on-chain
      try {
        const accountInfo = await this.connection.getAccountInfo(noncePubkey);
        if (!accountInfo) return false;
        
        const nonceAccount = NonceAccount.fromAccountData(accountInfo.data);
        
        // SECURITY FIX: Verify the transaction's blockhash matches the account's nonce value
        if (nonceAccount.nonce !== transaction.recentBlockhash) {
           return false;
        }

        return true;
      } catch (e) {
        return false;
      }
    }

    // If no nonce is used, we allow it for standard transactions (unless policy says otherwise)
    return true; 
  }

  /**
   * Registers a nonce account into the managed pool.
   */
  public registerNonceAccount(pubkey: PublicKey): void {
    this.activeNonces.add(pubkey.toBase58());
  }

  /**
   * Provisions a new rent-exempt Durable Nonce account.
   * 
   * @param feePayer The keypair paying for the account creation.
   * @returns The public key of the new nonce account.
   */
  public async provisionNonceAccount(feePayer: Keypair): Promise<PublicKey> {
    const nonceAccount = Keypair.generate();
    const rentExemptBalance = await this.connection.getMinimumBalanceForRentExemption(
      NONCE_ACCOUNT_LENGTH
    );

    const transaction = new Transaction().add(
      SystemProgram.createNonceAccount({
        fromPubkey: feePayer.publicKey,
        noncePubkey: nonceAccount.publicKey,
        authorizedPubkey: feePayer.publicKey,
        lamports: rentExemptBalance,
      })
    );

    await this.connection.sendTransaction(transaction, [feePayer, nonceAccount]);
    
    this.registerNonceAccount(nonceAccount.publicKey);
    return nonceAccount.publicKey;
  }

  /**
   * Heuristic to check if instruction data corresponds to nonceAdvance.
   * SECURITY: This is a fragile check. In production, use a formal 
   * instruction decoder for the System Program.
   */
  private isNonceAdvance(data: Buffer): boolean {
    if (data.length < 4) return false;
    
    // SystemProgram nonceAdvance is index 4 in the instruction enum
    // Reference: https://github.com/solana-labs/solana-web3.js/blob/master/src/system-program.ts
    const instructionIndex = data.readUInt32LE(0);
    return instructionIndex === 4;
  }
}
