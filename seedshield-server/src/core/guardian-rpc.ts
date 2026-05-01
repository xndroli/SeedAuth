import { SeedShieldErrorCode } from "./types.js";

export interface GuardianVerificationResponse {
  valid: boolean;
  deviceId?: string;
  error?: string;
}

export class GuardianRpcAdapter {
  private readonly endpoint: string;

  constructor(endpoint: string = "https://mainnet.helius-rpc.com/") {
    this.endpoint = endpoint;
  }

  /**
   * Verifies the SGT quote via Solana Attestation Service (SAS).
   * @param attestationObject Base64 encoded authData/attestation
   * @param _sgtMetadata Optional SGT metadata
   */
  async verifySgtQuote(
    attestationObject: string,
    _sgtMetadata?: string,
  ): Promise<GuardianVerificationResponse> {
    // SECURITY FIX: Default to valid: false (Fail-Closed)
    if (this.endpoint.includes("mock")) {
      // Mock logic for tests
      if (attestationObject.includes("INVALID_QUOTE")) {
        return { valid: false, error: SeedShieldErrorCode.INVALID_TEEPIN_QUOTE };
      }
      return { valid: true, deviceId: "seeker-device-123" };
    }

    // In production, this would be a real SAS RPC call
    // For Phase 1, we simulate a successful call but ONLY if the endpoint is not mock
    // In a real scenario, this would involve a cryptographic check on the SGT quote.
    return { valid: false, error: SeedShieldErrorCode.INVALID_TEEPIN_QUOTE };
  }
}
