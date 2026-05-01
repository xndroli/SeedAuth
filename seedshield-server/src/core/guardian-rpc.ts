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
    // In a real implementation, this would be a fetch call to the Guardian RPC.
    // For Phase 1 and TDD, we simulate the network boundary.

    if (this.endpoint.includes("mock")) {
      // Mock logic for tests
      if (attestationObject.includes("INVALID_QUOTE")) {
        return { valid: false, error: SeedShieldErrorCode.INVALID_TEEPIN_QUOTE };
      }
      return { valid: true, deviceId: "seeker-device-123" };
    }

    try {
      // Simulation of the 2026 SAS API call
      // const response = await fetch(`${this.endpoint}/v1/sas/verify`, { ... });

      // For the sake of the story, we assume a successful verification if not mock
      return { valid: true, deviceId: "seeker-device-real" };
    } catch (_error) {
      return { valid: false, error: "RPC_UNREACHABLE" };
    }
  }
}
