# SeedShield Exchange Demo

This example demonstrates a reference implementation of a crypto exchange that uses SeedShield for hardware-attested authentication and recovery.

## Key Features

- **Hardware-Only Registration**: Only allows registration from genuine Solana Seeker devices (AAGUID verification).
- **Squads v4 Multisig**: Automatically deploys a siloed multisig for every user on registration.
- **Institutional Recovery**: Demonstrates the co-signing flow for account recovery using the `InstitutionalGuardianProxy`.
- **Safe-Fail Design**: Returns machine-readable error codes (e.g., `UNTRUSTED_AAGUID`) for all security rejections.

## Setup

1. Ensure you have `bun` installed.
2. Run a local Solana validator: `solana-test-validator`
3. Install dependencies: `bun install`
4. Run the demo server: `task run` (or `bun run src/index.ts`)

## E2E Tests

The demo includes E2E tests using `MockTEE` to simulate hardware attestations:

```bash
task test
```

## "SIM-swap Kill" Logic

The server explicitly rejects any attestation that is not hardware-backed. In the demo dApp, SMS recovery is disabled with a message: "Protected by SeedShield Silicon Identity."
