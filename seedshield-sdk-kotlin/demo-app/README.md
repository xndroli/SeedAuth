# SeedShield Exchange Demo dApp

This demo dApp showcases the "Silicon-First" exchange UI, replacing vulnerable SMS fallbacks with hardware-rooted security.

## Features

- **Hardware Registration**: Triggers the SeedShield SDK registration flow.
- **Mock TEE Support**: Runs in `testMode` to allow testing without physical Seeker hardware.
- **Identity Multisig Display**: Shows the on-chain Squads v4 multisig address upon successful registration.
- **SMS Kill UI**: Explicitly disables SMS recovery options to demonstrate SIM-swap resistance.

## Integration Details

- **SDK Core**: Uses `com.seedshield.sdk:core` for attestation generation.
- **Demo Server**: Connects to the Node.js `exchange-demo` server (default: `http://10.0.2.2:3000` for Android Emulator).
- **Architecture**: Follows the "Async Result" pattern for all security operations.

## Running the Demo

1. Ensure the `seedshield-server/examples/exchange-demo` is running.
2. Build and run the `demo-app` on an Android Emulator.
3. Use the "Register" flow to see the full hardware-attested multisig deployment.
