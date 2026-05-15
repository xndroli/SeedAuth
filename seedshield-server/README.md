# SeedAuth Server

Hardware-attested anti-SIM-swap verifier for Solana Seeker.

## Overview
SeedAuth shifts the root of trust from vulnerable telecom networks to device silicon. This library verifies FIDO2/WebAuthn attestations generated within the Solana Seeker Seed Vault.

## Installation
```bash
bun add @seedauth/server
```

## Usage
```typescript
import { AttestationVerifier } from '@seedauth/server';

const result = await AttestationVerifier.verify(attestation, origin);
```
