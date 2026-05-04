# SeedShield

**Hardware-Attested Anti-SIM-Swap Login & Recovery for Crypto Apps**

*A drop-in SDK that lets exchanges, wallets, and dApps replace SMS 2FA with a Seed Vault-attested passkey, killing the single biggest crypto loss vector.*

<p align="center">
  <img src="https://img.shields.io/badge/platform-solana%20seeker-blueviolet" alt="Solana Seeker">
  <img src="https://img.shields.io/badge/security-FIDO2%20%7C%20WebAuthn-success" alt="FIDO2/WebAuthn">
  <img src="https://img.shields.io/badge/attestation-Hardware--backed-orange" alt="Hardware Attestation">
  <img src="https://img.shields.io/badge/recovery-Squads%20v4-blue" alt="Squads v4">
</p>

---

## Overview

**SeedShield** brings SIM-swap-proof authentication and account recovery to every crypto application running on the **Solana Seeker** smartphone. By replacing SMS-based 2FA with a **passkey** that is generated, stored, and attested inside the device’s **Seed Vault** (hardware-backed secure element), SeedShield eliminates the #1 attack vector responsible for billions in user losses.

The SDK is designed as a lightweight, drop-in library that integrates into any Solana dApp, custodial exchange app, or mobile wallet. It leverages **Squads v4 multisigs** to establish a sovereign identity for every user, ensuring that even if a device is lost, recovery is hardware-attested and immune to social engineering.

---

## Strategic Differentiators

- **Silicon Identity Anchor:** Proves a key was "born" in genuine, untampered hardware via factory-rooted attestation (SGT/TEEPIN).
- **Hardware-Bound Recovery:** Replaces traditional fallbacks with hardware-attested threshold approvals (M-of-N), inheriting silicon-level guarantees for account restoration.
- **The SIM-Swap Kill-Switch:** Enables the total removal of SMS/phone-number dependencies from operational risk models.

---

## The Problem

SMS-based 2FA and recovery codes are the weakest link in crypto account security:

- **SIM swaps** enable attackers to intercept SMS OTPs in minutes.
- **Phishing** tricks users into revealing codes or seed phrases.
- **Centralised recovery** often relies on easily compromised channels (email, support tickets).
- **Plain passkeys** without hardware attestation can be exfiltrated via malware or malicious backup.

---

## The Solution — SeedShield

SeedShield turns every Solana Seeker into a **FIDO2 authenticator** with **hardware attestation** tied to the device’s Seed Vault.

- **Private keys** never leave the secure hardware (TEE / Secure Element).  
- **Hardware Attestation** proves the key origin is a genuine Solana Seeker.
- **Biometric Enforcement** is handled entirely within the TEE boundary.
- **Sovereign Identity** is managed via siloed **Squads v4 multisigs** deployed on registration.

---

## How It Works (High Level)

1. **Registration (Create Passkey)**
   - App calls `SeedShield.register(userId)`.
   - Solana Seeker’s Seed Vault generates a **non-syncable** asymmetric key pair.  
   - Hardware attestation (SGT) is created, binding the public key to the device silicon.
   - The backend verifies the attestation and deploys a **siloed 1-of-2 Squads v4 multisig** (User Key + Institutional Guardian).

2. **Authentication (Login)**
   - App calls `SeedShield.authenticate(challenge)`.
   - User verifies identity via biometrics inside the TEE.
   - Hardware-attested signature is sent to the backend, which verifies it against the stored public key.

3. **Recovery (Institutional / Social Guardian)**
   - User initiates recovery on a new Solana Seeker.
   - Institutional Guardian co-signs the key rotation after out-of-band KYC.
   - A **mandatory 72-hour timelock** is enforced on-chain for all guardian-initiated rotations.
   - The entire flow avoids SMS codes, email links, or centralised escrow.

---

## Features

- 🔐 **Phishing-resistant passkeys** – FIDO2/WebAuthn standards bound to hardware.
- 🛡️ **Hardware attestation** – Verifiable proof of key origin via SGT/TEEPIN.
- 🚫 **SIM-swap immune** – Zero dependency on mobile network identity or SMS.
- ✋ **Biometric Isolation** – Fingerprint/Face required; matching stays in the TEE.
- 🔄 **Squads v4 Recovery** – On-chain sovereign recovery with hardware-attested co-signatures.
- 📦 **Dual SDK Stack** – Native Kotlin client for Seeker and Node.js library for verifiers.

---

## Project Status & Roadmap

### Phase 1: MVP – The Wedge (Current)
- [ ] `@seedshield/client`: Kotlin SDK for Solana Seeker.
- [ ] `@seedshield/server`: Node.js library for attestation verification.
- [ ] Squads Recovery Module: Siloed 1-of-2 multisig deployment.

### Phase 2: Growth – The Anti-SIM-Swap Stack
- [ ] Social Guardian Protocol: M-of-N social mesh via Squads.
- [ ] Platform Plugins: One-click wrappers for Privy, Dynamic, and Magic.

### Phase 3: Vision – The Identity Passport
- [ ] SeedShield ID: Open protocol for enterprise hardware-bound identity.

---

## Repository Structure

```
SeedShield/
├── seedshield-sdk-kotlin/   # Kotlin SDK for Solana Seeker (Android)
│   ├── sdk-core/           # Headless SDK Logic (Pure Kotlin)
│   ├── sdk-compose/        # Jetpack Compose UI Wrappers
│   └── demo-app/           # Exchange Clone PoC
└── seedshield-server/       # Node.js Verifier & Recovery Manager
    └── src/features/
        ├── attestation/     # SGT/TEEPIN Verification
        ├── multisig/        # Squads v4 Integration
        └── subsidizer/      # Sybil-Resistant Fee Payer
```

---

## Installation

### Mobile (Kotlin)
Add to your `build.gradle.kts`:
```kotlin
implementation("com.seedshield:sdk-core:1.0.0")
```

### Server (Node.js)
```bash
npm install @seedshield/server
# or
bun add @seedshield/server
```

---

## Quick Start

### Client (Kotlin)
```kotlin
val shield = SeedShield.initialize(context)
val result = shield.register(rpId = "exchange.com", userId = "user_123")
if (result.isHardwareAttested) {
    sendToServer(result.attestationObject)
}
```

### Server (Node.js / TypeScript)
```typescript
import { verifyAttestation } from '@seedshield/server';

const outcome = await verifyAttestation(req.body.attestation, "https://exchange.com");

if (outcome.status === 'VALID_HARDWARE') {
    await db.users.update(req.user.id, { 
        credentialId: outcome.credentialId,
        multisigAddress: outcome.multisigAddress 
    });
}
```

---
