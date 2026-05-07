import express from "express";
import {
  AttestationVerifier,
  MockTEE,
  SeedShieldErrorCode,
  MultisigManager,
  AuditManager,
  InstitutionalGuardianProxy,
  FeePayerSubsidizer,
  MigrationHandler,
  type UserDb,
  type AttestationObject,
  AuditEventType,
} from "@seedshield/server";
import { Connection, PublicKey, Keypair } from "@solana/web3.js";
import { randomBytes, createHash } from "node:crypto";
import { decode } from "cbor-x";
import bs58 from "bs58";

const app = express();
app.use(express.json());

// Reference Architecture: Localnet + MockTEE for POC (AC-5.1.5)
const connection = new Connection("http://localhost:8899", "confirmed");
const verifier = new AttestationVerifier();
const multisigManager = new MultisigManager("http://localhost:8899");
const auditManager = new AuditManager("http://localhost:8899");

// For Demo purposes, use a fixed fee payer and guardian key (Mocked)
const demoFeePayer = Keypair.generate();
const demoGuardian = Keypair.generate();

const guardianProxy = new InstitutionalGuardianProxy(
  connection,
  multisigManager,
  verifier,
  undefined, // Default throttle
  auditManager
);

// In-memory database for demo purposes
const MAX_USERS = 1000;
const MAX_CHALLENGES = 5000;

interface UserRecord {
  userId: string;
  hardwarePublicKey: string;
  multisigPda: string;
  smsEnabled: boolean;
}

const users = new Map<string, UserRecord>();
const challenges = new Map<string, string>();

/**
 * AC-5.1.1: Demo Registration Endpoint
 */
app.post("/register", async (req, res) => {
  const { attestation, userId } = req.body as { attestation: AttestationObject, userId: string };
  const clientVersion = req.header("X-SeedShield-Version");

  try {
    // 1. Input Validation (Finding 3)
    if (!userId || !attestation) {
        return res.status(400).json({ errorCode: SeedShieldErrorCode.INVALID_INPUT, message: "Missing required fields" });
    }

    const storedChallenge = challenges.get(userId);
    if (!storedChallenge) {
      return res.status(400).json({
        errorCode: SeedShieldErrorCode.CHALLENGE_MISMATCH,
        message: "No active registration challenge for this user.",
        attestationStatus: "INVALID"
      });
    }

    // 2. Hardware-Only Verification (FR7, AC-5.1.3, AC-5.3.4)
    const outcome = await verifier.verify(attestation, "https://exchange.com", storedChallenge, clientVersion);

    if (outcome.attestationStatus !== "VALID_HARDWARE") {
      const eventType = outcome.errorCode === SeedShieldErrorCode.VERSION_DEPRECATED 
        ? AuditEventType.VERSION_REJECTION 
        : AuditEventType.GUARDIAN_REJECTION;

      auditManager.logRejection({
        code: outcome.errorCode || SeedShieldErrorCode.SOFTWARE_ATTESTATION_REJECTED,
        message: outcome.message || "Non-Genuine Device Detected",
        timestamp: outcome.timestamp,
        deviceId: outcome.unverifiedDeviceId,
        attestationStatus: outcome.attestationStatus
      }, eventType);

      return res.status(403).json(outcome);
    }

    // Extract User Public Key from Attestation Object
    let userPubkey: PublicKey;
    try {
      const authData = decode(Buffer.from(attestation.attestationObject, "base64"));
      if (!authData.credentialPublicKey) {
         throw new Error("Missing credentialPublicKey in attestation");
      }
      userPubkey = new PublicKey(Buffer.from(authData.credentialPublicKey));
    } catch (e) {
      return res.status(400).json({ errorCode: SeedShieldErrorCode.INTERNAL_ERROR, message: "Invalid hardware key in attestation" });
    }

    const hardwarePublicKey = userPubkey.toBase58();

    const multisigPda = await multisigManager.ensureMultisig(
      userPubkey,
      demoFeePayer,
      demoGuardian.publicKey
    );

    if (users.size < MAX_USERS || users.has(userId)) {
      users.set(userId, {
        userId,
        hardwarePublicKey,
        multisigPda: multisigPda.toBase58(),
        smsEnabled: true // Default for registered users in demo
      });
    }

    challenges.delete(userId);

    res.json({
      success: true,
      multisigPda: multisigPda.toBase58(),
      message: "Protected by SeedShield Silicon Identity."
    });

  } catch (error) {
    console.error("Registration Error:", error);
    res.status(500).json({
      errorCode: SeedShieldErrorCode.INTERNAL_ERROR,
      message: "Internal Server Error",
      attestationStatus: "INVALID"
    });
  }
});

/**
 * AC-5.1.1: Demo Authentication Endpoint (Refactored from /login)
 * Distinct flow for assertion verification (AC-Decision).
 */
app.post("/authenticate", async (req, res) => {
  const { attestation, userId } = req.body as { attestation: AttestationObject, userId: string };
  const clientVersion = req.header("X-SeedShield-Version");

  try {
    // 1. Input Validation
    if (!userId || !attestation) {
        return res.status(400).json({ errorCode: SeedShieldErrorCode.INVALID_INPUT });
    }

    const storedChallenge = challenges.get(userId);
    if (!storedChallenge) {
       return res.status(400).json({ errorCode: SeedShieldErrorCode.CHALLENGE_MISMATCH });
    }

    // 2. Hardware Verification (using verifyAssertion logic via verifier.verify with clientData.type='webauthn.get')
    const outcome = await verifier.verify(attestation, "https://exchange.com", storedChallenge, clientVersion);

    if (outcome.attestationStatus !== "VALID_HARDWARE") {
       const eventType = outcome.errorCode === SeedShieldErrorCode.VERSION_DEPRECATED 
         ? AuditEventType.VERSION_REJECTION 
         : AuditEventType.GUARDIAN_REJECTION;

       auditManager.logRejection({
         code: outcome.errorCode || SeedShieldErrorCode.USER_VERIFICATION_FAILED,
         message: "Login hardware verification failed",
         timestamp: outcome.timestamp,
         deviceId: outcome.unverifiedDeviceId,
         attestationStatus: outcome.attestationStatus
       }, eventType);
       return res.status(403).json(outcome);
    }

    const user = users.get(userId);
    // 3. Identity Binding Check (Finding 1)
    if (!user || user.hardwarePublicKey !== outcome.deviceId) {
       return res.status(401).json({ message: "Identity mismatch or user not registered." });
    }

    challenges.delete(userId);
    res.json({ success: true, user });

  } catch (error) {
    res.status(500).json({ errorCode: SeedShieldErrorCode.INTERNAL_ERROR });
  }
});

/**
 * AC-5.1.4: Recovery Proof of Concept
 */
app.post("/recovery/initiate", async (req, res) => {
  const { userId, attestation, transaction } = req.body;
  const clientVersion = req.header("X-SeedShield-Version");

  try {
    const user = users.get(userId);
    if (!user) throw new Error("User not found");

    const challenge = challenges.get(userId);
    if (!challenge) throw new Error("Challenge mismatch");

    const signature = await guardianProxy.approveRotation(
      new PublicKey(user.multisigPda),
      attestation,
      transaction,
      demoGuardian,
      challenge,
      clientVersion
    );

    challenges.delete(userId);

    res.json({ success: true, signature, message: "72h Security Timelock Activated." });
  } catch (error: any) {
    // Mapped error handling for recovery
    res.status(403).json({ errorCode: error.message || error.code });
  }
});

/**
 * Helper to generate challenges for demo
 */
app.get("/challenge/:userId", (req, res) => {
  if (challenges.size >= MAX_CHALLENGES) {
    challenges.clear();
  }

  const challenge = randomBytes(32).toString("base64");
  challenges.set(req.params.userId, challenge);
  res.json({ challenge });
});

// Implement UserDb interface for the demo
const userDb: UserDb = {
  async getUserByLegacyToken(token: string) {
    // In demo, the token is just the userId (e.g., from a mock legacy session)
    const user = users.get(token);
    return user ? { userId: user.userId, smsEnabled: user.smsEnabled } : null;
  },
  async updateUserMigration(userId, hardwarePublicKey, multisigPda) {
    const user = users.get(userId);
    if (user) {
      user.hardwarePublicKey = hardwarePublicKey;
      user.multisigPda = multisigPda;
      user.smsEnabled = false;
    } else {
      // Create user if they only had a legacy account (represented by token in demo)
      users.set(userId, {
        userId,
        hardwarePublicKey,
        multisigPda,
        smsEnabled: false
      });
    }
  },
  async isHardwareLinked(hardwarePublicKey) {
    for (const user of users.values()) {
      if (user.hardwarePublicKey === hardwarePublicKey) return true;
    }
    return false;
  }
};

const migrationHandler = new MigrationHandler(verifier, multisigManager, userDb);

/**
 * AC-5.2.1: Enrollment Flow Endpoint
 */
app.post("/migrate/enroll", async (req, res) => {
  const { legacyToken, attestation, userId } = req.body;
  const challenge = challenges.get(userId);
  
  if (!challenge) {
    return res.status(400).json({ errorCode: SeedShieldErrorCode.CHALLENGE_MISMATCH });
  }

  const result = await migrationHandler.enroll(
    legacyToken, 
    attestation, 
    "https://exchange.com", 
    challenge, 
    demoFeePayer
  );

  if (!result.success) {
    // AC-5.2.6: Forensic Logging
    auditManager.logRejection({
      code: result.errorCode || SeedShieldErrorCode.INTERNAL_ERROR,
      message: result.message || "Migration Failed",
      timestamp: result.timestamp,
      deviceId: result.unverifiedDeviceId,
      attestationStatus: result.attestationStatus
    });
    return res.status(403).json(result);
  }

  res.json({ 
    success: true, 
    multisigAddress: result.multisigAddress,
    message: "Migration Complete. Legacy SMS factors have been retired."
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`SeedShield Exchange Demo Server running on http://localhost:${PORT}`);
});
