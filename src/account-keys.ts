import {
  generateKeyPair,
  wrapPrivateKey,
  unwrapPrivateKey,
  generateGroupKey,
  grantGroupKey,
  openGroupKeyGrant,
  generateRecoveryCode,
  wrapGroupKeyForRecovery,
  openGroupKeyWithRecovery,
  type WrappedSecret,
} from "./e2ee";

/**
 * Account identity keypair helpers (the "account keychain"; #214/#49). The
 * account gets its own X25519 keypair so others can seal secrets *to the account*
 * directed-invite preapproval seals the Group Key to `publicKey`, and the
 * account profile key is sealed here too. The private key is wrapped under the
 * account password (the same secret that already wraps every membership key), so
 * one password unlocks it on any device. Runs in the browser; the server only
 * ever stores the public key and the opaque wrapped blob.
 */
export interface AccountKeyEnrollment {
  publicKey: string;
  wrappedPrivateKey: WrappedSecret;
}

/** Generate a fresh account keypair and wrap the private key under `password`. */
export async function enrollAccountKeypair(password: string): Promise<AccountKeyEnrollment> {
  const kp = await generateKeyPair();
  const wrappedPrivateKey = await wrapPrivateKey(kp.privateKey, password);
  return { publicKey: kp.publicKey, wrappedPrivateKey };
}

/** Wrap/open the account private key under a one-time recovery code (the account
 * recovery kit, #202). Reuses the generic recovery-wrap primitive. */
export async function wrapAccountKeyForRecovery(
  privateKey: string,
  recoveryCode: string,
): Promise<WrappedSecret> {
  return wrapGroupKeyForRecovery(privateKey, recoveryCode);
}
export async function openAccountKeyWithRecovery(
  wrapped: WrappedSecret,
  recoveryCode: string,
): Promise<string> {
  return openGroupKeyWithRecovery(wrapped, recoveryCode);
}

/** Everything the browser mints for a new account at sign-up. */
export interface AccountSignupEnrollment {
  publicKey: string;
  wrappedPrivateKey: WrappedSecret;
  wrappedProfileKey: string;
  /** Shown to the user once, never sent to the server. */
  recoveryCode: string;
  recoveryWrappedPrivateKey: WrappedSecret;
}

/**
 * Full account enrollment for sign-up: the identity keypair (wrapped under the
 * password), the profile key (sealed to the public key), and a one-time recovery
 * code with the private key wrapped under it (#202). The caller posts every blob
 * but shows the `recoveryCode` to the user and discards it.
 */
export async function enrollAccountForSignup(password: string): Promise<AccountSignupEnrollment> {
  const kp = await generateKeyPair();
  const wrappedPrivateKey = await wrapPrivateKey(kp.privateKey, password);
  const wrappedProfileKey = await sealProfileKeyTo(kp.publicKey);
  const recoveryCode = await generateRecoveryCode();
  const recoveryWrappedPrivateKey = await wrapAccountKeyForRecovery(kp.privateKey, recoveryCode);
  return { publicKey: kp.publicKey, wrappedPrivateKey, wrappedProfileKey, recoveryCode, recoveryWrappedPrivateKey };
}

/**
 * Mint a fresh Account Profile Key (APK) and seal it to the account's public key
 * (#49). The APK is a symmetric key that encrypts account-level onboarding profile
 * fields (contact, children); sealing it to the account public key means the
 * account private key opens it, so there is nothing extra to re-wrap on a password change.
 * Returns the sealed blob to persist as `Account.wrappedProfileKey`. Used at
 * sign-up, where `accountKeyMaterial` isn't in the keystore yet.
 */
export async function sealProfileKeyTo(accountPublicKey: string): Promise<string> {
  const profileKey = await generateGroupKey();
  return grantGroupKey(profileKey, accountPublicKey);
}

/**
 * Backfill enrollment for an account created before the keychain shipped: mint the
 * identity keypair (wrapped under the password) + a profile key (sealed to it).
 * No recovery wrap; the person sets that up from My Account -> Recovery code.
 */
export interface AccountKeychainBackfill {
  publicKey: string;
  wrappedPrivateKey: WrappedSecret;
  wrappedProfileKey: string;
}
export async function enrollAccountKeychainBackfill(
  password: string,
): Promise<AccountKeychainBackfill> {
  const kp = await generateKeyPair();
  const wrappedPrivateKey = await wrapPrivateKey(kp.privateKey, password);
  const wrappedProfileKey = await sealProfileKeyTo(kp.publicKey);
  return { publicKey: kp.publicKey, wrappedPrivateKey, wrappedProfileKey };
}

/** Recover the account private key from its wrapped blob. Throws if the password is wrong. */
export async function openAccountPrivateKey(
  wrapped: WrappedSecret,
  password: string,
): Promise<string> {
  return unwrapPrivateKey(wrapped, password);
}

/** Re-wrap an already-unwrapped account private key under a new password (password change). */
export async function rewrapAccountPrivateKey(
  privateKey: string,
  newPassword: string,
): Promise<WrappedSecret> {
  return wrapPrivateKey(privateKey, newPassword);
}

// --- Forgotten-password recovery restore (#202, Increment 2) -----------------
// A membership's private key is normally wrapped only under the account password,
// so forgetting it loses the key. But every membership key is ALSO sealed to the
// account public key (Member.accountSealedPrivateKey). Holding the account private
// key (recovered from the one-time code) lets us reopen each membership key and
// re-wrap it under a NEW password, keeping Group Key grants and standing intact.
// This is the no-re-approval restore path; it mirrors the password-change re-wrap,
// the difference being the secret comes from the recovery code, not the old password.

/** One membership to restore: its id and its key sealed to the account public key. */
export interface SealedMembership {
  memberId: string;
  accountSealedPrivateKey: string;
}
/** A restored membership key, re-wrapped under the new password. */
export interface RestoredMembership {
  memberId: string;
  wrappedPrivateKey: WrappedSecret;
}

/**
 * Recover the account private key from the one-time recovery code, then re-wrap
 * every supplied membership key under the new password. Returns the account key
 * re-wrapped under the new password plus the per-membership re-wraps. The caller
 * posts these for the server to persist. Throws if the recovery code is wrong.
 */
export async function restoreKeychainWithRecoveryCode(args: {
  accountPublicKey: string;
  recoveryWrappedPrivateKey: WrappedSecret;
  recoveryCode: string;
  memberships: SealedMembership[];
  newPassword: string;
}): Promise<{ accountWrappedPrivateKey: WrappedSecret; restored: RestoredMembership[] }> {
  // Unlock the account private key with the recovery code (throws on a bad code).
  const accountPrivateKey = await openAccountKeyWithRecovery(
    args.recoveryWrappedPrivateKey,
    args.recoveryCode,
  );
  const accountKeyPair = { publicKey: args.accountPublicKey, privateKey: accountPrivateKey };
  // The keypair is unchanged; only re-wrap it under the new password.
  const accountWrappedPrivateKey = await wrapPrivateKey(accountPrivateKey, args.newPassword);
  const restored: RestoredMembership[] = [];
  for (const m of args.memberships) {
    const membershipPrivateKey = await openGroupKeyGrant(m.accountSealedPrivateKey, accountKeyPair);
    const wrappedPrivateKey = await wrapPrivateKey(membershipPrivateKey, args.newPassword);
    restored.push({ memberId: m.memberId, wrappedPrivateKey });
  }
  return { accountWrappedPrivateKey, restored };
}

/** A membership re-enrolled with a brand-new key pair (the data-loss path). */
export interface ReenrolledMembership {
  memberId: string;
  publicKey: string;
  wrappedPrivateKey: WrappedSecret;
  accountSealedPrivateKey: string;
}

/**
 * Mint fresh membership key pairs under a new account keychain, for the
 * no-recovery-code reset (the private keys are unrecoverable, so the memberships
 * return to PENDING for re-approval). Each fresh key is wrapped under the new
 * password and sealed to the new account public key so future recovery works.
 */
export async function reenrollMembershipsForReset(args: {
  memberIds: string[];
  newAccountPublicKey: string;
  newPassword: string;
}): Promise<ReenrolledMembership[]> {
  const out: ReenrolledMembership[] = [];
  for (const memberId of args.memberIds) {
    const kp = await generateKeyPair();
    const wrappedPrivateKey = await wrapPrivateKey(kp.privateKey, args.newPassword);
    const accountSealedPrivateKey = await grantGroupKey(kp.privateKey, args.newAccountPublicKey);
    out.push({ memberId, publicKey: kp.publicKey, wrappedPrivateKey, accountSealedPrivateKey });
  }
  return out;
}
