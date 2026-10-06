/**
 * The group's recovery entry (`adr/0035-recovery-phrase-is-a-group-recovery-key`).
 *
 * A group MAY have a second keypair, K0, whose private half is what the 24-word
 * phrase encodes. Every K1 generation is sealed to K0's public half once:
 *
 *     entry = seal(k1_priv, k0_pub, aad=AAD(group_id, "recovery", k1_pub))
 *
 * Sealing needs only K0's public half, so a rotation writes a fresh entry
 * without anybody producing the phrase. The entry is not a bucket entry: it
 * is not an API key, does not count towards the bucket's minimum, and is never
 * published to the edge.
 */

import { timingSafeEqual } from "./encoding.js";
import { derivePublicKey, open, recoveryAssociatedData, seal } from "./envelope.js";
import {
  asPrivateKey,
  type PrivateKey,
  type PublicKey,
  type SealedEnvelope,
  VaultDecryptionError,
  X25519_PRIVATE_KEY_BYTES,
} from "./types.js";

/**
 * Seal K1's private half to K0's public half.
 *
 * @param k1PrivateKey the generation's private half.
 * @param recoveryPublicKey K0's public half.
 * @param groupId the group the entry belongs to.
 */
export async function sealRecovery(
  k1PrivateKey: PrivateKey,
  recoveryPublicKey: PublicKey,
  groupId: string,
): Promise<SealedEnvelope> {
  const k1PublicKey = await derivePublicKey(k1PrivateKey);
  return seal(k1PrivateKey, recoveryPublicKey, recoveryAssociatedData(groupId, k1PublicKey));
}

/**
 * Open a recovery entry with K0's private half, yielding K1's private half.
 *
 * @param entry the stored recovery entry.
 * @param recoveryPrivateKey K0's private half, decoded from the phrase.
 * @param groupId the group the entry belongs to.
 * @param k1PublicKey the group's current public half, which the entry is bound to.
 * @throws {VaultDecryptionError} for the wrong K0, another group's entry, an
 *   entry from another generation, or corruption — indistinguishably, as for
 *   every other `open`.
 */
export async function openRecovery(
  entry: SealedEnvelope | string | Uint8Array,
  recoveryPrivateKey: PrivateKey,
  groupId: string,
  k1PublicKey: PublicKey,
): Promise<PrivateKey> {
  const opened = await open(
    entry,
    recoveryPrivateKey,
    recoveryAssociatedData(groupId, k1PublicKey),
  );
  // The AAD already binds k1PublicKey; these catch a writer that sealed
  // something other than this generation's private half under the right binding.
  if (opened.length !== X25519_PRIVATE_KEY_BYTES) {
    throw new VaultDecryptionError();
  }
  const k1PrivateKey = asPrivateKey(opened);
  if (!timingSafeEqual(await derivePublicKey(k1PrivateKey), k1PublicKey)) {
    throw new VaultDecryptionError();
  }
  return k1PrivateKey;
}
