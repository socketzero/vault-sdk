/**
 * Key groups and the key bucket
 * (`product/control-plane/component/store/component/tenant/datamodel/key-group`).
 *
 * A group is one X25519 keypair plus one bucket entry per API key, each holding
 * K1's private half wrapped under that key:
 *
 *     key_id   = HKDF-SHA256(api_key, salt=tenant_id, info="socket0/v1/key-id",   16)
 *     wrap_key = HKDF-SHA256(api_key, salt=tenant_id, info="socket0/v1/tmk-wrap", 32)
 *     entry    = AES-256-GCM(wrap_key, nonce, group_priv, aad=group_id || key_id)
 *
 * An API key opens its group and nothing else.
 */

import { deriveKeyIdHex, deriveWrapKey } from "./api-key.js";
import { timingSafeEqual, utf8Encode } from "./encoding.js";
import { bucketAssociatedData, generateX25519KeyPair } from "./envelope.js";
import {
  type BucketEntry,
  type GroupKeyPair,
  type KeyGroup,
  VaultDecryptionError,
} from "./types.js";

/** K1's private half: the AES-GCM plaintext of every bucket entry. */
const PRIVATE_KEY_BYTES = 32;
/** The AES-GCM nonce that prefixes a wrapped entry. */
const WRAP_NONCE_BYTES = 12;
/** The AES-GCM tag that terminates a wrapped entry. */
const WRAP_TAG_BYTES = 16;

/** `nonce(12) || ciphertext(32) || tag(16)`. The private half is always 32 bytes. */
export const WRAPPED_PRIVATE_KEY_BYTES = WRAP_NONCE_BYTES + PRIVATE_KEY_BYTES + WRAP_TAG_BYTES;

/**
 * A fresh X25519 keypair for a key group.
 *
 * The private half is returned once and never stored unwrapped — the caller's
 * only durable copies are the bucket entries `wrap` produces from it.
 */
export function generateGroup(): Promise<GroupKeyPair> {
  return generateX25519KeyPair();
}

/**
 * Derive the pair a bucket operation needs from one API key.
 *
 * Two info strings over one secret: `keyId` is stored in the clear in every
 * bundle that carries the group, so it must be independent of the key that
 * opens the group. The salt is the tenant id, never the group's public half —
 * that half rotates and `keyId` must survive the rotation, or bucket lookup
 * breaks halfway through the operation that rotates it.
 */
async function deriveBucketKeys(
  apiKey: Uint8Array,
  tenantId: string,
): Promise<{ keyId: string; wrapKey: Uint8Array }> {
  const [keyId, wrapKey] = await Promise.all([
    deriveKeyIdHex(apiKey, tenantId),
    deriveWrapKey(apiKey, tenantId),
  ]);
  return { keyId, wrapKey };
}

/**
 * Copy bytes into an `ArrayBuffer`-backed view.
 *
 * Web Crypto's `BufferSource` excludes `SharedArrayBuffer`, while the SDK's own
 * `Uint8Array` values are backed by `ArrayBufferLike`. A copy is how that gap is
 * closed without a cast — and at 12 to 60 bytes per call it is not worth a type
 * escape to avoid.
 */
function argument(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy;
}

/**
 * Import a derived wrap key for exactly one AES-GCM operation.
 *
 * Non-extractable, and granted only the usage it is about to perform: the wrap
 * key exists to move one bucket entry, and nothing downstream has a reason to
 * read it back out or to reuse it in the other direction.
 */
function importWrapKey(wrapKey: Uint8Array, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey("raw", argument(wrapKey), { name: "AES-GCM" }, false, [
    usage,
  ]);
}

/**
 * Wrap K1's private half under one API key, producing one bucket entry.
 *
 * @param privateKey K1's private half, 32 raw bytes.
 * @param apiKey the RAW 32 bytes of the API key, never the display string.
 * @param tenantId the HKDF salt. Stable across rotation, which is why `key_id`
 *   survives a rotation of the group's public half.
 * @param groupId bound into the entry as associated data with the key id.
 * @throws {RangeError} if `privateKey` is not exactly 32 bytes. Wrapping the
 *   wrong-sized thing is a programming error rather than a decryption failure,
 *   and it has to be loud: a malformed entry is otherwise silent until somebody
 *   tries to open the group, long after the plaintext could have been resealed.
 */
export async function wrap(
  privateKey: Uint8Array,
  apiKey: Uint8Array,
  tenantId: string,
  groupId: string,
): Promise<BucketEntry> {
  if (privateKey.length !== PRIVATE_KEY_BYTES) {
    throw new RangeError(
      `a group private half is ${PRIVATE_KEY_BYTES} bytes, got ${privateKey.length}`,
    );
  }

  const { keyId, wrapKey } = await deriveBucketKeys(apiKey, tenantId);
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(WRAP_NONCE_BYTES));
  const key = await importWrapKey(wrapKey, "encrypt");
  const sealed = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: argument(bucketAssociatedData(groupId, keyId)),
      },
      key,
      argument(privateKey),
    ),
  );

  const wrapped = new Uint8Array(WRAPPED_PRIVATE_KEY_BYTES);
  wrapped.set(nonce, 0);
  wrapped.set(sealed, WRAP_NONCE_BYTES);
  return { keyId, wrapped };
}

/**
 * Recover K1's private half from a bucket entry with the API key that wrapped it.
 *
 * The `keyId` carried on the entry is not consulted: the associated data is
 * rebuilt from the key id this API key actually derives, so an entry relabelled
 * with somebody else's id fails the tag instead of being opened under a
 * borrowed identity.
 *
 * @throws {VaultDecryptionError} if the key does not open this entry. Wrong key,
 *   wrong group and a corrupted entry are one indistinguishable failure.
 */
export async function unwrap(
  entry: BucketEntry,
  apiKey: Uint8Array,
  tenantId: string,
  groupId: string,
): Promise<Uint8Array> {
  if (entry.wrapped.length !== WRAPPED_PRIVATE_KEY_BYTES) {
    // A truncated entry is corruption, and corruption reports exactly as "not
    // yours" does: nothing here may become an oracle that tells the two apart.
    throw new VaultDecryptionError();
  }

  const { keyId, wrapKey } = await deriveBucketKeys(apiKey, tenantId);
  const nonce = entry.wrapped.subarray(0, WRAP_NONCE_BYTES);
  const ciphertextAndTag = entry.wrapped.subarray(WRAP_NONCE_BYTES);
  const key = await importWrapKey(wrapKey, "decrypt");

  const opened = await globalThis.crypto.subtle
    .decrypt(
      {
        name: "AES-GCM",
        iv: argument(nonce),
        additionalData: argument(bucketAssociatedData(groupId, keyId)),
      },
      key,
      argument(ciphertextAndTag),
    )
    .catch(() => {
      throw new VaultDecryptionError();
    });

  return new Uint8Array(opened);
}

/**
 * Find the entry a given API key can open, by deriving its key id and matching
 * the bucket in constant time. `undefined` when the key is not in the bucket.
 *
 * The whole bucket is scanned even after a hit: returning early would leak the
 * matching key's position in the bucket through timing.
 */
export async function findBucketEntry(
  group: KeyGroup,
  apiKey: Uint8Array,
  tenantId: string,
): Promise<BucketEntry | undefined> {
  const wanted = utf8Encode(await deriveKeyIdHex(apiKey, tenantId));

  let match: BucketEntry | undefined;
  for (const entry of group.bucket) {
    if (timingSafeEqual(wanted, utf8Encode(entry.keyId))) {
      match = entry;
    }
  }
  return match;
}

/**
 * Build a whole bucket: K1's private half wrapped once per API key.
 *
 * Used at bootstrap and at rotation, where a new K1 is wrapped for the keys
 * that survive the removal that triggered the rotation.
 */
export function buildBucket(
  privateKey: Uint8Array,
  apiKeys: readonly Uint8Array[],
  tenantId: string,
  groupId: string,
): Promise<BucketEntry[]> {
  return Promise.all(apiKeys.map((apiKey) => wrap(privateKey, apiKey, tenantId, groupId)));
}
