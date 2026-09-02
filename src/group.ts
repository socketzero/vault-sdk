/**
 * Key groups and the key bucket
 * (`product/control-plane/component/store/component/tenant/datamodel/key-group`).
 *
 * A group is one X25519 keypair plus one bucket entry per API key, each holding
 * K1's private half wrapped under that key:
 *
 *     key_id   = HKDF-SHA256(api_key, salt=utf8(tenant_id), info="socket0/v1/key-id",   16)
 *     wrap_key = HKDF-SHA256(api_key, salt=utf8(tenant_id), info="socket0/v1/tmk-wrap", 32)
 *     entry    = nonce(12) || AES-256-GCM(wrap_key, nonce, group_priv,
 *                                         aad=AAD(group_id, key_id))
 *
 * where `AAD` is the length-prefixed construction of
 * `datamodel/sealed-secret/construction.md` — `u32be(len(utf8(x))) || utf8(x)`
 * per component, never plain concatenation, never canonicalised.
 *
 * An API key opens its group and nothing else.
 */

import { deriveKeyIdHex, deriveWrapKey } from "./api-key.js";
import { timingSafeEqual, utf8Encode } from "./encoding.js";
import {
  bucketAssociatedData,
  derivePublicKey,
  fieldAssociatedData,
  generateX25519KeyPair,
  open,
  seal,
} from "./envelope.js";
import {
  type ApiKeyBytes,
  asPrivateKey,
  type BucketEntry,
  type GroupKeyPair,
  type GroupRotation,
  type KeyGroup,
  type PrivateKey,
  type SealedField,
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
 * A stored `key_id` is always its 32 lowercase hex characters, per
 * `datamodel/sealed-secret/construction.md`. Uppercase is a *different* string,
 * and since the id is bound into the entry's associated data byte for byte, an
 * uppercase id is an id nothing derives and nothing can open.
 */
const KEY_ID_PATTERN = /^[0-9a-f]{32}$/;

/**
 * A group must be able to wrap its private half for at least one key.
 *
 * Both key-group schemas put `minItems: 1` on the bucket, and the catalog says
 * why: a group with no entry can never be opened again and there is no recovery
 * path, because the private half is returned once and never stored unwrapped.
 */
const MINIMUM_BUCKET_SIZE = 1;

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
 * Reject a stored key id that is not 32 lowercase hex characters.
 *
 * Without this a mis-cased or truncated id is silent: it never equals a derived
 * id, so `findBucketEntry` reports "not your group" for an entry that is in fact
 * yours, and an operator sees a refusal where they should see corruption. The id
 * is stored in the clear in every bundle that carries the group, so echoing it
 * in the message reveals nothing a reader of the bundle does not already have.
 *
 * @throws {RangeError} when the id is malformed.
 */
function requireKeyId(keyId: string): string {
  if (!KEY_ID_PATTERN.test(keyId)) {
    throw new RangeError(
      `a bucket entry's key id is 32 lowercase hex characters, got ${JSON.stringify(keyId)}`,
    );
  }
  return keyId;
}

/**
 * Derive the pair a bucket operation needs from one API key.
 *
 * Two info strings over one secret: `keyId` is stored in the clear in every
 * bundle that carries the group, so it must be independent of the key that opens
 * the group. The salt is the tenant id, never the group's public half — that
 * half rotates and `keyId` must survive the rotation, or bucket lookup breaks
 * halfway through the operation that rotates it.
 */
async function deriveBucketKeys(
  apiKey: ApiKeyBytes,
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
 * The private half arrives branded, so its length is settled by `asPrivateKey`
 * before it gets here: wrapping the wrong-sized thing is no longer expressible,
 * which is stronger than the runtime check it replaces. A malformed entry would
 * otherwise stay silent until somebody tried to open the group, long after the
 * plaintext could have been resealed.
 *
 * @param privateKey K1's private half.
 * @param apiKey the RAW bytes of the API key, never the display string.
 * @param tenantId the HKDF salt, used as its exact UTF-8 bytes. Stable across
 *   rotation, which is why `key_id` survives a rotation of the public half.
 * @param groupId bound into the entry as associated data with the key id.
 */
export async function wrap(
  privateKey: PrivateKey,
  apiKey: ApiKeyBytes,
  tenantId: string,
  groupId: string,
): Promise<BucketEntry> {
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
 * The `keyId` carried on the entry is checked for shape but not consulted for the
 * associated data: that is rebuilt from the key id this API key actually derives,
 * so an entry relabelled with somebody else's id fails the tag instead of being
 * opened under a borrowed identity.
 *
 * @throws {RangeError} if the entry's key id is not 32 lowercase hex characters.
 *   The id is public — it is stored in the clear in every bundle — so a loud
 *   failure here is not an oracle, and `adr/0012` puts the obligation to make
 *   refusals indistinguishable on the relay rather than on this library.
 * @throws {VaultDecryptionError} if the key does not open this entry. Wrong key,
 *   wrong group and a corrupted entry are one indistinguishable failure.
 */
export async function unwrap(
  entry: BucketEntry,
  apiKey: ApiKeyBytes,
  tenantId: string,
  groupId: string,
): Promise<PrivateKey> {
  requireKeyId(entry.keyId);

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

  return asPrivateKey(new Uint8Array(opened));
}

/**
 * Find the entry a given API key can open, by deriving its key id and matching
 * the bucket in constant time. `undefined` when the key is not in the bucket.
 *
 * `adr/0012` accepts that this scan exists and is required, on two conditions:
 * it must be constant-time and it must not stop early on a hit, or it becomes an
 * oracle for which key ids a group holds. Both hold here — every entry is
 * compared with `timingSafeEqual`, and the loop always runs to the end.
 *
 * Every id is validated **before** the scan, in a pass that reads only the bucket
 * and never the caller's key, so the shape check cannot become a timing signal
 * about which entry matched.
 *
 * @throws {RangeError} if any entry's key id is not 32 lowercase hex characters.
 */
export async function findBucketEntry(
  group: KeyGroup,
  apiKey: ApiKeyBytes,
  tenantId: string,
): Promise<BucketEntry | undefined> {
  for (const entry of group.bucket) {
    requireKeyId(entry.keyId);
  }

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
 * Used at bootstrap and at rotation, where a new K1 is wrapped for the keys that
 * survive the removal that triggered the rotation.
 *
 * @throws {RangeError} if `apiKeys` is empty. An empty bucket is unconstructable
 *   on purpose: the private half is returned once and never stored unwrapped, so
 *   a group with no entry can never be read again and there is no recovery path.
 *   Both key-group schemas say `minItems: 1`; silently returning `[]` turned a
 *   caller's mistake into permanent data loss one write later.
 */
export async function buildBucket(
  privateKey: PrivateKey,
  apiKeys: readonly ApiKeyBytes[],
  tenantId: string,
  groupId: string,
): Promise<BucketEntry[]> {
  if (apiKeys.length < MINIMUM_BUCKET_SIZE) {
    throw new RangeError(
      "a key bucket needs at least one API key: a group with an empty bucket can never be opened again",
    );
  }
  return Promise.all(apiKeys.map((apiKey) => wrap(privateKey, apiKey, tenantId, groupId)));
}

/**
 * Rotate a key group: a new K1, every field resealed to it, and the bucket
 * rebuilt for the surviving keys — **as one result or not at all**.
 *
 * `protocol/vault-operations` makes this one operation rather than a recipe of
 * `generateGroup` + `seal` + `wrap` because assembled by hand it is three loops
 * and one chance to get the ordering wrong, in the one operation where getting it
 * wrong is unrecoverable. There is no per-field wrapped data key, so this is a
 * genuine decrypt-and-reseal rather than a re-wrap.
 *
 * **It writes nothing.** Persisting the result atomically — one generation, all
 * of it — is the caller's job, and only the caller can do it: a partial write
 * leaves fields no surviving key can open.
 *
 * @param oldPrivateKey the outgoing K1's private half, unwrapped from a bucket
 *   entry the caller could open.
 * @param fields every sealed field in the group, each with the identity its
 *   associated data binds. The identity is carried through unchanged: rotation
 *   changes the recipient, never what the envelope is bound to.
 * @param apiKeys the keys that survive the removal that triggered the rotation.
 * @throws {VaultDecryptionError} if any field fails to open under the old private
 *   half. The whole operation fails and returns nothing, because a partial result
 *   is exactly the thing that must never be written.
 * @throws {RangeError} if no API key survives — see `buildBucket`.
 */
export async function rotateGroup(
  oldPrivateKey: PrivateKey,
  fields: readonly SealedField[],
  apiKeys: readonly ApiKeyBytes[],
  tenantId: string,
  groupId: string,
): Promise<GroupRotation> {
  const { publicKey, privateKey } = await generateGroup();

  // The outgoing public half is half of the HKDF salt every `open` rebuilds;
  // deriving it once here saves a base-point multiplication per field.
  const oldPublicKey = await derivePublicKey(oldPrivateKey);

  const [resealed, bucket] = await Promise.all([
    Promise.all(
      fields.map(async (field): Promise<SealedField> => {
        const aad = fieldAssociatedData(field.identity.connectionUuid, field.identity.fieldName);
        const plaintext = await open(field.envelope, oldPrivateKey, aad, oldPublicKey);
        return { identity: field.identity, envelope: await seal(plaintext, publicKey, aad) };
      }),
    ),
    buildBucket(privateKey, apiKeys, tenantId, groupId),
  ]);

  return { publicKey, privateKey, fields: resealed, bucket };
}
