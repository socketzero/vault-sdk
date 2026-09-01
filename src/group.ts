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

import type { BucketEntry, GroupKeyPair, KeyGroup } from "./types.js";

/** `nonce(12) || ciphertext(32) || tag(16)`. The private half is always 32 bytes. */
export const WRAPPED_PRIVATE_KEY_BYTES = 60;

/**
 * A fresh X25519 keypair for a key group.
 *
 * The private half is returned once and never stored unwrapped — the caller's
 * only durable copies are the bucket entries `wrap` produces from it.
 */
export function generateGroup(): Promise<GroupKeyPair> {
  void 0;
  throw new Error("not implemented");
}

/**
 * Wrap K1's private half under one API key, producing one bucket entry.
 *
 * @param privateKey K1's private half, 32 raw bytes.
 * @param apiKey the RAW 32 bytes of the API key, never the display string.
 * @param tenantId the HKDF salt. Stable across rotation, which is why `key_id`
 *   survives a rotation of the group's public half.
 * @param groupId bound into the entry as associated data with the key id.
 */
export function wrap(
  privateKey: Uint8Array,
  apiKey: Uint8Array,
  tenantId: string,
  groupId: string,
): Promise<BucketEntry> {
  void privateKey;
  void apiKey;
  void tenantId;
  void groupId;
  throw new Error("not implemented");
}

/**
 * Recover K1's private half from a bucket entry with the API key that wrapped it.
 *
 * @throws {VaultDecryptionError} if the key does not open this entry. Wrong key,
 *   wrong group and a corrupted entry are one indistinguishable failure.
 */
export function unwrap(
  entry: BucketEntry,
  apiKey: Uint8Array,
  tenantId: string,
  groupId: string,
): Promise<Uint8Array> {
  void entry;
  void apiKey;
  void tenantId;
  void groupId;
  throw new Error("not implemented");
}

/**
 * Find the entry a given API key can open, by deriving its key id and matching
 * the bucket in constant time. `undefined` when the key is not in the bucket.
 */
export function findBucketEntry(
  group: KeyGroup,
  apiKey: Uint8Array,
  tenantId: string,
): Promise<BucketEntry | undefined> {
  void group;
  void apiKey;
  void tenantId;
  throw new Error("not implemented");
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
  void privateKey;
  void apiKeys;
  void tenantId;
  void groupId;
  throw new Error("not implemented");
}
