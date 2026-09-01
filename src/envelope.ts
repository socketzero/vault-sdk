/**
 * The envelope, exactly as `datamodel/sealed-secret/construction.md` states it.
 *
 *     eph        = X25519.generate()
 *     shared     = X25519(eph.priv, group_pub)
 *     key        = HKDF-SHA256(ikm=shared, salt=eph.pub || group_pub, info="socket0/v1", 32)
 *     nonce      = random(12)
 *     ct || tag  = AES-256-GCM(key, nonce, plaintext, aad=connection_id || field_name)
 *     envelope   = "x25519-hkdf-aesgcm:" + b64(eph.pub || nonce || ct || tag)
 *
 * Web Crypto only — `globalThis.crypto.subtle`. No `node:crypto`, no wasm, no
 * third-party crypto library.
 *
 * **`seal` takes a public key.** There is no code path in this module that
 * seals using a private half, which is `adr/0008-per-tenant-root-keypair`
 * expressed as a function signature.
 */

import type { AssociatedData, EnvelopeParts, GroupKeyPair, SealedEnvelope } from "./types.js";

/** `eph_pub`. */
export const EPHEMERAL_PUBLIC_KEY_BYTES = 32;
/** `nonce`. */
export const NONCE_BYTES = 12;
/** `gcm_tag`. */
export const TAG_BYTES = 16;
/**
 * `32 + 12 + 16`. AES-GCM is a stream mode, so the ciphertext is exactly the
 * plaintext's length: an envelope is always exactly 60 bytes larger than the
 * secret inside it, unconditionally, at every size. This is what makes the
 * bundle's in-place write-back cache possible at all.
 */
export const ENVELOPE_OVERHEAD_BYTES = 60;
/** The HKDF info string for the content key. */
export const HKDF_INFO_ENVELOPE = "socket0/v1";
/** The X25519 base point, used to recover a public half from a private one. */
export const X25519_BASE_POINT_BYTES = 32;

/** Generate an ephemeral or long-lived X25519 keypair, exported as raw bytes. */
export function generateX25519KeyPair(): Promise<GroupKeyPair> {
  void 0;
  throw new Error("not implemented");
}

/**
 * Recover the public half of an X25519 private key, as `X25519(priv, basepoint)`.
 *
 * Needed because `open` must reconstruct the HKDF salt `eph.pub || group_pub`
 * and a caller may hold only the unwrapped private half. Pass the public half
 * to `open` explicitly on a hot path to skip this.
 */
export function derivePublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
  void privateKey;
  throw new Error("not implemented");
}

/**
 * Build the associated data for a credential field: `connection_id || field_name`.
 *
 * An envelope copied from one connection's row to another's, or from `password`
 * into `api_key`, fails to open.
 */
export function fieldAssociatedData(connectionId: string, fieldName: string): AssociatedData {
  void connectionId;
  void fieldName;
  throw new Error("not implemented");
}

/** Build the associated data for a bucket entry: `group_id || key_id`. */
export function bucketAssociatedData(groupId: string, keyId: string): AssociatedData {
  void groupId;
  void keyId;
  throw new Error("not implemented");
}

/**
 * Seal a value to a key group's public half.
 *
 * **Needs no secret.** That is what lets the control plane and the credential
 * broker store what they cannot read.
 *
 * @param plaintext the value.
 * @param recipientPublicKey K1's public half, 32 raw bytes.
 * @param aad identity binding — build it with `fieldAssociatedData`.
 */
export function seal(
  plaintext: Uint8Array,
  recipientPublicKey: Uint8Array,
  aad: AssociatedData,
): Promise<SealedEnvelope> {
  void plaintext;
  void recipientPublicKey;
  void aad;
  throw new Error("not implemented");
}

/**
 * Open an envelope with K1's private half.
 *
 * @param envelope the `<alg>:<base64>` string, or the raw payload bytes.
 * @param recipientPrivateKey K1's private half, 32 raw bytes.
 * @param aad the same binding the writer used.
 * @param recipientPublicKey K1's public half, if the caller has it. Supplied to
 *   skip the base-point derivation needed to rebuild the HKDF salt.
 * @throws {VaultDecryptionError} on any authentication failure — wrong key,
 *   wrong group, wrong AAD and corruption are deliberately indistinguishable.
 */
export function open(
  envelope: SealedEnvelope | string | Uint8Array,
  recipientPrivateKey: Uint8Array,
  aad: AssociatedData,
  recipientPublicKey?: Uint8Array,
): Promise<Uint8Array> {
  void envelope;
  void recipientPrivateKey;
  void aad;
  void recipientPublicKey;
  throw new Error("not implemented");
}

/**
 * Split `<alg>:<base64>` into its parts, as views over one decoded payload.
 *
 * @throws {EnvelopeFormatError} on a wrong algorithm, bad base64, or a payload
 *   shorter than the 60-byte overhead.
 */
export function parseEnvelope(envelope: SealedEnvelope | string): EnvelopeParts {
  void envelope;
  throw new Error("not implemented");
}

/** Split raw payload bytes — the form a bundle stores — into the same parts. */
export function parseEnvelopeBytes(payload: Uint8Array): EnvelopeParts {
  void payload;
  throw new Error("not implemented");
}

/** Render raw payload bytes as the `<alg>:<base64>` display form. */
export function formatEnvelope(payload: Uint8Array): SealedEnvelope {
  void payload;
  throw new Error("not implemented");
}
