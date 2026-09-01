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

import { base64Decode, base64Encode, utf8Encode } from "./encoding.js";
import type { AssociatedData, EnvelopeParts, GroupKeyPair, SealedEnvelope } from "./types.js";
import { EnvelopeFormatError, SEAL_ALGORITHM, VaultDecryptionError, VaultError } from "./types.js";

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

// ---------------------------------------------------------------------------
// Module-private constants
// ---------------------------------------------------------------------------

/** Raw X25519 scalars and points are both 32 bytes. */
const X25519_KEY_BYTES = 32;

/** AES-GCM tag length is quoted in bits by Web Crypto and in bytes by the format. */
const TAG_BITS = TAG_BYTES * 8;

/** HKDF-SHA256 output for the content key, in bits. */
const CONTENT_KEY_BITS = 256;

const X25519_ALGORITHM = { name: "X25519" } as const;

/**
 * `u = 9`, little-endian, zero-padded to 32 bytes.
 *
 * Web Crypto exposes no "scalar to public key" call, so recovering a public
 * half from a private one is spelled as an ECDH against the base point — which
 * is what `X25519(priv, basepoint)` means arithmetically anyway.
 */
const X25519_BASE_POINT = Uint8Array.from({ length: X25519_BASE_POINT_BYTES }, (_unused, index) =>
  index === 0 ? 9 : 0,
);

/**
 * The fixed DER preamble of a PKCS#8 X25519 private key (OID 1.3.101.110),
 * followed by the 32 raw scalar bytes.
 *
 * Web Crypto cannot import a raw private scalar — only `pkcs8` or `jwk`, and
 * `jwk` (RFC 8037) demands the public half we are often trying to recover. So
 * the SDK keeps raw scalars, as every other Socket0 implementation does, and
 * re-wraps them here at the boundary.
 */
const PKCS8_X25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

/** Standard base64 with padding, and nothing else. */
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** An algorithm tag long enough to identify itself is short enough to quote. */
const ALGORITHM_QUOTE_LIMIT = 32;

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

/**
 * Present a view to Web Crypto, which accepts no view over a `SharedArrayBuffer`.
 *
 * The overwhelmingly common case rebinds the same bytes as a new view and copies
 * nothing; only a genuinely shared buffer is copied, because the alternative is
 * an opaque `DataError` from `subtle`.
 */
function asBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes.buffer instanceof ArrayBuffer
    ? new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    : Uint8Array.from(bytes);
}

/** Concatenate views into one fresh buffer. */
function concatBytes(...parts: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
  let total = 0;
  for (const part of parts) {
    total += part.length;
  }
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return joined;
}

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Reject a key of the wrong size before Web Crypto turns it into an opaque
 * `DataError`. A wrong-sized key is a caller bug, not a decryption failure, and
 * must not be reported as one — the two need different fixes.
 */
function assertX25519KeyLength(key: Uint8Array, role: string): Uint8Array {
  if (key.length !== X25519_KEY_BYTES) {
    throw new VaultError(`${role} must be ${X25519_KEY_BYTES} raw bytes, received ${key.length}`);
  }
  return key;
}

// ---------------------------------------------------------------------------
// Key import and derivation
// ---------------------------------------------------------------------------

function importPublicKey(publicKey: Uint8Array): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    "raw",
    asBufferSource(assertX25519KeyLength(publicKey, "an X25519 public key")),
    X25519_ALGORITHM,
    false,
    [],
  );
}

function importPrivateKey(privateKey: Uint8Array): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    "pkcs8",
    concatBytes(PKCS8_X25519_PREFIX, assertX25519KeyLength(privateKey, "an X25519 private key")),
    X25519_ALGORITHM,
    false,
    ["deriveBits"],
  );
}

/** `X25519(priv, basepoint)`, for a scalar that is already a `CryptoKey`. */
async function publicKeyOf(privateKey: CryptoKey): Promise<Uint8Array> {
  const basePoint = await importPublicKey(X25519_BASE_POINT);
  return new Uint8Array(
    await globalThis.crypto.subtle.deriveBits(
      { ...X25519_ALGORITHM, public: basePoint },
      privateKey,
      X25519_KEY_BYTES * 8,
    ),
  );
}

/**
 * `HKDF-SHA256(ikm=X25519(priv, pub), salt=eph_pub || group_pub, info="socket0/v1", 32)`.
 *
 * The salt is the transcript of the exchange, so a content key is bound to both
 * halves that produced it: the same ephemeral public key replayed against a
 * different group derives an unrelated key rather than a related one.
 */
async function deriveContentKey(
  privateKey: CryptoKey,
  peerPublicKey: CryptoKey,
  ephemeralPublicKey: Uint8Array,
  recipientPublicKey: Uint8Array,
): Promise<CryptoKey> {
  const subtle = globalThis.crypto.subtle;
  const sharedSecret = await subtle.deriveBits(
    { ...X25519_ALGORITHM, public: peerPublicKey },
    privateKey,
    X25519_KEY_BYTES * 8,
  );
  const extractionKey = await subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveBits"]);
  const contentKeyBits = await subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: concatBytes(ephemeralPublicKey, recipientPublicKey),
      info: utf8Encode(HKDF_INFO_ENVELOPE),
    },
    extractionKey,
    CONTENT_KEY_BITS,
  );
  return subtle.importKey("raw", contentKeyBits, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/** Generate an ephemeral or long-lived X25519 keypair, exported as raw bytes. */
export async function generateX25519KeyPair(): Promise<GroupKeyPair> {
  // An X25519 private key is 32 uniform random bytes; clamping happens inside
  // the scalar multiplication, so there is no key-generation step to delegate.
  const privateKey = randomBytes(X25519_KEY_BYTES);
  return { privateKey, publicKey: await derivePublicKey(privateKey) };
}

/**
 * Recover the public half of an X25519 private key, as `X25519(priv, basepoint)`.
 *
 * Needed because `open` must reconstruct the HKDF salt `eph.pub || group_pub`
 * and a caller may hold only the unwrapped private half. Pass the public half
 * to `open` explicitly on a hot path to skip this.
 */
export async function derivePublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
  return publicKeyOf(await importPrivateKey(privateKey));
}

/**
 * Build the associated data for a credential field: `connection_id || field_name`.
 *
 * An envelope copied from one connection's row to another's, or from `password`
 * into `api_key`, fails to open.
 */
export function fieldAssociatedData(connectionId: string, fieldName: string): AssociatedData {
  return concatBytes(utf8Encode(connectionId), utf8Encode(fieldName));
}

/** Build the associated data for a bucket entry: `group_id || key_id`. */
export function bucketAssociatedData(groupId: string, keyId: string): AssociatedData {
  return concatBytes(utf8Encode(groupId), utf8Encode(keyId));
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
export async function seal(
  plaintext: Uint8Array,
  recipientPublicKey: Uint8Array,
  aad: AssociatedData,
): Promise<SealedEnvelope> {
  const recipient = await importPublicKey(recipientPublicKey);
  const ephemeralPrivate = await importPrivateKey(randomBytes(X25519_KEY_BYTES));
  const ephemeralPublicKey = await publicKeyOf(ephemeralPrivate);
  const contentKey = await deriveContentKey(
    ephemeralPrivate,
    recipient,
    ephemeralPublicKey,
    recipientPublicKey,
  );
  const nonce = randomBytes(NONCE_BYTES);
  const ciphertextAndTag = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: asBufferSource(aad), tagLength: TAG_BITS },
      contentKey,
      asBufferSource(plaintext),
    ),
  );
  return formatEnvelope(concatBytes(ephemeralPublicKey, nonce, ciphertextAndTag));
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
export async function open(
  envelope: SealedEnvelope | string | Uint8Array,
  recipientPrivateKey: Uint8Array,
  aad: AssociatedData,
  recipientPublicKey?: Uint8Array,
): Promise<Uint8Array> {
  const parts =
    envelope instanceof Uint8Array ? parseEnvelopeBytes(envelope) : parseEnvelope(envelope);
  const recipientPrivate = await importPrivateKey(recipientPrivateKey);
  const recipientPublic =
    recipientPublicKey === undefined
      ? await publicKeyOf(recipientPrivate)
      : assertX25519KeyLength(recipientPublicKey, "an X25519 public key");
  const ephemeralPublic = await importPublicKey(parts.ephemeralPublicKey);
  const contentKey = await deriveContentKey(
    recipientPrivate,
    ephemeralPublic,
    parts.ephemeralPublicKey,
    recipientPublic,
  );
  try {
    return new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: asBufferSource(parts.nonce),
          additionalData: asBufferSource(aad),
          tagLength: TAG_BITS,
        },
        contentKey,
        asBufferSource(parts.ciphertextAndTag),
      ),
    );
  } catch {
    // One error for wrong key, wrong group, wrong AAD and flipped bits. The
    // cause is deliberately dropped: a caller able to tell them apart could
    // build the enumeration oracle the relay must not offer.
    throw new VaultDecryptionError();
  }
}

/**
 * Split `<alg>:<base64>` into its parts, as views over one decoded payload.
 *
 * @throws {EnvelopeFormatError} on a wrong algorithm, bad base64, or a payload
 *   shorter than the 60-byte overhead.
 */
export function parseEnvelope(envelope: SealedEnvelope | string): EnvelopeParts {
  const separator = envelope.indexOf(":");
  if (separator < 0) {
    throw new EnvelopeFormatError('envelope is not in "<alg>:<base64>" form');
  }
  const algorithm = envelope.slice(0, separator);
  if (algorithm !== SEAL_ALGORITHM) {
    throw new EnvelopeFormatError(
      `unsupported envelope algorithm "${algorithm.slice(0, ALGORITHM_QUOTE_LIMIT)}"`,
    );
  }
  const encoded = envelope.slice(separator + 1);
  if (!BASE64_PATTERN.test(encoded)) {
    throw new EnvelopeFormatError("envelope payload is not standard base64");
  }
  return parseEnvelopeBytes(base64Decode(encoded));
}

/** Split raw payload bytes — the form a bundle stores — into the same parts. */
export function parseEnvelopeBytes(payload: Uint8Array): EnvelopeParts {
  assertEnvelopeLength(payload);
  const nonceStart = EPHEMERAL_PUBLIC_KEY_BYTES;
  const bodyStart = nonceStart + NONCE_BYTES;
  return {
    algorithm: SEAL_ALGORITHM,
    ephemeralPublicKey: payload.subarray(0, nonceStart),
    nonce: payload.subarray(nonceStart, bodyStart),
    ciphertextAndTag: payload.subarray(bodyStart),
  };
}

/** Render raw payload bytes as the `<alg>:<base64>` display form. */
export function formatEnvelope(payload: Uint8Array): SealedEnvelope {
  assertEnvelopeLength(payload);
  return `${SEAL_ALGORITHM}:${base64Encode(payload)}`;
}

/**
 * A payload below the overhead cannot even hold an ephemeral key, a nonce and a
 * tag, so it is a format error rather than a decryption failure.
 */
function assertEnvelopeLength(payload: Uint8Array): void {
  if (payload.length < ENVELOPE_OVERHEAD_BYTES) {
    throw new EnvelopeFormatError(
      `envelope payload is ${payload.length} bytes, below the ${ENVELOPE_OVERHEAD_BYTES}-byte overhead`,
    );
  }
}
