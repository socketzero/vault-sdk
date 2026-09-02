/**
 * Shared types for the whole vault SDK.
 *
 * Source of truth: the metaframework catalog under `solutions/socket0`.
 *   - `datamodel/api-key`                        the key format and its two derivations
 *   - `datamodel/sealed-secret/construction.md`  the envelope, exactly
 *   - `product/vault-sdk/datamodel/bundle`       the binary format and the write-back cache
 *   - `protocol/vault-operations`                the surface every plane agrees on
 *
 * Nothing here is derived from `any`, and nothing here performs I/O.
 */

// ---------------------------------------------------------------------------
// Branded key material
// ---------------------------------------------------------------------------

/*
 * Every key in this system is 32 raw bytes, so `Uint8Array` makes the public
 * half, the private half and an API key mutually substitutable. That is not a
 * cosmetic weakness: `seal(value, keypair.privateKey, aad)` type-checks, runs,
 * and produces an envelope whose recipient is a public half nobody holds — the
 * plaintext is gone and there is no error at the moment it is lost.
 *
 * The brands below make each role a distinct type. They are `unique symbol`
 * keys, so a brand cannot be forged by writing an object literal, cannot be
 * spelled by a caller, and does not survive JSON — a key that arrives over a
 * wire has to be re-validated through a constructor, which is the point.
 *
 * The constructors do not copy. A public half read out of a bundle is a view
 * into the caller's buffer and `product/vault-sdk/datamodel/bundle` forbids
 * copying it; branding is a compile-time act and stays one.
 */

declare const publicKeyBrand: unique symbol;
declare const privateKeyBrand: unique symbol;
declare const apiKeyBytesBrand: unique symbol;

/** X25519 public half, 32 raw bytes. Public — sealing needs only this. */
export type PublicKey = Uint8Array & { readonly [publicKeyBrand]: "x25519-public" };

/** X25519 private scalar, 32 raw bytes. Opens a group; never stored unwrapped. */
export type PrivateKey = Uint8Array & { readonly [privateKeyBrand]: "x25519-private" };

/**
 * The 32 raw bytes of an API key — the HKDF input for both derivations.
 *
 * **Never the display string.** The prefix and the checksum are packaging;
 * `datamodel/api-key` requires that changing them cannot invalidate a key.
 */
export type ApiKeyBytes = Uint8Array & { readonly [apiKeyBytesBrand]: "api-key" };

/** An X25519 point. */
export const X25519_PUBLIC_KEY_BYTES = 32;
/** An X25519 scalar. */
export const X25519_PRIVATE_KEY_BYTES = 32;
/** `adr/0012-tenant-held-keys`: the key is 32 random bytes, and it is a KEK. */
export const API_KEY_MATERIAL_BYTES = 32;

/**
 * Assert bytes are a group's public half.
 *
 * @throws {RangeError} if the length is wrong. A wrong-sized key is a
 *   programming error, and it has to be loud here: carried further it becomes
 *   an envelope that fails to open, weeks later, with the plaintext long gone.
 */
export function asPublicKey(bytes: Uint8Array): PublicKey {
  if (bytes.length !== X25519_PUBLIC_KEY_BYTES) {
    throw new RangeError(
      `an X25519 public half is ${X25519_PUBLIC_KEY_BYTES} bytes, got ${bytes.length}`,
    );
  }
  return bytes as PublicKey;
}

/**
 * Assert bytes are a group's private half.
 *
 * @throws {RangeError} if the length is wrong.
 */
export function asPrivateKey(bytes: Uint8Array): PrivateKey {
  if (bytes.length !== X25519_PRIVATE_KEY_BYTES) {
    throw new RangeError(
      `an X25519 private half is ${X25519_PRIVATE_KEY_BYTES} bytes, got ${bytes.length}`,
    );
  }
  return bytes as PrivateKey;
}

/**
 * Assert bytes are an API key's raw material.
 *
 * @throws {RangeError} if the length is wrong. A short key is a weak KEK, and
 *   `requirement/api-key-entropy` makes the entropy load-bearing: an attacker
 *   with a KV dump attacks it offline.
 */
export function asApiKeyBytes(bytes: Uint8Array): ApiKeyBytes {
  if (bytes.length !== API_KEY_MATERIAL_BYTES) {
    throw new RangeError(`an API key is ${API_KEY_MATERIAL_BYTES} bytes, got ${bytes.length}`);
  }
  return bytes as ApiKeyBytes;
}

// ---------------------------------------------------------------------------
// API key
// ---------------------------------------------------------------------------

/** The environment segment of a displayed API key. */
export type ApiKeyEnvironment = "live" | "test";

/** Raw key material plus the display form it round-trips to. */
export interface ApiKeyMaterial {
  readonly environment: ApiKeyEnvironment;
  /** The 32 random bytes. **This**, never the display string, is the HKDF input. */
  readonly bytes: ApiKeyBytes;
  /** `sk0_<env>_<43 base62>_<6 base62>`, 59 characters. */
  readonly display: string;
}

/** Why a display string is not a key. Reported locally, before any request. */
export type ApiKeyParseFailure =
  | "empty"
  | "bad-length"
  | "bad-segment-count"
  | "bad-issuer-prefix"
  | "unknown-environment"
  | "bad-body-length"
  | "bad-checksum-length"
  | "non-base62-character"
  | "body-out-of-range"
  | "checksum-mismatch";

/**
 * The result of `parseApiKey`. A discriminated union rather than an exception,
 * because "you mistyped it" is the whole reason the checksum exists: the server
 * cannot tell the user, so the client must.
 */
export type ParsedApiKey =
  | ({ readonly ok: true } & ApiKeyMaterial)
  | {
      readonly ok: false;
      readonly reason: ApiKeyParseFailure;
      /** Human-readable, safe to show. Never contains key material. */
      readonly message: string;
    };

/**
 * Take the material out of a parse result, or throw.
 *
 * `parseKey` never throws — that is its contract, and `protocol/vault-operations`
 * says so. This is the one sanctioned bridge for a caller who has already
 * decided that a malformed key at this point is a bug rather than a typo (a
 * config loader, a test fixture), and it is the only construction site of
 * `ApiKeyFormatError`. Without it the class is an invitation to wrap a
 * non-throwing function in `try`/`catch` and never notice the branch is dead.
 *
 * @throws {ApiKeyFormatError} carrying the machine reason and a safe message.
 */
export function requireApiKey(parsed: ParsedApiKey): ApiKeyMaterial {
  if (!parsed.ok) {
    throw new ApiKeyFormatError(parsed.reason, parsed.message);
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// Key groups and buckets
// ---------------------------------------------------------------------------

/**
 * An X25519 keypair. The private half is returned once and never stored
 * unwrapped.
 *
 * The two halves are different types, so `seal(value, pair.privateKey, aad)`
 * does not compile.
 */
export interface GroupKeyPair {
  /** 32 bytes, raw. Public — sealing needs only this. */
  readonly publicKey: PublicKey;
  /** 32 bytes, raw. */
  readonly privateKey: PrivateKey;
}

/**
 * One API key's copy of a group's private half.
 *
 * `keyId` is `HKDF-SHA256(apiKey, salt=utf8(tenantId), info="socket0/v1/key-id", 16)`
 * as 32 lowercase hex characters; it is stored in the clear in every bundle.
 * `wrapped` is the private half under
 * `HKDF-SHA256(apiKey, salt=utf8(tenantId), info="socket0/v1/tmk-wrap", 32)`.
 */
export interface BucketEntry {
  readonly keyId: string;
  /** `nonce(12) || ciphertext(32) || tag(16)`, 60 bytes. AAD = `AAD(groupId, keyId)`. */
  readonly wrapped: Uint8Array;
}

/**
 * A key group as it travels inside a bundle: public half plus the whole bucket.
 *
 * `generation` is required. The compiled key-group schema
 * (`.../component/shard/datamodel/key-group/schema.json`) lists it in
 * `required`, and it decides whether a bundle is stale rather than corrupt — a
 * question a reader cannot answer from an absent counter.
 */
export interface KeyGroup {
  readonly groupId: string;
  /** K1 public half, 32 raw bytes. */
  readonly publicKey: PublicKey;
  /** The group's own rotation counter, distinct from the bundle's generation. */
  readonly generation: number;
  /**
   * One entry per API key. Empty is not representable in the schema: a group
   * with no key can never be opened again.
   */
  readonly bucket: readonly BucketEntry[];
}

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

/** The only algorithm this library speaks. */
export const SEAL_ALGORITHM = "x25519-hkdf-aesgcm";
export type SealAlgorithm = typeof SEAL_ALGORITHM;

/**
 * The stored form of every sensitive value: `<alg>:<base64>` where the payload
 * is `eph_pub(32) || nonce(12) || ciphertext || tag(16)`.
 */
export type SealedEnvelope = `${SealAlgorithm}:${string}`;

/** A parsed envelope. All three members are views over one decoded payload. */
export interface EnvelopeParts {
  readonly algorithm: SealAlgorithm;
  /** 32 bytes. */
  readonly ephemeralPublicKey: Uint8Array;
  /** 12 bytes. */
  readonly nonce: Uint8Array;
  /** `ciphertext || tag`; the tag is the trailing 16 bytes. */
  readonly ciphertextAndTag: Uint8Array;
}

/**
 * Associated data, built by `fieldAssociatedData` or `bucketAssociatedData` and
 * by nothing else.
 *
 * **Length-prefixed, per `datamodel/sealed-secret/construction.md`:**
 *
 *     AAD(a, b, ...) = u32be(len(utf8(a))) || utf8(a) || u32be(len(utf8(b))) || utf8(b) || ...
 *
 * Plain concatenation is a defect: `("conn", "1password")` and
 * `("conn1", "password")` would produce identical associated data, so an
 * envelope sealed for one would open under the other. Components are never
 * canonicalised, trimmed or lower-cased — what is bound is the exact byte
 * string the caller passed, so a mismatch fails rather than being repaired.
 */
export type AssociatedData = Uint8Array;

/**
 * The identity a credential field's AAD binds, in that order.
 *
 * The connection is its raw sixteen UUID bytes rather than a rendered id: the
 * rendering is a presentation choice, and binding one would make the AAD depend
 * on how the id happened to be spelled.
 */
export interface FieldIdentity {
  readonly connectionUuid: Uint8Array;
  readonly fieldName: string;
}

/** The identity a bucket entry's AAD binds, in that order. */
export interface BucketIdentity {
  readonly groupId: string;
  /** Always its 32 lowercase hex characters. */
  readonly keyId: string;
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

/** One sealed value together with the identity its AAD binds. */
export interface SealedField {
  readonly identity: FieldIdentity;
  readonly envelope: SealedEnvelope;
}

/**
 * What `rotateGroup` returns: a new K1, every field resealed to it, and the
 * bucket rebuilt for the surviving API keys — **together or not at all**.
 *
 * `protocol/vault-operations` makes rotation one operation rather than a recipe
 * of `generateGroup` + `seal` + `wrap` precisely so this object cannot exist
 * half-built: a partial write leaves fields no surviving key can open, and
 * there is no recovery path. Modelling it as one readonly result is what stops
 * a caller persisting the new bucket and the old envelopes.
 *
 * Nothing here is written by the library. Persisting the whole result
 * atomically is the caller's obligation, and the caller is the only party that
 * can — including incrementing `KeyGroup.generation`, which rotation does not
 * receive and therefore cannot compute.
 */
export interface GroupRotation {
  /** K1's new public half. Every future seal uses this. */
  readonly publicKey: PublicKey;
  /** K1's new private half, returned once. The bucket is its only durable copy. */
  readonly privateKey: PrivateKey;
  /** Every field of the group, resealed under the new public half. */
  readonly fields: readonly SealedField[];
  /** The rebuilt bucket: one entry per surviving API key, never empty. */
  readonly bucket: readonly BucketEntry[];
}

// ---------------------------------------------------------------------------
// Bundle: sections
// ---------------------------------------------------------------------------

/** Section kinds, as their four ASCII characters. */
export type SectionKindName = "INDX" | "CONN" | "GRUP" | "FILT" | "STRS";

/** One 16-byte section-table entry, read in place. */
export interface SectionEntry {
  readonly kind: number;
  /** Absolute byte offset from the start of the buffer. */
  readonly offset: number;
  readonly length: number;
  readonly count: number;
}

/** The fixed 64-byte header, the only part a reader materialises. */
export interface BundleHeader {
  /** Always `"S0BUNDLE"`. */
  readonly magic: string;
  /** A reader refuses a value it does not know. */
  readonly version: number;
  /** Reserved, must be zero. */
  readonly flags: number;
  /** Monotonic per shard, from the compiler. */
  readonly generation: bigint;
  /** Unix millis. Advisory only. */
  readonly builtAt: bigint;
  /** Count of section-table descriptors that follow. */
  readonly sections: number;
}

// ---------------------------------------------------------------------------
// Bundle: field descriptors and the write-back cache
// ---------------------------------------------------------------------------

/** `0` sealed, `1` open. Published last, after the bytes and the length. */
export const FieldState = {
  Sealed: 0,
  Open: 1,
} as const;
export type FieldState = (typeof FieldState)[keyof typeof FieldState];

/**
 * One sealed value's slot: `strs_offset 4 | sealed_len 4 | plain_len 4 | state 1 | pad 3`.
 *
 * `descriptorOffset` is where those 16 bytes live, which is what a write-back
 * needs in order to publish `plain_len` and then `state` into the same buffer.
 */
export interface FieldDescriptor {
  readonly descriptorOffset: number;
  readonly strsOffset: number;
  readonly sealedLen: number;
  readonly plainLen: number;
  readonly state: FieldState;
}

// ---------------------------------------------------------------------------
// Bundle: read-in-place views
// ---------------------------------------------------------------------------

/*
 * Every accessor below is a `readonly` function property rather than a method.
 * A view is a window onto a buffer shared by every concurrent request in the
 * isolate; replacing one of its accessors is never a legitimate act, and
 * `readonly` says so at compile time. Implementations still write them as
 * ordinary methods and callers still call them as ordinary methods.
 *
 * The byte views themselves stay `Uint8Array`: the bundle is mutated in place
 * — that is the cache — and every one of these views is handed to Web Crypto,
 * which takes a `BufferSource`. Immutability is enforced where it is true, and
 * not claimed where it is not.
 */

/** One bucket entry, read in place. `wrapped()` returns a view, never a copy. */
export interface BucketEntryView {
  readonly entryOffset: number;
  readonly keyIdBytes: () => Uint8Array;
  readonly keyIdHex: () => string;
  readonly wrapped: () => Uint8Array;
}

/** One key group, read in place. */
export interface KeyGroupView {
  readonly groupIndex: number;
  readonly recordOffset: number;
  readonly groupIdBytes: () => Uint8Array;
  readonly groupId: () => string;
  readonly publicKey: () => PublicKey;
  readonly generation: () => number;
  readonly bucketSize: number;
  readonly bucketEntry: (index: number) => BucketEntryView | undefined;
  readonly findBucketEntry: (keyId: string) => BucketEntryView | undefined;
  /**
   * The descriptor for K1's wrapped private half, cached the same way a field
   * is. Its scratch region is sized to the group's widest bucket entry and is
   * never itself a bucket entry — writing an unwrapped half into an entry would
   * destroy the wrap another API key needs.
   */
  readonly privateKeyDescriptor: () => FieldDescriptor;
}

/**
 * One connection record, read in place.
 *
 * Nothing here allocates a per-record object graph: every accessor computes an
 * offset and reads through the shared `DataView`.
 */
export interface ConnectionRecord {
  readonly recordOffset: number;
  readonly groupIndex: number;
  /** A 16-byte view over the record's UUID. */
  readonly idBytes: () => Uint8Array;
  /** Full sixteen-byte comparison; the index fingerprint is a filter, not a proof. */
  readonly matchesId: (id: Uint8Array) => boolean;
  readonly target: () => string;
  readonly visibleKeys: () => readonly string[];
  /** First match wins, and the walk stops there; duplicate keys are not rejected. */
  readonly visible: (name: string) => string | number | boolean | undefined;
  /** Unix millis, or `null` when the connection does not expire. */
  readonly expiresAt: () => number | null;
  /** Indices into the FILT section. */
  readonly filterIndices: () => Uint32Array;
  readonly fieldNames: () => readonly string[];
  readonly field: (name: string) => FieldDescriptor | undefined;
  /**
   * The current bytes of a field: the envelope while `state === Sealed`, the
   * plaintext once it is `Open`. A view into the buffer, never a copy.
   */
  readonly fieldBytes: (descriptor: FieldDescriptor) => Uint8Array;
}

/** A filter's constructor arguments, read at call time and never instantiated. */
export interface FilterArgsView {
  readonly filterIndex: number;
  readonly kind: number;
  readonly args: () => Uint8Array;
}

/**
 * What `readBundle` returns. A set of accessors over the caller's buffer — no
 * deserialisation, no object per record, no copy.
 */
export interface BundleView {
  readonly header: BundleHeader;
  /** The buffer being read. Held so a write-back lands where the read started. */
  readonly buffer: Uint8Array;
  readonly section: (kind: SectionKindName) => SectionEntry | undefined;
  /** Verified once at load, and never again: write-back invalidates it by design. */
  readonly verifyChecksum: () => Promise<boolean>;
  readonly connectionCount: number;
  readonly groupCount: number;
  /**
   * One masked slot read, a fingerprint compare, then a full id verify.
   *
   * A miss is one read and a hit is a read plus cryptography, so the difference
   * is observable. Closing that oracle is `component/shard`'s duty on **every**
   * miss path — malformed id, wrong shard prefix, empty slot, fingerprint
   * mismatch alike — because lookup is synchronous and cannot perform the decoy
   * itself. The library offers `decoyUnwrap`; it cannot make a caller run it.
   */
  readonly lookup: (connectionId: string) => ConnectionRecord | undefined;
  readonly connectionAt: (recordOffset: number) => ConnectionRecord;
  readonly group: (index: number) => KeyGroupView | undefined;
  readonly groupById: (groupId: string) => KeyGroupView | undefined;
  readonly filter: (index: number) => FilterArgsView | undefined;
  /**
   * Write plaintext into the slot its own ciphertext occupied: bytes, then
   * `plain_len`, then `state` — in one synchronous block, flag published last.
   * An envelope is always exactly 60 bytes larger than its plaintext, so it fits.
   */
  readonly writeBack: (descriptor: FieldDescriptor, plaintext: Uint8Array) => FieldDescriptor;
}

// ---------------------------------------------------------------------------
// Bundle: the writer's input (the logical form of schema.json)
// ---------------------------------------------------------------------------

/** Configuration readable with no key at all. */
export type VisibleValue = string | number | boolean;

export interface BundleHeaderInput {
  readonly version: number;
  readonly generation: bigint;
  /** Unix millis. */
  readonly builtAt: bigint;
}

export interface ConnectionInput {
  /**
   * A canonical lowercase UUID — no shard prefix. Its low 32 bits address the
   * index bucket, and its raw bytes are bound into every field's AAD.
   */
  readonly connectionId: string;
  readonly groupId: string;
  readonly target: string;
  readonly visible: Readonly<Record<string, VisibleValue>>;
  /** Field name to sealed envelope. Opaque to the format. */
  readonly sealed: Readonly<Record<string, SealedEnvelope>>;
  readonly filters?: readonly number[];
  /** Unix millis, or null. Visible, so a shard can see the renewal margin. */
  readonly expiresAt?: number | null;
}

export interface FilterInput {
  /** The filter class discriminator, as a uint32. */
  readonly kind: number;
  /** Constructor arguments, as bytes. */
  readonly args: Uint8Array;
}

/** A whole shard generation, as handed to `writeBundle`. */
export interface BundleInput {
  readonly header: BundleHeaderInput;
  readonly groups: readonly KeyGroup[];
  readonly connections: readonly ConnectionInput[];
  readonly filters: readonly FilterInput[];
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Base for everything this library throws on its own behalf. */
export class VaultError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "VaultError";
  }
}

/**
 * A display string is not a well-formed API key. Carries the machine reason.
 *
 * Thrown only by `requireApiKey`. `parseKey` returns a result and never throws.
 */
export class ApiKeyFormatError extends VaultError {
  readonly reason: ApiKeyParseFailure;
  constructor(reason: ApiKeyParseFailure, message: string) {
    super(message);
    this.name = "ApiKeyFormatError";
    this.reason = reason;
  }
}

/** The envelope string is malformed: wrong algorithm, bad base64, short payload. */
export class EnvelopeFormatError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = "EnvelopeFormatError";
  }
}

/**
 * An authentication tag did not verify.
 *
 * Deliberately one error for wrong key, wrong group, wrong AAD and corrupted
 * bytes: the relay must not become an enumeration oracle, so the library does
 * not hand a caller the distinction it would need to build one.
 *
 * `adr/0012-tenant-held-keys` scopes that narrowly, and the narrow statement is
 * the true one: a library may distinguish a malformed envelope from a failed
 * tag, and should, because somebody debugging a corrupt bundle needs it. What
 * must be indistinguishable is what a caller of the *relay* observes — one
 * status, one body, one timing envelope — and collapsing that wider set of
 * outcomes is `component/shard`'s obligation, not this type's.
 */
export class VaultDecryptionError extends VaultError {
  constructor(message = "decryption failed") {
    super(message);
    this.name = "VaultDecryptionError";
  }
}

/** The buffer is not a bundle, or is truncated, or a section is inconsistent. */
export class BundleFormatError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = "BundleFormatError";
  }
}

/**
 * A `version` this reader does not implement — higher or lower. Refuse the whole
 * bundle: partial understanding of a security artifact is worse than none.
 */
export class UnsupportedBundleVersionError extends VaultError {
  readonly found: number;
  readonly supported: number;
  constructor(found: number, supported: number) {
    super(`bundle version ${found} is not supported; this reader implements ${supported}`);
    this.name = "UnsupportedBundleVersionError";
    this.found = found;
    this.supported = supported;
  }
}

/** The generation does not fit the format's fixed-width limits. */
export class BundleCapacityError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = "BundleCapacityError";
  }
}
