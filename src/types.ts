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
// API key
// ---------------------------------------------------------------------------

/** The environment segment of a displayed API key. */
export type ApiKeyEnvironment = "live" | "test";

/** Raw key material plus the display form it round-trips to. */
export interface ApiKeyMaterial {
  readonly environment: ApiKeyEnvironment;
  /** The 32 random bytes. **This**, never the display string, is the HKDF input. */
  readonly bytes: Uint8Array;
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

// ---------------------------------------------------------------------------
// Key groups and buckets
// ---------------------------------------------------------------------------

/** An X25519 keypair. The private half is returned once and never stored unwrapped. */
export interface GroupKeyPair {
  /** 32 bytes, raw. Public — sealing needs only this. */
  readonly publicKey: Uint8Array;
  /** 32 bytes, raw. */
  readonly privateKey: Uint8Array;
}

/**
 * One API key's copy of a group's private half.
 *
 * `keyId` is `HKDF(apiKey, salt=tenantId, info="socket0/v1/key-id", 16)` as 32
 * lowercase hex characters; it is stored in the clear in every bundle.
 * `wrapped` is the private half under `HKDF(..., info="socket0/v1/tmk-wrap", 32)`.
 */
export interface BucketEntry {
  readonly keyId: string;
  /** `nonce(12) || ciphertext(32) || tag(16)`, AAD = group id || key id. */
  readonly wrapped: Uint8Array;
}

/** A key group as it travels inside a bundle: public half plus the whole bucket. */
export interface KeyGroup {
  readonly groupId: string;
  /** K1 public half, 32 raw bytes. */
  readonly publicKey: Uint8Array;
  /** The group's own rotation counter, distinct from the bundle's generation. */
  readonly generation?: number;
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
 * Associated data. Always binds the identity of what is sealed — a field's
 * connection id and name, or a bucket entry's group id and key id — so an
 * envelope moved between slots fails to open even with the right key.
 */
export type AssociatedData = Uint8Array;

/** The identity a credential field's AAD binds. */
export interface FieldIdentity {
  readonly connectionId: string;
  readonly fieldName: string;
}

/** The identity a bucket entry's AAD binds. */
export interface BucketIdentity {
  readonly groupId: string;
  readonly keyId: string;
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
  /** The four-character shard prefix, ASCII. */
  readonly shard: string;
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

/** One bucket entry, read in place. `wrapped()` returns a view, never a copy. */
export interface BucketEntryView {
  readonly entryOffset: number;
  keyIdBytes(): Uint8Array;
  keyIdHex(): string;
  wrapped(): Uint8Array;
}

/** One key group, read in place. */
export interface KeyGroupView {
  readonly groupIndex: number;
  readonly recordOffset: number;
  groupIdBytes(): Uint8Array;
  groupId(): string;
  publicKey(): Uint8Array;
  generation(): number;
  readonly bucketSize: number;
  bucketEntry(index: number): BucketEntryView | undefined;
  findBucketEntry(keyId: string): BucketEntryView | undefined;
  /** The descriptor for K1's wrapped private half, cached the same way a field is. */
  privateKeyDescriptor(): FieldDescriptor;
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
  idBytes(): Uint8Array;
  /** Full sixteen-byte comparison; the index fingerprint is a filter, not a proof. */
  matchesId(id: Uint8Array): boolean;
  target(): string;
  visibleKeys(): readonly string[];
  visible(name: string): string | number | boolean | undefined;
  /** Unix millis, or `null` when the connection does not expire. */
  expiresAt(): number | null;
  /** Indices into the FILT section. */
  filterIndices(): Uint32Array;
  fieldNames(): readonly string[];
  field(name: string): FieldDescriptor | undefined;
  /**
   * The current bytes of a field: the envelope while `state === Sealed`, the
   * plaintext once it is `Open`. A view into the buffer, never a copy.
   */
  fieldBytes(descriptor: FieldDescriptor): Uint8Array;
}

/** A filter's constructor arguments, read at call time and never instantiated. */
export interface FilterArgsView {
  readonly filterIndex: number;
  readonly kind: number;
  args(): Uint8Array;
}

/**
 * What `readBundle` returns. A set of accessors over the caller's buffer — no
 * deserialisation, no object per record, no copy.
 */
export interface BundleView {
  readonly header: BundleHeader;
  /** The buffer being read. Held so a write-back lands where the read started. */
  readonly buffer: Uint8Array;
  section(kind: SectionKindName): SectionEntry | undefined;
  /** Verified once at load, and never again: write-back invalidates it by design. */
  verifyChecksum(): Promise<boolean>;
  readonly connectionCount: number;
  readonly groupCount: number;
  /** One masked slot read, a fingerprint compare, then a full id verify. */
  lookup(connectionId: string): ConnectionRecord | undefined;
  connectionAt(recordOffset: number): ConnectionRecord;
  group(index: number): KeyGroupView | undefined;
  groupById(groupId: string): KeyGroupView | undefined;
  filter(index: number): FilterArgsView | undefined;
  /**
   * Write plaintext into the slot its own ciphertext occupied: bytes, then
   * `plain_len`, then `state` — in one synchronous block, flag published last.
   * An envelope is always exactly 60 bytes larger than its plaintext, so it fits.
   */
  writeBack(descriptor: FieldDescriptor, plaintext: Uint8Array): FieldDescriptor;
}

// ---------------------------------------------------------------------------
// Bundle: the writer's input (the logical form of schema.json)
// ---------------------------------------------------------------------------

/** Configuration readable with no key at all. */
export type VisibleValue = string | number | boolean;

export interface BundleHeaderInput {
  readonly version: number;
  readonly generation: bigint;
  /** Exactly four lowercase ASCII letters. */
  readonly shard: string;
  /** Unix millis. */
  readonly builtAt: bigint;
}

export interface ConnectionInput {
  /** Shard prefix then UUIDv7. Its low 32 bits address the bucket. */
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

/** A display string is not a well-formed API key. Carries the machine reason. */
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

/** A higher `version` than this reader knows. Refuse the whole bundle. */
export class UnsupportedBundleVersionError extends VaultError {
  readonly found: number;
  readonly supported: number;
  constructor(found: number, supported: number) {
    super(`bundle version ${found} is newer than the supported version ${supported}`);
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
