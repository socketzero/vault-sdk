/**
 * The binary layout of a bundle (`product/vault-sdk/datamodel/bundle`).
 *
 * Constants and offset arithmetic only — no reads, no writes, no state. The
 * writer and the reader are two implementations of the same document and this
 * module is the document.
 *
 * Little-endian throughout. All offsets are absolute byte offsets from the
 * start of the buffer; all lengths are in bytes.
 *
 *     +-----------------------------------------------------------------+
 *     | HEADER            64 bytes, fixed                               |
 *     | SECTION TABLE     16 bytes per section                          |
 *     | INDX  bucket table   open-addressed, power-of-two, 8 B slots    |
 *     | CONN  connection records   fixed width, referenced by INDX      |
 *     | GRUP  key groups        public half + bucket, per group         |
 *     | FILT  filter arguments  read at call time, never instantiated   |
 *     | STRS  value arena       every variable-length value, once       |
 *     +-----------------------------------------------------------------+
 */

import { BundleCapacityError, BundleFormatError, type SectionKindName } from "../types.js";

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/** `"S0BUNDLE"`, the first eight bytes. */
export const BUNDLE_MAGIC = "S0BUNDLE";
/** The magic as bytes, for a comparison that does not decode. */
export const BUNDLE_MAGIC_BYTES: Uint8Array = new Uint8Array([
  0x53, 0x30, 0x42, 0x55, 0x4e, 0x44, 0x4c, 0x45,
]);
/** The version this build writes and is the highest it will read. */
export const BUNDLE_VERSION = 1;
/** Fixed. */
export const HEADER_BYTES = 64;

/** Offsets within the header. */
export const HEADER_OFFSET = {
  MAGIC: 0, // 8 bytes, ASCII
  VERSION: 8, // uint16
  FLAGS: 10, // uint16, reserved, must be zero
  GENERATION: 12, // uint64, monotonic, from the compiler
  SHARD: 20, // 4 bytes, ASCII, the shard prefix
  BUILT_AT: 24, // uint64, unix millis, advisory only
  SECTIONS: 32, // uint32, count of section-table descriptors
  CHECKSUM: 36, // 28 bytes, over everything after the header
} as const;

/** 28 bytes: SHA-256 over everything after the header, truncated. */
export const CHECKSUM_BYTES = 28;
/**
 * The digest the checksum truncates. It detects truncation and corruption and
 * is **not** an authenticity control: it is unkeyed, so anyone who can write to
 * the store can produce a valid one. Verified once at load and never again,
 * because a write-back deliberately invalidates it.
 */
export const CHECKSUM_ALGORITHM = "SHA-256";
/** The shard prefix is exactly four ASCII letters. */
export const SHARD_PREFIX_BYTES = 4;

// ---------------------------------------------------------------------------
// Section table
// ---------------------------------------------------------------------------

/** `kind 4 | offset 4 | length 4 | count 4`. */
export const SECTION_ENTRY_BYTES = 16;

export const SECTION_ENTRY_OFFSET = {
  KIND: 0, // uint32, the four ASCII characters little-endian
  OFFSET: 4, // uint32, absolute
  LENGTH: 8, // uint32
  COUNT: 12, // uint32, records in the section
} as const;

/**
 * Section kinds as uint32, being the four ASCII characters read little-endian.
 * An unknown kind is skipped by the table walk and does not need a version bump.
 */
export const SECTION_KIND = {
  INDX: 0x58444e49,
  CONN: 0x4e4e4f43,
  GRUP: 0x50555247,
  FILT: 0x544c4946,
  STRS: 0x53525453,
} as const satisfies Record<SectionKindName, number>;

/** The section table starts immediately after the header. */
export const SECTION_TABLE_OFFSET = HEADER_BYTES;

// ---------------------------------------------------------------------------
// INDX
// ---------------------------------------------------------------------------

/** `fingerprint uint32 || CONN offset uint32`. */
export const INDEX_SLOT_BYTES = 8;

export const INDEX_SLOT_OFFSET = {
  FINGERPRINT: 0, // uint32, uuid_high32
  CONN_OFFSET: 4, // uint32, absolute; 0 means empty
} as const;

/** An offset of zero means the slot is empty; the header occupies offset 0. */
export const INDEX_EMPTY_SLOT = 0;
/** `2^k >= 4 x connection_count`, so the load factor stays at or below 0.25. */
export const INDEX_MIN_SLOTS_PER_CONNECTION = 4;
/**
 * The floor, so that an empty or single-connection shard still has a table to
 * mask into. `slots - 1` must be a usable mask, and a one-slot table would make
 * every id collide with every other as soon as a second connection arrived.
 */
export const INDEX_MIN_SLOTS = 8;
/** A full shard: 262,144 slots, 2 MiB, roughly 51,000 connections. */
export const INDEX_MAX_SLOTS = 262144;
/** The connection id's UUID part is sixteen bytes; all sixteen are verified on a hit. */
export const CONNECTION_ID_BYTES = 16;

// ---------------------------------------------------------------------------
// CONN
// ---------------------------------------------------------------------------

/**
 * The fixed-width part of a connection record, before its field descriptors.
 * Fixed width is what makes a record addressable by the index.
 */
export const CONN_HEADER_BYTES = 64;

export const CONN_OFFSET = {
  ID: 0, // 16 bytes, the UUID
  GROUP_INDEX: 16, // uint32, index into GRUP
  TARGET_OFFSET: 20, // uint32, into STRS
  TARGET_LENGTH: 24, // uint32
  VISIBLE_OFFSET: 28, // uint32, into STRS
  VISIBLE_LENGTH: 32, // uint32
  FILTERS_OFFSET: 36, // uint32, into FILT indices
  FILTERS_COUNT: 40, // uint32
  EXPIRES_AT: 44, // uint64, unix millis; 0 means null
  FIELD_COUNT: 52, // uint32
  FIELD_NAMES_OFFSET: 56, // uint32, into STRS
  RESERVED: 60, // uint32, must be zero
} as const;

/** Descriptors per record. Fixed, because the record must be fixed width. */
export const CONN_MAX_FIELDS = 8;
/** `64 + 8 * 16`. */
export const CONN_RECORD_BYTES = CONN_HEADER_BYTES + CONN_MAX_FIELDS * 16;

// ---------------------------------------------------------------------------
// Field descriptors
// ---------------------------------------------------------------------------

/** `strs_offset 4 | sealed_len 4 | plain_len 4 | state 1 | pad 3`. */
export const FIELD_DESCRIPTOR_BYTES = 16;

export const FIELD_DESCRIPTOR_OFFSET = {
  STRS_OFFSET: 0, // uint32
  SEALED_LEN: 4, // uint32
  PLAIN_LEN: 8, // uint32
  STATE: 12, // uint8, 0 sealed / 1 open. Published LAST.
  PAD: 13, // 3 bytes, must be zero
} as const;

// ---------------------------------------------------------------------------
// GRUP
// ---------------------------------------------------------------------------

/** Group record, carrying the same descriptor shape for K1's private half. */
export const GRUP_RECORD_BYTES = 80;

export const GRUP_OFFSET = {
  GROUP_ID: 0, // 16 bytes, the UUID
  PUBLIC_KEY: 16, // 32 bytes, K1's public half, in the clear
  GENERATION: 48, // uint32, the group's own rotation counter
  BUCKET_OFFSET: 52, // uint32, absolute, to the first bucket entry
  BUCKET_COUNT: 56, // uint32
  RESERVED: 60, // uint32, must be zero
  PRIVATE_DESCRIPTOR: 64, // 16 bytes, the descriptor for the wrapped private half
} as const;

/** `key_id 16 | wrapped_offset 4 | wrapped_len 4`. */
export const BUCKET_ENTRY_BYTES = 24;

export const BUCKET_ENTRY_OFFSET = {
  KEY_ID: 0, // 16 bytes
  WRAPPED_OFFSET: 16, // uint32, into STRS
  WRAPPED_LENGTH: 20, // uint32
} as const;

/** `key_id` is 16 bytes in the bundle, 32 hex characters in the API. */
export const KEY_ID_BYTES = 16;

// ---------------------------------------------------------------------------
// FILT
// ---------------------------------------------------------------------------

/** `kind 4 | args_offset 4 | args_len 4 | pad 4`. */
export const FILT_ENTRY_BYTES = 16;

export const FILT_ENTRY_OFFSET = {
  KIND: 0, // uint32
  ARGS_OFFSET: 4, // uint32, into STRS
  ARGS_LENGTH: 8, // uint32
  RESERVED: 12, // uint32, must be zero
} as const;

// ---------------------------------------------------------------------------
// Offset arithmetic
// ---------------------------------------------------------------------------

/**
 * A power of two has exactly one bit set, and `n & (n - 1)` clears that bit.
 * The integer and range checks come first because `&` silently truncates to
 * int32: without them `8.5` and `2 ** 32 + 8` would both answer yes.
 */
function isPowerOfTwo(value: number): boolean {
  return (
    Number.isInteger(value) && value > 0 && value <= MAX_POWER_OF_TWO && (value & (value - 1)) === 0
  );
}

/** The largest power of two that survives a bitwise `&` as a positive int32. */
const MAX_POWER_OF_TWO = 0x40000000;

/** Section kinds are four ASCII characters read as a uint32; nothing else fits. */
function assertUint32(name: string, value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new BundleFormatError(`${name} must be a uint32, got ${value}`);
  }
}

/**
 * Reading four big-endian bytes through a `DataView` rather than by indexing.
 * Indexing a `Uint8Array` under `noUncheckedIndexedAccess` yields `number |
 * undefined` and would need a coalesce per byte — a branch that can never be
 * taken once the length is checked, which is worse than one view.
 */
function readUint32BE(bytes: Uint8Array, byteOffset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(
    byteOffset,
    false,
  );
}

function assertUuidBytes(id: Uint8Array): void {
  if (id.byteLength !== CONNECTION_ID_BYTES) {
    throw new BundleFormatError(
      `a connection id is ${CONNECTION_ID_BYTES} bytes, got ${id.byteLength}`,
    );
  }
}

/** The smallest power of two that is at least `4 x connectionCount`, minimum 8. */
export function indexSlotCount(connectionCount: number): number {
  if (!Number.isInteger(connectionCount) || connectionCount < 0) {
    throw new BundleFormatError(
      `connection count must be a non-negative integer, got ${connectionCount}`,
    );
  }
  const required = Math.max(connectionCount * INDEX_MIN_SLOTS_PER_CONNECTION, INDEX_MIN_SLOTS);
  // Checked before rounding up, so the shift below can never overflow int32.
  if (required > INDEX_MAX_SLOTS) {
    throw new BundleCapacityError(
      `${connectionCount} connections need more than the ${INDEX_MAX_SLOTS} index slots a shard has`,
    );
  }
  // `required >= 8`, so `required - 1` is positive and `clz32` is meaningful.
  return 1 << (32 - Math.clz32(required - 1));
}

/**
 * `bucket = uuid_low32 & (slots - 1)`.
 *
 * No hash function is evaluated. A UUIDv7's low bits are already uniform; its
 * high bits are a timestamp and would cluster every id minted in the same
 * millisecond.
 */
export function bucketOf(uuidLow32: number, slots: number): number {
  assertUint32("uuid_low32", uuidLow32);
  if (!isPowerOfTwo(slots)) {
    throw new BundleFormatError(`the index slot count must be a power of two, got ${slots}`);
  }
  return uuidLow32 & (slots - 1);
}

/** The last four bytes of the UUID, big-endian, as an unsigned 32-bit number. */
export function uuidLow32(id: Uint8Array): number {
  assertUuidBytes(id);
  return readUint32BE(id, CONNECTION_ID_BYTES - 4);
}

/**
 * The first four bytes of the UUID, big-endian. Drawn from different bits than
 * the bucket, so the fingerprint is an independent check.
 */
export function uuidHigh32(id: Uint8Array): number {
  assertUuidBytes(id);
  return readUint32BE(id, 0);
}

/** Absolute offset of index slot `slot`. */
export function indexSlotOffset(indexSectionOffset: number, slot: number): number {
  return indexSectionOffset + slot * INDEX_SLOT_BYTES;
}

/** Absolute offset of section-table entry `entryIndex`. */
export function sectionEntryOffset(entryIndex: number): number {
  return SECTION_TABLE_OFFSET + entryIndex * SECTION_ENTRY_BYTES;
}

/** Absolute offset of connection record `recordIndex` within the CONN section. */
export function connRecordOffset(connSectionOffset: number, recordIndex: number): number {
  return connSectionOffset + recordIndex * CONN_RECORD_BYTES;
}

/**
 * Absolute offset of field descriptor `fieldIndex` inside a connection record.
 *
 * Bounded, unlike the other offset helpers: a record is fixed width precisely so
 * the index can address it, and an out-of-range field index would silently point
 * into the *next* connection's id rather than fail.
 */
export function fieldDescriptorOffset(recordOffset: number, fieldIndex: number): number {
  if (!Number.isInteger(fieldIndex) || fieldIndex < 0 || fieldIndex >= CONN_MAX_FIELDS) {
    throw new BundleFormatError(
      `field index must be in [0, ${CONN_MAX_FIELDS}), got ${fieldIndex}`,
    );
  }
  return recordOffset + CONN_HEADER_BYTES + fieldIndex * FIELD_DESCRIPTOR_BYTES;
}

/** Absolute offset of group record `groupIndex` within the GRUP section. */
export function grupRecordOffset(grupSectionOffset: number, groupIndex: number): number {
  return grupSectionOffset + groupIndex * GRUP_RECORD_BYTES;
}

/** Absolute offset of bucket entry `entryIndex` within a group's bucket. */
export function bucketEntryOffset(bucketOffset: number, entryIndex: number): number {
  return bucketOffset + entryIndex * BUCKET_ENTRY_BYTES;
}

/** Absolute offset of filter entry `filterIndex` within the FILT section. */
export function filtEntryOffset(filtSectionOffset: number, filterIndex: number): number {
  return filtSectionOffset + filterIndex * FILT_ENTRY_BYTES;
}

/** `<shard>_<canonical uuid>`, the only form a connection id is ever written in. */
const CONNECTION_ID_PATTERN =
  /^([a-z]{4})_([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$/;

/** Split a `<shard>_<uuid>` connection id into its prefix and sixteen UUID bytes. */
export function parseConnectionId(connectionId: string): {
  shard: string;
  uuid: Uint8Array;
} {
  const match = CONNECTION_ID_PATTERN.exec(connectionId);
  if (match === null) {
    throw new BundleFormatError(
      "a connection id is four lowercase letters, an underscore, then a UUID",
    );
  }
  // Group 1 is the shard; groups 2..6 are the UUID's hex runs, which concatenate
  // to exactly 32 characters. `replaceAll` on the tail is simpler than joining
  // the groups back up and cannot reintroduce a separator the pattern rejected.
  const shard = connectionId.slice(0, SHARD_PREFIX_BYTES);
  const hex = connectionId.slice(SHARD_PREFIX_BYTES + 1).replaceAll("-", "");
  const uuid = new Uint8Array(CONNECTION_ID_BYTES);
  for (let i = 0; i < CONNECTION_ID_BYTES; i += 1) {
    uuid[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return { shard, uuid };
}

/** Printable ASCII, so a corrupt kind cannot smuggle control characters into a log. */
function isPrintableAscii(code: number): boolean {
  return code >= 0x20 && code <= 0x7e;
}

/** The four ASCII characters of a section kind, for diagnostics. */
export function sectionKindName(kind: number): string {
  assertUint32("section kind", kind);
  let name = "";
  for (let shift = 0; shift < 32; shift += 8) {
    const code = (kind >>> shift) & 0xff;
    name += isPrintableAscii(code) ? String.fromCharCode(code) : "?";
  }
  return name;
}
