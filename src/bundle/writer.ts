/**
 * The bundle writer. Used by the publisher, and by tests that need a bundle the
 * reader must agree with byte for byte.
 *
 * Emits, in order: the 64-byte header, the section table, INDX, CONN, GRUP with
 * its nested buckets, FILT, and the STRS arena holding every variable-length
 * value exactly once. The checksum is written last, over everything after the
 * header.
 *
 * Every offset comes from `./layout`, which is the document this module and the
 * reader both implement. There is no literal offset below.
 */

import { base64Decode, hexDecode, utf8Encode } from "../encoding.js";
import type {
  BundleHeaderInput,
  BundleInput,
  ConnectionInput,
  FilterInput,
  KeyGroup,
  SealedEnvelope,
  VisibleValue,
} from "../types.js";
import { BundleCapacityError, SEAL_ALGORITHM } from "../types.js";
import {
  BUCKET_ENTRY_BYTES,
  BUCKET_ENTRY_OFFSET,
  BUNDLE_MAGIC_BYTES,
  bucketEntryOffset,
  bucketOf,
  CHECKSUM_ALGORITHM,
  CHECKSUM_BYTES,
  CONN_MAX_FIELDS,
  CONN_OFFSET,
  CONN_RECORD_BYTES,
  connRecordOffset,
  FIELD_DESCRIPTOR_OFFSET,
  FILT_ENTRY_BYTES,
  FILT_ENTRY_OFFSET,
  fieldDescriptorOffset,
  filtEntryOffset,
  GRUP_OFFSET,
  GRUP_RECORD_BYTES,
  grupRecordOffset,
  HEADER_BYTES,
  HEADER_OFFSET,
  INDEX_EMPTY_SLOT,
  INDEX_SLOT_BYTES,
  INDEX_SLOT_OFFSET,
  indexSlotCount,
  indexSlotOffset,
  KEY_ID_BYTES,
  parseConnectionId,
  SECTION_ENTRY_BYTES,
  SECTION_ENTRY_OFFSET,
  SECTION_KIND,
  SECTION_TABLE_OFFSET,
  SHARD_PREFIX_BYTES,
  sectionEntryOffset,
  uuidHigh32,
  uuidLow32,
} from "./layout.js";

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/**
 * The largest bundle a shard will hold. An isolate budget rather than a format
 * limit — the format's own ceiling is its uint32 offsets, three orders of
 * magnitude further out. Exceeding it is refused rather than truncated, because
 * a truncated bundle is one that silently stops serving some connections.
 */
export const BUNDLE_MAX_BYTES = 10 * 1024 * 1024;

/** `eph_pub(32) || nonce(12) || tag(16)` — everything an envelope is but plaintext. */
const ENVELOPE_OVERHEAD_BYTES = 60;

/** INDX, CONN, GRUP, FILT, STRS. */
const SECTION_COUNT = 5;

/** K1's public half, sized by the gap the group record leaves for it. */
const GROUP_PUBLIC_KEY_BYTES = GRUP_OFFSET.GENERATION - GRUP_OFFSET.PUBLIC_KEY;

/** Field names are stored length-prefixed with a uint16. */
const FIELD_NAME_LENGTH_BYTES = 2;

/** The three value types a `visible` entry can carry. Shared with the reader. */
const VISIBLE_TYPE = {
  String: 0,
  Number: 1,
  Boolean: 2,
} as const;

/** `type u8 | key_len u16` in front of every visible key. */
const VISIBLE_ENTRY_HEADER_BYTES = 3;

/** A visible string's own `u32` length prefix. */
const VISIBLE_STRING_LENGTH_BYTES = 4;

/** A visible number is a little-endian `float64`. */
const VISIBLE_NUMBER_BYTES = 8;

const MAX_UINT16 = 0xffff;
const MAX_UINT32 = 0xffffffff;
const MAX_UINT64 = 2n ** 64n - 1n;

const SHARD_PATTERN = /^[a-z]{4}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KEY_ID_PATTERN = /^[0-9a-f]{32}$/;

// ---------------------------------------------------------------------------
// The STRS arena
// ---------------------------------------------------------------------------

/** One placed value and the absolute offset it will be copied to. */
interface ArenaChunk {
  readonly offset: number;
  readonly bytes: Uint8Array;
}

/**
 * The value arena.
 *
 * `interned` deduplicates immutable values — targets, visible blobs, field-name
 * tables, filter arguments, wrapped bucket entries — so a value repeated across
 * a slice is stored once. That is what "every variable-length value, once"
 * means.
 *
 * Mutable slots are deliberately excluded: a sealed field's bytes are
 * overwritten by its own plaintext on the first open, so two fields sharing one
 * region would read the other's write-back as corruption of a still-sealed
 * value.
 *
 * Nothing is aligned. Every value is reached through the shared `DataView` by
 * byte offset, so alignment would buy padding and nothing else.
 */
interface Arena {
  readonly base: number;
  readonly chunks: ArenaChunk[];
  readonly interned: Map<string, number>;
  cursor: number;
  entries: number;
}

function createArena(base: number): Arena {
  return { base, chunks: [], interned: new Map(), cursor: 0, entries: 0 };
}

/**
 * Reserve a zeroed region and return its absolute offset.
 *
 * Nothing is written: the output buffer is freshly allocated, so a reserved
 * region already holds the zeroes it is meant to.
 */
function arenaReserve(arena: Arena, byteLength: number): number {
  const offset = arena.base + arena.cursor;
  arena.cursor += byteLength;
  arena.entries += 1;
  return offset;
}

/** Place bytes that may later be mutated in place, and so are never shared. */
function arenaPlace(arena: Arena, bytes: Uint8Array): number {
  const offset = arenaReserve(arena, bytes.byteLength);
  arena.chunks.push({ offset, bytes });
  return offset;
}

/** Place bytes, reusing an identical value already in the arena. */
function arenaIntern(arena: Arena, bytes: Uint8Array): number {
  const key = interningKey(bytes);
  const existing = arena.interned.get(key);
  if (existing !== undefined) {
    return existing;
  }
  const offset = arenaPlace(arena, bytes);
  arena.interned.set(key, offset);
  return offset;
}

/**
 * A latin-1 view of the bytes, used only as a `Map` key.
 *
 * Chunked because spreading a multi-megabyte array into `fromCharCode` would
 * exceed the argument limit.
 */
function interningKey(bytes: Uint8Array): string {
  const chunkSize = 4096;
  let key = "";
  for (let start = 0; start < bytes.byteLength; start += chunkSize) {
    key += String.fromCharCode(...bytes.subarray(start, start + chunkSize));
  }
  return key;
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

/** One section-table entry, resolved. */
interface PlannedSection {
  readonly kind: number;
  readonly offset: number;
  readonly length: number;
  readonly count: number;
}

interface PlannedField {
  readonly strsOffset: number;
  readonly sealedLen: number;
}

interface PlannedConnection {
  readonly uuid: Uint8Array;
  readonly recordOffset: number;
  readonly groupIndex: number;
  readonly targetOffset: number;
  readonly targetLength: number;
  readonly visibleOffset: number;
  readonly visibleLength: number;
  readonly filterIndicesOffset: number;
  readonly filterCount: number;
  readonly expiresAt: bigint;
  readonly fieldNamesOffset: number;
  readonly fields: readonly PlannedField[];
}

interface PlannedBucketEntry {
  readonly keyId: Uint8Array;
  readonly wrappedOffset: number;
  readonly wrappedLength: number;
}

interface PlannedGroup {
  readonly id: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly generation: number;
  readonly bucketOffset: number;
  readonly bucket: readonly PlannedBucketEntry[];
  readonly privateKeyOffset: number;
  readonly privateKeyLength: number;
}

interface PlannedFilter {
  readonly kind: number;
  readonly argsOffset: number;
  readonly argsLength: number;
}

interface Plan {
  readonly header: BundleHeaderInput;
  readonly slots: number;
  readonly sections: readonly PlannedSection[];
  readonly indexOffset: number;
  readonly grupOffset: number;
  readonly filtOffset: number;
  readonly connections: readonly PlannedConnection[];
  readonly groups: readonly PlannedGroup[];
  readonly filters: readonly PlannedFilter[];
  readonly arena: readonly ArenaChunk[];
  readonly totalBytes: number;
}

/**
 * Resolve every offset without producing bytes.
 *
 * The fixed-width sections are sized from the counts alone, so the STRS base is
 * known before a single value is placed. That is what lets the arena hand out
 * absolute offsets in one pass, instead of placing everything relatively and
 * relocating afterwards.
 */
function planBundle(input: BundleInput): Plan {
  assertHeader(input.header);

  const slots = indexSlotCount(input.connections.length);
  const groupIndices = indexGroups(input.groups);

  const indexOffset = SECTION_TABLE_OFFSET + SECTION_COUNT * SECTION_ENTRY_BYTES;
  const indexLength = slots * INDEX_SLOT_BYTES;
  const connOffset = indexOffset + indexLength;
  const connLength = input.connections.length * CONN_RECORD_BYTES;
  const grupOffset = connOffset + connLength;
  const grupLength =
    input.groups.length * GRUP_RECORD_BYTES + countBucketEntries(input.groups) * BUCKET_ENTRY_BYTES;
  const filtOffset = grupOffset + grupLength;
  const filtLength = input.filters.length * FILT_ENTRY_BYTES;

  const arena = createArena(filtOffset + filtLength);
  const filters = planFilters(input.filters, arena);
  const groups = planGroups(input.groups, grupOffset, arena);
  const connections = planConnections(input, connOffset, groupIndices, arena);

  const totalBytes = arena.base + arena.cursor;
  if (totalBytes > BUNDLE_MAX_BYTES) {
    throw new BundleCapacityError(
      `bundle is ${totalBytes} bytes, over the ${BUNDLE_MAX_BYTES} byte limit`,
    );
  }

  return {
    header: input.header,
    slots,
    sections: [
      { kind: SECTION_KIND.INDX, offset: indexOffset, length: indexLength, count: slots },
      {
        kind: SECTION_KIND.CONN,
        offset: connOffset,
        length: connLength,
        count: input.connections.length,
      },
      {
        kind: SECTION_KIND.GRUP,
        offset: grupOffset,
        length: grupLength,
        count: input.groups.length,
      },
      {
        kind: SECTION_KIND.FILT,
        offset: filtOffset,
        length: filtLength,
        count: input.filters.length,
      },
      { kind: SECTION_KIND.STRS, offset: arena.base, length: arena.cursor, count: arena.entries },
    ],
    indexOffset,
    grupOffset,
    filtOffset,
    connections,
    groups,
    filters,
    arena: arena.chunks,
    totalBytes,
  };
}

function countBucketEntries(groups: readonly KeyGroup[]): number {
  let total = 0;
  for (const group of groups) {
    total += group.bucket.length;
  }
  return total;
}

/** Group id to its GRUP index, which is what a connection record stores. */
function indexGroups(groups: readonly KeyGroup[]): ReadonlyMap<string, number> {
  const indices = new Map<string, number>();
  for (const group of groups) {
    if (indices.has(group.groupId)) {
      throw new RangeError(`duplicate key group ${group.groupId}`);
    }
    indices.set(group.groupId, indices.size);
  }
  return indices;
}

function planFilters(filters: readonly FilterInput[], arena: Arena): readonly PlannedFilter[] {
  return filters.map((filter, index) => ({
    kind: assertUint32(`filter ${index} kind`, filter.kind),
    argsOffset: arenaIntern(arena, filter.args),
    argsLength: filter.args.byteLength,
  }));
}

function planGroups(
  groups: readonly KeyGroup[],
  grupSectionOffset: number,
  arena: Arena,
): readonly PlannedGroup[] {
  const planned: PlannedGroup[] = [];
  // Buckets nest inside GRUP, laid out after every fixed-width group record so a
  // record stays addressable by its index.
  let bucketCursor = grupSectionOffset + groups.length * GRUP_RECORD_BYTES;

  for (const group of groups) {
    const bucket = planBucket(group, arena);
    const privateKeyLength = widestWrapped(bucket);
    planned.push({
      id: uuidToBytes(`key group id "${group.groupId}"`, group.groupId),
      publicKey: assertByteLength(
        `key group ${group.groupId} public key`,
        group.publicKey,
        GROUP_PUBLIC_KEY_BYTES,
      ),
      // `KeyGroup.generation` is required, never defaulted. An absent counter
      // and a counter of zero are different claims and only the caller knows
      // which it means; substituting zero here would let a caller who dropped
      // the field publish a rotated group that reads as freshly minted, and
      // `generation` is what decides stale from corrupt.
      generation: assertUint32(`key group ${group.groupId} generation`, group.generation),
      bucketOffset: bucketCursor,
      bucket,
      // A dedicated scratch slot rather than one of the bucket entries: which
      // entry gets unwrapped depends on the API key presented, and opening the
      // private half into an entry would destroy the copy belonging to another
      // key. Sized by the widest entry, so the wrap's own overhead always covers
      // the private half written back into it.
      privateKeyOffset: arenaReserve(arena, privateKeyLength),
      privateKeyLength,
    });
    bucketCursor += bucket.length * BUCKET_ENTRY_BYTES;
  }
  return planned;
}

function planBucket(group: KeyGroup, arena: Arena): readonly PlannedBucketEntry[] {
  if (group.bucket.length === 0) {
    throw new RangeError(`key group ${group.groupId} has an empty bucket`);
  }
  const seen = new Set<string>();
  return group.bucket.map((entry) => {
    if (!KEY_ID_PATTERN.test(entry.keyId)) {
      throw new RangeError(
        `key id must be ${KEY_ID_BYTES * 2} lowercase hex characters, got "${entry.keyId}"`,
      );
    }
    if (seen.has(entry.keyId)) {
      throw new RangeError(`duplicate key id ${entry.keyId} in key group ${group.groupId}`);
    }
    seen.add(entry.keyId);
    return {
      keyId: hexDecode(entry.keyId),
      wrappedOffset: arenaIntern(arena, entry.wrapped),
      wrappedLength: entry.wrapped.byteLength,
    };
  });
}

function widestWrapped(bucket: readonly PlannedBucketEntry[]): number {
  let widest = 0;
  for (const entry of bucket) {
    widest = Math.max(widest, entry.wrappedLength);
  }
  return widest;
}

function planConnections(
  input: BundleInput,
  connSectionOffset: number,
  groupIndices: ReadonlyMap<string, number>,
  arena: Arena,
): readonly PlannedConnection[] {
  const seen = new Set<string>();
  return input.connections.map((connection, index) => {
    if (seen.has(connection.connectionId)) {
      throw new RangeError(`duplicate connection ${connection.connectionId}`);
    }
    seen.add(connection.connectionId);
    return planConnection(
      connection,
      connRecordOffset(connSectionOffset, index),
      groupIndices,
      input.filters.length,
      arena,
    );
  });
}

function planConnection(
  connection: ConnectionInput,
  recordOffset: number,
  groupIndices: ReadonlyMap<string, number>,
  filterCount: number,
  arena: Arena,
): PlannedConnection {
  const groupIndex = groupIndices.get(connection.groupId);
  if (groupIndex === undefined) {
    throw new RangeError(
      `connection ${connection.connectionId} names key group ${connection.groupId}, which is not in the bundle`,
    );
  }

  const sealed = Object.entries(connection.sealed);
  if (sealed.length > CONN_MAX_FIELDS) {
    throw new BundleCapacityError(
      `connection ${connection.connectionId} has ${sealed.length} sealed fields, over the ${CONN_MAX_FIELDS} a record holds`,
    );
  }
  const target = utf8Encode(connection.target);
  const visible = encodeVisible(connection);

  return {
    uuid: parseConnectionId(connection.connectionId).uuid,
    recordOffset,
    groupIndex,
    targetOffset: arenaIntern(arena, target),
    targetLength: target.byteLength,
    visibleOffset: arenaIntern(arena, visible),
    visibleLength: visible.byteLength,
    filterIndicesOffset: arenaIntern(arena, encodeFilterIndices(connection, filterCount)),
    filterCount: connection.filters?.length ?? 0,
    expiresAt: encodeExpiresAt(connection),
    fieldNamesOffset: arenaIntern(
      arena,
      encodeFieldNames(
        connection,
        sealed.map(([name]) => name),
      ),
    ),
    fields: sealed.map(([name, envelope]) => planField(connection, name, envelope, arena)),
  };
}

/**
 * One sealed field's slot.
 *
 * Placed rather than interned: the first open overwrites these bytes with the
 * plaintext, so the region has to belong to exactly one field.
 */
function planField(
  connection: ConnectionInput,
  name: string,
  envelope: SealedEnvelope,
  arena: Arena,
): PlannedField {
  const payload = envelopePayload(connection, name, envelope);
  return { strsOffset: arenaPlace(arena, payload), sealedLen: payload.byteLength };
}

/**
 * The envelope's payload, stripped of its algorithm prefix.
 *
 * The prefix is not stored: a bundle speaks one algorithm, and a per-field
 * algorithm string would be a negotiation this format does not have.
 */
function envelopePayload(
  connection: ConnectionInput,
  name: string,
  envelope: SealedEnvelope,
): Uint8Array {
  const separator = envelope.indexOf(":");
  if (envelope.slice(0, separator) !== SEAL_ALGORITHM) {
    throw new RangeError(
      `connection ${connection.connectionId} field "${name}": envelope algorithm must be ${SEAL_ALGORITHM}`,
    );
  }
  const payload = base64Decode(envelope.slice(separator + 1));
  if (payload.byteLength < ENVELOPE_OVERHEAD_BYTES) {
    throw new RangeError(
      `connection ${connection.connectionId} field "${name}": an envelope is at least ${ENVELOPE_OVERHEAD_BYTES} bytes, got ${payload.byteLength}`,
    );
  }
  return payload;
}

/**
 * The packed `visible` map: a run of `type u8 | key_len u16 | key utf8 | value`,
 * where the value is `len u32 || utf8` for a string, a `float64` for a number
 * and a `u8` for a boolean. Little-endian, unaligned, read through the shared
 * `DataView`.
 *
 * **Not JSON.** A shard reads this map on every request, before it touches any
 * secret, to route and to refuse. `JSON.parse` would materialise an object per
 * record on that path — the one thing `datamodel/bundle` forbids outright — and
 * would do it for the calls about to be refused as well as the ones that are
 * not. A packed scan answers `visible(name)` while allocating only the one
 * value asked for. `bundle/reader.ts` documents the same encoding; the two must
 * be changed together.
 */
function encodeVisible(connection: ConnectionInput): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const [name, value] of Object.entries(connection.visible)) {
    const key = utf8Encode(name);
    if (key.byteLength > MAX_UINT16) {
      throw new RangeError(
        `connection ${connection.connectionId} has a visible key of ${key.byteLength} bytes, over the ${MAX_UINT16} a length prefix holds`,
      );
    }
    const encoded = encodeVisibleValue(connection, name, value);
    const entry = new Uint8Array(VISIBLE_ENTRY_HEADER_BYTES + key.byteLength + encoded.byteLength);
    const view = new DataView(entry.buffer);
    view.setUint8(0, visibleType(value));
    view.setUint16(1, key.byteLength, true);
    entry.set(key, VISIBLE_ENTRY_HEADER_BYTES);
    entry.set(encoded, VISIBLE_ENTRY_HEADER_BYTES + key.byteLength);
    chunks.push(entry);
  }
  return concatBytes(chunks);
}

function visibleType(value: VisibleValue): number {
  if (typeof value === "boolean") {
    return VISIBLE_TYPE.Boolean;
  }
  return typeof value === "number" ? VISIBLE_TYPE.Number : VISIBLE_TYPE.String;
}

function encodeVisibleValue(
  connection: ConnectionInput,
  name: string,
  value: VisibleValue,
): Uint8Array {
  if (typeof value === "boolean") {
    return Uint8Array.of(value ? 1 : 0);
  }
  if (typeof value === "number") {
    // Refused rather than stored: a `float64` would round-trip a NaN or an
    // infinity faithfully, and a routing hint that is NaN is a publishing
    // mistake that must not reach a shard.
    if (!Number.isFinite(value)) {
      throw new RangeError(
        `connection ${connection.connectionId} visible "${name}" must be a finite number, got ${value}`,
      );
    }
    const bytes = new Uint8Array(VISIBLE_NUMBER_BYTES);
    new DataView(bytes.buffer).setFloat64(0, value, true);
    return bytes;
  }
  // No `u32` overflow guard on the value: `BUNDLE_MAX_BYTES` refuses the whole
  // bundle three orders of magnitude below 4 GiB, so a string long enough to
  // overflow this length prefix cannot reach a written buffer. A guard here
  // would be a branch no input can take.
  const text = utf8Encode(value);
  const bytes = new Uint8Array(VISIBLE_STRING_LENGTH_BYTES + text.byteLength);
  new DataView(bytes.buffer).setUint32(0, text.byteLength, true);
  bytes.set(text, VISIBLE_STRING_LENGTH_BYTES);
  return bytes;
}

function concatBytes(chunks: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) {
    total += chunk.byteLength;
  }
  const out = new Uint8Array(total);
  let cursor = 0;
  for (const chunk of chunks) {
    out.set(chunk, cursor);
    cursor += chunk.byteLength;
  }
  return out;
}

/**
 * `uint16 length || utf-8 name`, repeated `field_count` times.
 *
 * The record carries this table's offset but no length, so the encoding has to
 * be self-delimiting given the field count.
 */
function encodeFieldNames(connection: ConnectionInput, names: readonly string[]): Uint8Array {
  const encoded = names.map((name) => {
    const bytes = utf8Encode(name);
    if (bytes.byteLength > MAX_UINT16) {
      throw new RangeError(
        `connection ${connection.connectionId} has a field name of ${bytes.byteLength} bytes, over the ${MAX_UINT16} a length prefix holds`,
      );
    }
    return bytes;
  });

  let total = 0;
  for (const bytes of encoded) {
    total += FIELD_NAME_LENGTH_BYTES + bytes.byteLength;
  }
  const table = new Uint8Array(total);
  const view = new DataView(table.buffer);
  let cursor = 0;
  for (const bytes of encoded) {
    view.setUint16(cursor, bytes.byteLength, true);
    table.set(bytes, cursor + FIELD_NAME_LENGTH_BYTES);
    cursor += FIELD_NAME_LENGTH_BYTES + bytes.byteLength;
  }
  return table;
}

/** The connection's filter indices, as little-endian uint32s. */
function encodeFilterIndices(connection: ConnectionInput, filterCount: number): Uint8Array {
  const indices = connection.filters ?? [];
  const bytes = new Uint8Array(indices.length * Uint32Array.BYTES_PER_ELEMENT);
  const view = new DataView(bytes.buffer);
  indices.forEach((index, position) => {
    if (!Number.isInteger(index) || index < 0 || index >= filterCount) {
      throw new RangeError(
        `connection ${connection.connectionId} references filter ${index}, outside the ${filterCount} filters in the bundle`,
      );
    }
    view.setUint32(position * Uint32Array.BYTES_PER_ELEMENT, index, true);
  });
  return bytes;
}

/** Unix millis, with `0` standing for "does not expire". */
function encodeExpiresAt(connection: ConnectionInput): bigint {
  const expiresAt = connection.expiresAt;
  if (expiresAt === undefined || expiresAt === null) {
    return 0n;
  }
  if (!Number.isSafeInteger(expiresAt) || expiresAt < 0) {
    throw new RangeError(
      `connection ${connection.connectionId} expires_at must be non-negative unix millis, got ${expiresAt}`,
    );
  }
  return BigInt(expiresAt);
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

function assertHeader(header: BundleHeaderInput): void {
  if (!SHARD_PATTERN.test(header.shard)) {
    throw new RangeError(`shard must be four lowercase letters, got "${header.shard}"`);
  }
  if (!Number.isInteger(header.version) || header.version < 1 || header.version > MAX_UINT16) {
    throw new RangeError(`bundle version must be in [1, ${MAX_UINT16}], got ${header.version}`);
  }
  assertUint64("generation", header.generation);
  assertUint64("built_at", header.builtAt);
}

function assertUint64(name: string, value: bigint): void {
  if (value < 0n || value > MAX_UINT64) {
    throw new RangeError(`${name} must fit an unsigned 64-bit integer, got ${value}`);
  }
}

function assertUint32(name: string, value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > MAX_UINT32) {
    throw new RangeError(`${name} must fit an unsigned 32-bit integer, got ${value}`);
  }
  return value;
}

function assertByteLength(name: string, bytes: Uint8Array, expected: number): Uint8Array {
  if (bytes.byteLength !== expected) {
    throw new RangeError(`${name} must be ${expected} bytes, got ${bytes.byteLength}`);
  }
  return bytes;
}

/** A group id is a bare UUID: no shard prefix, unlike a connection id. */
function uuidToBytes(name: string, text: string): Uint8Array {
  if (!UUID_PATTERN.test(text)) {
    throw new RangeError(`${name} must be a lowercase UUID`);
  }
  return hexDecode(text.replaceAll("-", ""));
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

function emitBundle(plan: Plan): Uint8Array {
  const buffer = new Uint8Array(plan.totalBytes);
  const view = new DataView(buffer.buffer);
  emitHeader(buffer, view, plan);
  emitSectionTable(view, plan);
  emitIndex(view, plan);
  emitConnections(buffer, view, plan);
  emitGroups(buffer, view, plan);
  emitFilters(view, plan);
  emitArena(buffer, plan);
  return buffer;
}

function emitHeader(buffer: Uint8Array, view: DataView, plan: Plan): void {
  buffer.set(BUNDLE_MAGIC_BYTES, HEADER_OFFSET.MAGIC);
  view.setUint16(HEADER_OFFSET.VERSION, plan.header.version, true);
  view.setUint16(HEADER_OFFSET.FLAGS, 0, true);
  view.setBigUint64(HEADER_OFFSET.GENERATION, plan.header.generation, true);
  for (let index = 0; index < SHARD_PREFIX_BYTES; index += 1) {
    view.setUint8(HEADER_OFFSET.SHARD + index, plan.header.shard.charCodeAt(index));
  }
  view.setBigUint64(HEADER_OFFSET.BUILT_AT, plan.header.builtAt, true);
  view.setUint32(HEADER_OFFSET.SECTIONS, plan.sections.length, true);
  // The checksum stays zero here: it is stamped once the bytes it covers exist.
}

function emitSectionTable(view: DataView, plan: Plan): void {
  plan.sections.forEach((section, index) => {
    const at = sectionEntryOffset(index);
    view.setUint32(at + SECTION_ENTRY_OFFSET.KIND, section.kind, true);
    view.setUint32(at + SECTION_ENTRY_OFFSET.OFFSET, section.offset, true);
    view.setUint32(at + SECTION_ENTRY_OFFSET.LENGTH, section.length, true);
    view.setUint32(at + SECTION_ENTRY_OFFSET.COUNT, section.count, true);
  });
}

/**
 * Open addressing with linear probing.
 *
 * The load factor is at most 0.25 by construction, so a free slot always exists
 * and the probe terminates. A `CONN` offset of zero marks a free slot, which is
 * unambiguous because offset zero is the header's magic.
 */
function emitIndex(view: DataView, plan: Plan): void {
  const mask = plan.slots - 1;
  for (const connection of plan.connections) {
    let slot = bucketOf(uuidLow32(connection.uuid), plan.slots);
    while (
      view.getUint32(
        indexSlotOffset(plan.indexOffset, slot) + INDEX_SLOT_OFFSET.CONN_OFFSET,
        true,
      ) !== INDEX_EMPTY_SLOT
    ) {
      slot = (slot + 1) & mask;
    }
    const at = indexSlotOffset(plan.indexOffset, slot);
    view.setUint32(at + INDEX_SLOT_OFFSET.FINGERPRINT, uuidHigh32(connection.uuid), true);
    view.setUint32(at + INDEX_SLOT_OFFSET.CONN_OFFSET, connection.recordOffset, true);
  }
}

function emitConnections(buffer: Uint8Array, view: DataView, plan: Plan): void {
  for (const connection of plan.connections) {
    const at = connection.recordOffset;
    buffer.set(connection.uuid, at + CONN_OFFSET.ID);
    view.setUint32(at + CONN_OFFSET.GROUP_INDEX, connection.groupIndex, true);
    view.setUint32(at + CONN_OFFSET.TARGET_OFFSET, connection.targetOffset, true);
    view.setUint32(at + CONN_OFFSET.TARGET_LENGTH, connection.targetLength, true);
    view.setUint32(at + CONN_OFFSET.VISIBLE_OFFSET, connection.visibleOffset, true);
    view.setUint32(at + CONN_OFFSET.VISIBLE_LENGTH, connection.visibleLength, true);
    view.setUint32(at + CONN_OFFSET.FILTERS_OFFSET, connection.filterIndicesOffset, true);
    view.setUint32(at + CONN_OFFSET.FILTERS_COUNT, connection.filterCount, true);
    view.setBigUint64(at + CONN_OFFSET.EXPIRES_AT, connection.expiresAt, true);
    view.setUint32(at + CONN_OFFSET.FIELD_COUNT, connection.fields.length, true);
    view.setUint32(at + CONN_OFFSET.FIELD_NAMES_OFFSET, connection.fieldNamesOffset, true);
    view.setUint32(at + CONN_OFFSET.RESERVED, 0, true);
    connection.fields.forEach((field, index) => {
      emitFieldDescriptor(view, fieldDescriptorOffset(at, index), field);
    });
  }
}

/** Always written sealed: `plain_len` is zero and `state` is `0` until an open. */
function emitFieldDescriptor(view: DataView, at: number, field: PlannedField): void {
  view.setUint32(at + FIELD_DESCRIPTOR_OFFSET.STRS_OFFSET, field.strsOffset, true);
  view.setUint32(at + FIELD_DESCRIPTOR_OFFSET.SEALED_LEN, field.sealedLen, true);
  view.setUint32(at + FIELD_DESCRIPTOR_OFFSET.PLAIN_LEN, 0, true);
  view.setUint8(at + FIELD_DESCRIPTOR_OFFSET.STATE, 0);
}

function emitGroups(buffer: Uint8Array, view: DataView, plan: Plan): void {
  plan.groups.forEach((group, index) => {
    const at = grupRecordOffset(plan.grupOffset, index);
    buffer.set(group.id, at + GRUP_OFFSET.GROUP_ID);
    buffer.set(group.publicKey, at + GRUP_OFFSET.PUBLIC_KEY);
    view.setUint32(at + GRUP_OFFSET.GENERATION, group.generation, true);
    view.setUint32(at + GRUP_OFFSET.BUCKET_OFFSET, group.bucketOffset, true);
    view.setUint32(at + GRUP_OFFSET.BUCKET_COUNT, group.bucket.length, true);
    view.setUint32(at + GRUP_OFFSET.RESERVED, 0, true);
    emitFieldDescriptor(view, at + GRUP_OFFSET.PRIVATE_DESCRIPTOR, {
      strsOffset: group.privateKeyOffset,
      sealedLen: group.privateKeyLength,
    });
    emitBucket(buffer, view, group);
  });
}

function emitBucket(buffer: Uint8Array, view: DataView, group: PlannedGroup): void {
  group.bucket.forEach((entry, index) => {
    const at = bucketEntryOffset(group.bucketOffset, index);
    buffer.set(entry.keyId, at + BUCKET_ENTRY_OFFSET.KEY_ID);
    view.setUint32(at + BUCKET_ENTRY_OFFSET.WRAPPED_OFFSET, entry.wrappedOffset, true);
    view.setUint32(at + BUCKET_ENTRY_OFFSET.WRAPPED_LENGTH, entry.wrappedLength, true);
  });
}

function emitFilters(view: DataView, plan: Plan): void {
  plan.filters.forEach((filter, index) => {
    const at = filtEntryOffset(plan.filtOffset, index);
    view.setUint32(at + FILT_ENTRY_OFFSET.KIND, filter.kind, true);
    view.setUint32(at + FILT_ENTRY_OFFSET.ARGS_OFFSET, filter.argsOffset, true);
    view.setUint32(at + FILT_ENTRY_OFFSET.ARGS_LENGTH, filter.argsLength, true);
    view.setUint32(at + FILT_ENTRY_OFFSET.RESERVED, 0, true);
  });
}

function emitArena(buffer: Uint8Array, plan: Plan): void {
  for (const chunk of plan.arena) {
    buffer.set(chunk.bytes, chunk.offset);
  }
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/**
 * Serialise a whole shard generation.
 *
 * @throws {BundleCapacityError} when a connection carries more sealed fields
 *   than `CONN_MAX_FIELDS`, when the connection count exceeds what the index can
 *   address, or when the bundle would exceed `BUNDLE_MAX_BYTES`.
 * @throws {RangeError} on a malformed input: a shard prefix that is not four
 *   lowercase letters, a connection naming a group that is not in `groups`, an
 *   envelope with the wrong algorithm, or a filter index out of range.
 * @throws {BundleFormatError} propagated from `parseConnectionId`, when a
 *   connection id is not `<shard>_<uuid>`.
 */
export function writeBundle(input: BundleInput): Uint8Array {
  return emitBundle(planBundle(input));
}

/**
 * The exact byte length `writeBundle` will produce for an input.
 *
 * Separate from the write so a caller can size the pre-allocated ping-pong
 * buffers the shard reads into without serialising twice.
 */
export function measureBundle(input: BundleInput): number {
  return planBundle(input).totalBytes;
}

/**
 * Compute the 28-byte checksum over everything after the header.
 *
 * @param buffer the whole bundle, header included.
 */
export async function computeChecksum(buffer: Uint8Array): Promise<Uint8Array> {
  assertHeaderPresent(buffer);
  const digest = await globalThis.crypto.subtle.digest(
    CHECKSUM_ALGORITHM,
    digestSource(buffer.subarray(HEADER_BYTES)),
  );
  // Truncated rather than a different digest: 224 bits is what the header holds.
  return new Uint8Array(digest).slice(0, CHECKSUM_BYTES);
}

/**
 * Web Crypto's `BufferSource` excludes a view over a `SharedArrayBuffer`, whose
 * contents another thread could change mid-digest. A bundle read from the store
 * is backed by a plain `ArrayBuffer` and is digested where it lies; the shared
 * case is snapshotted instead, which is both what the API requires and what
 * makes the digest mean something.
 */
function digestSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const backing = bytes.buffer;
  return backing instanceof ArrayBuffer
    ? new Uint8Array(backing, bytes.byteOffset, bytes.byteLength)
    : new Uint8Array(bytes);
}

/**
 * Write a computed checksum into the header in place.
 *
 * Split from `writeBundle` because the digest is asynchronous under Web Crypto
 * while the serialisation is not.
 */
export function writeChecksum(buffer: Uint8Array, checksum: Uint8Array): void {
  assertHeaderPresent(buffer);
  assertByteLength("checksum", checksum, CHECKSUM_BYTES);
  buffer.set(checksum, HEADER_OFFSET.CHECKSUM);
}

function assertHeaderPresent(buffer: Uint8Array): void {
  if (buffer.byteLength < HEADER_BYTES) {
    throw new RangeError(`a bundle is at least ${HEADER_BYTES} bytes, got ${buffer.byteLength}`);
  }
}

/**
 * Serialise and stamp the checksum in one asynchronous call — what a publisher
 * actually wants.
 */
export async function writeBundleWithChecksum(input: BundleInput): Promise<Uint8Array> {
  const buffer = writeBundle(input);
  writeChecksum(buffer, await computeChecksum(buffer));
  return buffer;
}
