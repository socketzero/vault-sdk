/**
 * Reader tests.
 *
 * The bundles here are built byte by byte from `layout.ts`, not by `writeBundle`:
 * the reader and the writer are two independent implementations of one document,
 * and a test that used the writer would only prove they agree with each other.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  BundleFormatError,
  FieldState,
  UnsupportedBundleVersionError,
  type VisibleValue,
} from "../types.js";
import {
  BUNDLE_MAGIC_BYTES,
  BUNDLE_VERSION,
  CONN_HEADER_BYTES,
  CONN_OFFSET,
  CONN_RECORD_BYTES,
  FIELD_DESCRIPTOR_BYTES,
  FIELD_DESCRIPTOR_OFFSET,
  GRUP_OFFSET,
  GRUP_RECORD_BYTES,
  HEADER_BYTES,
  HEADER_OFFSET,
  INDEX_SLOT_BYTES,
  indexSlotCount,
  SECTION_ENTRY_BYTES,
  SECTION_ENTRY_OFFSET,
  SECTION_KIND,
  SECTION_TABLE_OFFSET,
} from "./layout.js";
import {
  decoyUnwrap,
  readBundle,
  readFieldDescriptor,
  writeBackPlaintext,
  zeroTail,
} from "./reader.js";

// ---------------------------------------------------------------------------
// A bundle builder, from the layout constants alone
// ---------------------------------------------------------------------------

const SHARD = "aaaa";
const TEXT = new TextEncoder();

interface TestField {
  readonly name: string;
  readonly sealed: Uint8Array;
}

interface TestConnection {
  readonly uuid: string;
  readonly groupIndex: number;
  readonly target: string;
  readonly visible: Readonly<Record<string, VisibleValue>>;
  readonly fields: readonly TestField[];
  readonly filters: readonly number[];
  readonly expiresAt: bigint;
}

interface TestBucketEntry {
  readonly keyId: string;
  readonly wrapped: Uint8Array;
}

interface TestGroup {
  readonly groupId: string;
  readonly publicKey: Uint8Array;
  readonly generation: number;
  readonly bucket: readonly TestBucketEntry[];
  readonly privateWrapped: Uint8Array;
}

interface BuildOptions {
  readonly connections?: readonly TestConnection[];
  readonly groups?: readonly TestGroup[];
  readonly filters?: ReadonlyArray<{ kind: number; args: Uint8Array }>;
  readonly omit?: readonly (keyof typeof SECTION_KIND)[];
  readonly shard?: string;
  readonly version?: number;
  readonly flags?: number;
}

interface BuiltBundle {
  readonly bytes: Uint8Array<ArrayBuffer>;
  readonly connOffset: number;
  readonly connLength: number;
  readonly indexOffset: number;
  readonly slots: number;
  readonly recordOffsets: readonly number[];
}

/** `high32` then eight zero bytes then `low32`, formatted 8-4-4-4-12. */
function makeUuid(high32: number, low32: number): string {
  const hex = `${high32.toString(16).padStart(8, "0")}0000000000000000${low32
    .toString(16)
    .padStart(8, "0")}`;
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function uuidBytes(uuid: string): Uint8Array {
  const hex = uuid.replaceAll("-", "");
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** `type u8 | key_len u16 | key utf8 | value`, the encoding reader.ts documents. */
function encodeVisible(map: Readonly<Record<string, VisibleValue>>): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const [key, value] of Object.entries(map)) {
    const keyBytes = TEXT.encode(key);
    const head = new Uint8Array(3 + keyBytes.byteLength);
    const headView = new DataView(head.buffer);
    headView.setUint16(1, keyBytes.byteLength, true);
    head.set(keyBytes, 3);
    if (typeof value === "string") {
      const valueBytes = TEXT.encode(value);
      headView.setUint8(0, 0);
      const tail = new Uint8Array(4 + valueBytes.byteLength);
      new DataView(tail.buffer).setUint32(0, valueBytes.byteLength, true);
      tail.set(valueBytes, 4);
      parts.push(head, tail);
    } else if (typeof value === "number") {
      headView.setUint8(0, 1);
      const tail = new Uint8Array(8);
      new DataView(tail.buffer).setFloat64(0, value, true);
      parts.push(head, tail);
    } else {
      headView.setUint8(0, 2);
      parts.push(head, Uint8Array.of(value ? 1 : 0));
    }
  }
  return concat(parts);
}

/** `name_len u16 | name utf8`, per name. */
function encodeFieldNames(fields: readonly TestField[]): Uint8Array {
  return concat(
    fields.map((field) => {
      const name = TEXT.encode(field.name);
      const out = new Uint8Array(2 + name.byteLength);
      new DataView(out.buffer).setUint16(0, name.byteLength, true);
      out.set(name, 2);
      return out;
    }),
  );
}

function encodeFilterIndices(indices: readonly number[]): Uint8Array {
  const out = new Uint8Array(indices.length * 4);
  const view = new DataView(out.buffer);
  indices.forEach((value, i) => {
    view.setUint32(i * 4, value, true);
  });
  return out;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const out = new Uint8Array(total);
  let cursor = 0;
  for (const part of parts) {
    out.set(part, cursor);
    cursor += part.byteLength;
  }
  return out;
}

function buildBundle(options: BuildOptions = {}): BuiltBundle {
  const connections = options.connections ?? [];
  const groups = options.groups ?? [];
  const filters = options.filters ?? [];
  const omit = new Set<string>(options.omit ?? []);

  const slots = indexSlotCount(connections.length);
  const tableBytes = 5 * SECTION_ENTRY_BYTES;
  const indexOffset = SECTION_TABLE_OFFSET + tableBytes;
  const indexLength = slots * INDEX_SLOT_BYTES;
  const connOffset = indexOffset + indexLength;
  const connLength = connections.length * CONN_RECORD_BYTES;
  const grupOffset = connOffset + connLength;
  const bucketTotal = groups.reduce((sum, group) => sum + group.bucket.length, 0);
  const grupLength = groups.length * GRUP_RECORD_BYTES + bucketTotal * 24;
  const filtOffset = grupOffset + grupLength;
  const filtLength = filters.length * 16;
  const strsOffset = filtOffset + filtLength;

  // The arena, laid out first so every record can point at an absolute offset.
  const arena: Uint8Array[] = [];
  let strsCursor = strsOffset;
  const place = (chunk: Uint8Array): number => {
    const at = strsCursor;
    arena.push(chunk);
    strsCursor += chunk.byteLength;
    return at;
  };

  const connBlobs = connections.map((connection) => ({
    target: place(TEXT.encode(connection.target)),
    targetLength: TEXT.encode(connection.target).byteLength,
    visible: place(encodeVisible(connection.visible)),
    visibleLength: encodeVisible(connection.visible).byteLength,
    filters: place(encodeFilterIndices(connection.filters)),
    names: place(encodeFieldNames(connection.fields)),
    fields: connection.fields.map((field) => place(field.sealed)),
  }));
  const grupBlobs = groups.map((group) => ({
    wrapped: group.bucket.map((entry) => place(entry.wrapped)),
    priv: place(group.privateWrapped),
  }));
  const filtBlobs = filters.map((entry) => place(entry.args));

  const strsLength = strsCursor - strsOffset;
  const bytes = new Uint8Array(strsOffset + strsLength);
  const view = new DataView(bytes.buffer);

  // ---- header
  bytes.set(BUNDLE_MAGIC_BYTES, HEADER_OFFSET.MAGIC);
  view.setUint16(HEADER_OFFSET.VERSION, options.version ?? BUNDLE_VERSION, true);
  view.setUint16(HEADER_OFFSET.FLAGS, options.flags ?? 0, true);
  view.setBigUint64(HEADER_OFFSET.GENERATION, 42n, true);
  bytes.set(TEXT.encode(options.shard ?? SHARD), HEADER_OFFSET.SHARD);
  view.setBigUint64(HEADER_OFFSET.BUILT_AT, 1_700_000_000_000n, true);

  // ---- section table
  const table: ReadonlyArray<readonly [string, number, number, number]> = [
    ["INDX", indexOffset, indexLength, slots],
    ["CONN", connOffset, connLength, connections.length],
    ["GRUP", grupOffset, grupLength, groups.length],
    ["FILT", filtOffset, filtLength, filters.length],
    ["STRS", strsOffset, strsLength, 1],
  ];
  let entryIndex = 0;
  for (const [name, offset, length, count] of table) {
    if (omit.has(name)) {
      continue;
    }
    const at = SECTION_TABLE_OFFSET + entryIndex * SECTION_ENTRY_BYTES;
    view.setUint32(at + SECTION_ENTRY_OFFSET.KIND, SECTION_KIND[name as "INDX"], true);
    view.setUint32(at + SECTION_ENTRY_OFFSET.OFFSET, offset, true);
    view.setUint32(at + SECTION_ENTRY_OFFSET.LENGTH, length, true);
    view.setUint32(at + SECTION_ENTRY_OFFSET.COUNT, count, true);
    entryIndex += 1;
  }
  view.setUint32(HEADER_OFFSET.SECTIONS, entryIndex, true);

  // ---- CONN + INDX
  const recordOffsets: number[] = [];
  connections.forEach((connection, i) => {
    const recordOffset = connOffset + i * CONN_RECORD_BYTES;
    recordOffsets.push(recordOffset);
    const blob = connBlobs[i] as (typeof connBlobs)[number];
    const id = uuidBytes(connection.uuid);
    bytes.set(id, recordOffset + CONN_OFFSET.ID);
    view.setUint32(recordOffset + CONN_OFFSET.GROUP_INDEX, connection.groupIndex, true);
    view.setUint32(recordOffset + CONN_OFFSET.TARGET_OFFSET, blob.target, true);
    view.setUint32(recordOffset + CONN_OFFSET.TARGET_LENGTH, blob.targetLength, true);
    view.setUint32(recordOffset + CONN_OFFSET.VISIBLE_OFFSET, blob.visible, true);
    view.setUint32(recordOffset + CONN_OFFSET.VISIBLE_LENGTH, blob.visibleLength, true);
    view.setUint32(recordOffset + CONN_OFFSET.FILTERS_OFFSET, blob.filters, true);
    view.setUint32(recordOffset + CONN_OFFSET.FILTERS_COUNT, connection.filters.length, true);
    view.setBigUint64(recordOffset + CONN_OFFSET.EXPIRES_AT, connection.expiresAt, true);
    view.setUint32(recordOffset + CONN_OFFSET.FIELD_COUNT, connection.fields.length, true);
    view.setUint32(recordOffset + CONN_OFFSET.FIELD_NAMES_OFFSET, blob.names, true);
    connection.fields.forEach((field, f) => {
      const at = recordOffset + CONN_HEADER_BYTES + f * FIELD_DESCRIPTOR_BYTES;
      view.setUint32(at + FIELD_DESCRIPTOR_OFFSET.STRS_OFFSET, blob.fields[f] as number, true);
      view.setUint32(at + FIELD_DESCRIPTOR_OFFSET.SEALED_LEN, field.sealed.byteLength, true);
    });

    // Open addressing: mask, then probe linearly to the first empty slot.
    const idView = new DataView(id.buffer);
    let slot = idView.getUint32(12, false) & (slots - 1);
    while (view.getUint32(indexOffset + slot * INDEX_SLOT_BYTES + 4, true) !== 0) {
      slot = (slot + 1) & (slots - 1);
    }
    view.setUint32(indexOffset + slot * INDEX_SLOT_BYTES, idView.getUint32(0, false), true);
    view.setUint32(indexOffset + slot * INDEX_SLOT_BYTES + 4, recordOffset, true);
  });

  // ---- GRUP
  let bucketCursor = grupOffset + groups.length * GRUP_RECORD_BYTES;
  groups.forEach((group, g) => {
    const recordOffset = grupOffset + g * GRUP_RECORD_BYTES;
    const blob = grupBlobs[g] as (typeof grupBlobs)[number];
    bytes.set(uuidBytes(group.groupId), recordOffset + GRUP_OFFSET.GROUP_ID);
    bytes.set(group.publicKey, recordOffset + GRUP_OFFSET.PUBLIC_KEY);
    view.setUint32(recordOffset + GRUP_OFFSET.GENERATION, group.generation, true);
    view.setUint32(recordOffset + GRUP_OFFSET.BUCKET_OFFSET, bucketCursor, true);
    view.setUint32(recordOffset + GRUP_OFFSET.BUCKET_COUNT, group.bucket.length, true);
    view.setUint32(
      recordOffset + GRUP_OFFSET.PRIVATE_DESCRIPTOR + FIELD_DESCRIPTOR_OFFSET.STRS_OFFSET,
      blob.priv,
      true,
    );
    view.setUint32(
      recordOffset + GRUP_OFFSET.PRIVATE_DESCRIPTOR + FIELD_DESCRIPTOR_OFFSET.SEALED_LEN,
      group.privateWrapped.byteLength,
      true,
    );
    group.bucket.forEach((entry, e) => {
      const at = bucketCursor + e * 24;
      for (let i = 0; i < 16; i += 1) {
        bytes[at + i] = Number.parseInt(entry.keyId.slice(i * 2, i * 2 + 2), 16);
      }
      view.setUint32(at + 16, blob.wrapped[e] as number, true);
      view.setUint32(at + 20, entry.wrapped.byteLength, true);
    });
    bucketCursor += group.bucket.length * 24;
  });

  // ---- FILT
  filters.forEach((entry, f) => {
    const at = filtOffset + f * 16;
    view.setUint32(at, entry.kind, true);
    view.setUint32(at + 4, filtBlobs[f] as number, true);
    view.setUint32(at + 8, entry.args.byteLength, true);
  });

  // ---- STRS
  let arenaCursor = strsOffset;
  for (const chunk of arena) {
    bytes.set(chunk, arenaCursor);
    arenaCursor += chunk.byteLength;
  }

  return { bytes, connOffset, connLength, indexOffset, slots, recordOffsets };
}

/** Flip a byte through a `DataView`, which reads a number rather than a maybe. */
function flipByte(bytes: Uint8Array, at: number): void {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  view.setUint8(at, view.getUint8(at) ^ 0xff);
}

async function stampChecksum(bytes: Uint8Array<ArrayBuffer>): Promise<void> {
  const digest = await crypto.subtle.digest("SHA-256", bytes.subarray(HEADER_BYTES));
  bytes.set(new Uint8Array(digest, 0, 28), HEADER_OFFSET.CHECKSUM);
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const GROUP_ID = "11111111-2222-3333-4444-555555555555";
const KEY_ID = "0123456789abcdef0123456789abcdef";
const CONNECTION_UUID = makeUuid(0xdeadbeef, 0x00000005);
const CONNECTION_ID = `${SHARD}_${CONNECTION_UUID}`;
/** 60 bytes of envelope: `eph_pub(32) || nonce(12) || ct(0) || tag(16)` plus a byte. */
const SEALED = new Uint8Array(64).fill(0x11);

function fixture(): BuiltBundle {
  return buildBundle({
    connections: [
      {
        uuid: CONNECTION_UUID,
        groupIndex: 0,
        target: "https://api.example.test",
        visible: { provider: "example", rate_limit: 250, sandbox: true },
        fields: [
          { name: "api_key", sealed: SEALED },
          { name: "secret", sealed: new Uint8Array(70).fill(0x22) },
        ],
        filters: [0, 1],
        expiresAt: 1_800_000_000_000n,
      },
    ],
    groups: [
      {
        groupId: GROUP_ID,
        publicKey: new Uint8Array(32).fill(0x33),
        generation: 7,
        bucket: [{ keyId: KEY_ID, wrapped: new Uint8Array(60).fill(0x44) }],
        privateWrapped: new Uint8Array(60).fill(0x55),
      },
    ],
    filters: [
      { kind: 1, args: Uint8Array.of(1, 2, 3) },
      { kind: 2, args: Uint8Array.of(9) },
    ],
  });
}

/** A 64-byte header and nothing else, for the load-time guards. */
function headerOnly(
  fields: { version?: number; flags?: number; sections?: number } = {},
): Uint8Array {
  const bytes = new Uint8Array(HEADER_BYTES);
  const view = new DataView(bytes.buffer);
  bytes.set(BUNDLE_MAGIC_BYTES, 0);
  view.setUint16(HEADER_OFFSET.VERSION, fields.version ?? BUNDLE_VERSION, true);
  view.setUint16(HEADER_OFFSET.FLAGS, fields.flags ?? 0, true);
  view.setUint32(HEADER_OFFSET.SECTIONS, fields.sections ?? 0, true);
  bytes.set(TEXT.encode(SHARD), HEADER_OFFSET.SHARD);
  return bytes;
}

// ---------------------------------------------------------------------------
// Load-time validation
// ---------------------------------------------------------------------------

describe("readBundle: refusing what it cannot read", () => {
  it("refuses a buffer too short to hold a header", () => {
    expect(() => readBundle(new Uint8Array(HEADER_BYTES - 1))).toThrow(BundleFormatError);
  });

  it("refuses a buffer whose magic is not S0BUNDLE", () => {
    const bytes = headerOnly();
    bytes[3] = 0x00;
    expect(() => readBundle(bytes)).toThrow(/magic/);
  });

  it("refuses a version it does not know, reporting both versions", () => {
    const bytes = headerOnly({ version: BUNDLE_VERSION + 1 });
    expect(() => readBundle(bytes)).toThrow(UnsupportedBundleVersionError);
    try {
      readBundle(bytes);
      expect.unreachable("a newer bundle must be refused");
    } catch (error) {
      expect(error).toBeInstanceOf(UnsupportedBundleVersionError);
      const refusal = error as UnsupportedBundleVersionError;
      expect(refusal.found).toBe(BUNDLE_VERSION + 1);
      expect(refusal.supported).toBe(BUNDLE_VERSION);
    }
  });

  it("refuses version zero", () => {
    expect(() => readBundle(headerOnly({ version: 0 }))).toThrow(/version is at least 1/);
  });

  it("refuses a bundle that sets a reserved flag", () => {
    expect(() => readBundle(headerOnly({ flags: 1 }))).toThrow(/reserved/);
  });

  it("refuses a section table that does not fit the buffer", () => {
    expect(() => readBundle(headerOnly({ sections: 4 }))).toThrow(/section table/);
  });

  it("refuses a section that points outside the buffer", () => {
    const bundle = fixture();
    new DataView(bundle.bytes.buffer).setUint32(
      SECTION_TABLE_OFFSET + SECTION_ENTRY_OFFSET.LENGTH,
      0xffff,
      true,
    );
    expect(() => readBundle(bundle.bytes)).toThrow(/lies outside the buffer/);
  });

  it("refuses a section kind that appears twice", () => {
    const bundle = fixture();
    new DataView(bundle.bytes.buffer).setUint32(
      SECTION_TABLE_OFFSET + SECTION_ENTRY_BYTES + SECTION_ENTRY_OFFSET.KIND,
      SECTION_KIND.INDX,
      true,
    );
    expect(() => readBundle(bundle.bytes)).toThrow(/appears twice/);
  });

  it("refuses an index that is not a whole number of slots", () => {
    const bundle = fixture();
    new DataView(bundle.bytes.buffer).setUint32(
      SECTION_TABLE_OFFSET + SECTION_ENTRY_OFFSET.LENGTH,
      12,
      true,
    );
    expect(() => readBundle(bundle.bytes)).toThrow(/whole number/);
  });

  it("refuses an index whose slot count is not a power of two", () => {
    const bundle = fixture();
    new DataView(bundle.bytes.buffer).setUint32(
      SECTION_TABLE_OFFSET + SECTION_ENTRY_OFFSET.LENGTH,
      24,
      true,
    );
    expect(() => readBundle(bundle.bytes)).toThrow(/power of two/);
  });

  it("accepts an empty section pointing nowhere", () => {
    const bundle = buildBundle({ filters: [] });
    const view = new DataView(bundle.bytes.buffer);
    // FILT is the fourth entry, and it is empty.
    view.setUint32(
      SECTION_TABLE_OFFSET + 3 * SECTION_ENTRY_BYTES + SECTION_ENTRY_OFFSET.OFFSET,
      0,
      true,
    );
    expect(readBundle(bundle.bytes).section("FILT")?.length).toBe(0);
  });

  it("reads a bundle handed over as a bare ArrayBuffer", () => {
    const bundle = fixture();
    const copy = bundle.bytes.slice();
    expect(readBundle(copy.buffer).connectionCount).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Header and sections
// ---------------------------------------------------------------------------

describe("readBundle: the header and the section table", () => {
  it("materialises the header, and only the header", () => {
    const view = readBundle(fixture().bytes);
    expect(view.header).toEqual({
      magic: "S0BUNDLE",
      version: BUNDLE_VERSION,
      flags: 0,
      generation: 42n,
      shard: SHARD,
      builtAt: 1_700_000_000_000n,
      sections: 5,
    });
    expect(view.connectionCount).toBe(1);
    expect(view.groupCount).toBe(1);
  });

  it("finds a section by kind and reports nothing for one that is absent", () => {
    const present = readBundle(fixture().bytes);
    expect(present.section("CONN")?.count).toBe(1);
    const without = readBundle(buildBundle({ omit: ["FILT"] }).bytes);
    expect(without.section("FILT")).toBeUndefined();
    expect(without.header.sections).toBe(4);
  });

  it("counts nothing when the record sections are absent", () => {
    const view = readBundle(buildBundle({ omit: ["CONN", "GRUP"] }).bytes);
    expect(view.connectionCount).toBe(0);
    expect(view.groupCount).toBe(0);
  });

  it("exposes the very buffer it was handed, so a write-back lands in it", () => {
    const bundle = fixture();
    expect(readBundle(bundle.bytes).buffer).toBe(bundle.bytes);
  });
});

// ---------------------------------------------------------------------------
// The checksum
// ---------------------------------------------------------------------------

describe("verifyChecksum", () => {
  it("accepts a bundle whose digest is stamped", async () => {
    const bundle = fixture();
    await stampChecksum(bundle.bytes);
    await expect(readBundle(bundle.bytes).verifyChecksum()).resolves.toBe(true);
  });

  it("rejects a truncated or corrupted bundle", async () => {
    const bundle = fixture();
    await stampChecksum(bundle.bytes);
    flipByte(bundle.bytes, bundle.bytes.byteLength - 1);
    await expect(readBundle(bundle.bytes).verifyChecksum()).resolves.toBe(false);
  });

  it("refuses to digest a buffer another thread could be changing", async () => {
    const bundle = fixture();
    const shared = new Uint8Array(new SharedArrayBuffer(bundle.bytes.byteLength));
    shared.set(bundle.bytes);
    await expect(readBundle(shared).verifyChecksum()).rejects.toThrow(/SharedArrayBuffer/);
  });

  it("verifies once and never again, because a write-back invalidates it", async () => {
    const bundle = fixture();
    await stampChecksum(bundle.bytes);
    const view = readBundle(bundle.bytes);
    expect(await view.verifyChecksum()).toBe(true);

    // Exactly what an open does to the covered bytes.
    flipByte(bundle.bytes, bundle.bytes.byteLength - 1);
    expect(await view.verifyChecksum()).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

describe("lookup", () => {
  it("finds a connection through the index", () => {
    const bundle = fixture();
    const record = readBundle(bundle.bytes).lookup(CONNECTION_ID);
    expect(record?.recordOffset).toBe(bundle.recordOffsets[0]);
  });

  it("misses on an empty slot without a record", () => {
    const view = readBundle(fixture().bytes);
    expect(view.lookup(`${SHARD}_${makeUuid(0x1, 0x2)}`)).toBeUndefined();
  });

  it("misses on a malformed id rather than throwing", () => {
    const view = readBundle(fixture().bytes);
    expect(view.lookup("not-a-connection-id")).toBeUndefined();
  });

  it("misses on another shard's id", () => {
    const view = readBundle(fixture().bytes);
    expect(view.lookup(`bbbb_${CONNECTION_UUID}`)).toBeUndefined();
  });

  it("misses when the bundle carries no index or no records", () => {
    expect(readBundle(buildBundle({ omit: ["INDX"] }).bytes).lookup(CONNECTION_ID)).toBeUndefined();
    expect(readBundle(buildBundle({ omit: ["CONN"] }).bytes).lookup(CONNECTION_ID)).toBeUndefined();
  });

  it("probes past a bucket collision to the right record", () => {
    // Two ids in the same bucket (identical low 32 bits), different fingerprints.
    const first = makeUuid(0x0000000a, 0x00000011);
    const second = makeUuid(0x0000000b, 0x00000011);
    const bundle = buildBundle({
      connections: [connection(first), connection(second)],
    });
    const view = readBundle(bundle.bytes);
    expect(view.lookup(`${SHARD}_${second}`)?.recordOffset).toBe(bundle.recordOffsets[1]);
  });

  it("does not trust a fingerprint match: all sixteen bytes are verified", () => {
    // Same fingerprint and same bucket, different middle bytes.
    const stored = makeUuid(0x0000000a, 0x00000011);
    const bundle = buildBundle({ connections: [connection(stored)] });
    const impostorHex = "0000000a00000000000000ff00000011";
    const impostor = `${impostorHex.slice(0, 8)}-${impostorHex.slice(8, 12)}-${impostorHex.slice(12, 16)}-${impostorHex.slice(16, 20)}-${impostorHex.slice(20)}`;
    expect(readBundle(bundle.bytes).lookup(`${SHARD}_${impostor}`)).toBeUndefined();
  });

  it("terminates on a table with no empty slot left", () => {
    const bundle = fixture();
    const view = new DataView(bundle.bytes.buffer);
    for (let slot = 0; slot < bundle.slots; slot += 1) {
      const at = bundle.indexOffset + slot * INDEX_SLOT_BYTES;
      view.setUint32(at, 0x77777777, true);
      view.setUint32(at + 4, bundle.connOffset, true);
    }
    expect(readBundle(bundle.bytes).lookup(CONNECTION_ID)).toBeUndefined();
  });

  it("refuses an index slot that does not address a record", () => {
    const bundle = fixture();
    const view = new DataView(bundle.bytes.buffer);
    for (let slot = 0; slot < bundle.slots; slot += 1) {
      const at = bundle.indexOffset + slot * INDEX_SLOT_BYTES;
      if (view.getUint32(at + 4, true) !== 0) {
        view.setUint32(at + 4, bundle.connOffset + 1, true);
      }
    }
    expect(() => readBundle(bundle.bytes).lookup(CONNECTION_ID)).toThrow(
      /not the offset of a connection record/,
    );
  });
});

function connection(uuid: string): TestConnection {
  return {
    uuid,
    groupIndex: 0,
    target: "https://api.example.test",
    visible: {},
    fields: [],
    filters: [],
    expiresAt: 0n,
  };
}

// ---------------------------------------------------------------------------
// A fingerprint miss must never touch CONN
// ---------------------------------------------------------------------------

/** Every offset any `DataView` getter or `subarray` was asked for, in order. */
function recordReads<T>(run: () => T): { result: T; offsets: readonly number[] } {
  const offsets: number[] = [];
  const getters = [
    "getUint8",
    "getUint16",
    "getUint32",
    "getBigUint64",
    "getFloat64",
  ] as const satisfies ReadonlyArray<keyof DataView>;

  for (const name of getters) {
    const original = DataView.prototype[name];
    vi.spyOn(DataView.prototype, name).mockImplementation(function (
      this: DataView,
      byteOffset: number,
      littleEndian?: boolean,
    ) {
      offsets.push(byteOffset);
      return Reflect.apply(original, this, [byteOffset, littleEndian]);
    } as typeof original);
  }
  const subarray = Uint8Array.prototype.subarray;
  vi.spyOn(Uint8Array.prototype, "subarray").mockImplementation(function (
    this: Uint8Array,
    begin?: number,
    end?: number,
  ) {
    offsets.push(begin ?? 0);
    return Reflect.apply(subarray, this, [begin, end]);
  });

  try {
    return { result: run(), offsets };
  } finally {
    vi.restoreAllMocks();
  }
}

describe("a fingerprint miss never reads CONN", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("resolves the miss from the index alone", () => {
    // An id in an occupied bucket whose fingerprint differs: the slot is read,
    // the fingerprints disagree, and the record must not be touched.
    const stored = makeUuid(0x0000000a, 0x00000011);
    const bundle = buildBundle({ connections: [connection(stored)] });
    const view = readBundle(bundle.bytes);
    const other = `${SHARD}_${makeUuid(0x0000000b, 0x00000011)}`;

    const { result, offsets } = recordReads(() => view.lookup(other));
    expect(result).toBeUndefined();
    const touched = offsets.filter(
      (offset) => offset >= bundle.connOffset && offset < bundle.connOffset + bundle.connLength,
    );
    expect(touched).toEqual([]);
  });

  it("does read CONN on a fingerprint match, so the test above is not vacuous", () => {
    const stored = makeUuid(0x0000000a, 0x00000011);
    const bundle = buildBundle({ connections: [connection(stored)] });
    const view = readBundle(bundle.bytes);

    const { result, offsets } = recordReads(() => view.lookup(`${SHARD}_${stored}`));
    expect(result).toBeDefined();
    const touched = offsets.filter(
      (offset) => offset >= bundle.connOffset && offset < bundle.connOffset + bundle.connLength,
    );
    expect(touched.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Connection records
// ---------------------------------------------------------------------------

describe("a connection record", () => {
  const view = () => readBundle(fixture().bytes);
  const record = () => {
    const found = view().lookup(CONNECTION_ID);
    if (found === undefined) {
      throw new Error("the fixture's connection must be findable");
    }
    return found;
  };

  it("reads the visible configuration without any key", () => {
    const connection = record();
    expect(connection.groupIndex).toBe(0);
    expect(connection.target()).toBe("https://api.example.test");
    expect(connection.visibleKeys()).toEqual(["provider", "rate_limit", "sandbox"]);
    expect(connection.visible("provider")).toBe("example");
    expect(connection.visible("rate_limit")).toBe(250);
    expect(connection.visible("sandbox")).toBe(true);
    expect(connection.visible("absent")).toBeUndefined();
  });

  it("returns the id as a view and verifies all sixteen bytes", () => {
    const connection = record();
    const id = connection.idBytes();
    expect(id.byteLength).toBe(16);
    expect(connection.matchesId(id)).toBe(true);
    expect(connection.matchesId(id.slice(0, 8))).toBe(false);
    const wrong = id.slice();
    flipByte(wrong, 15);
    expect(connection.matchesId(wrong)).toBe(false);
  });

  it("reads the expiry, and reads zero as no expiry", () => {
    expect(record().expiresAt()).toBe(1_800_000_000_000);
    const other = buildBundle({ connections: [connection(CONNECTION_UUID)] });
    expect(readBundle(other.bytes).lookup(CONNECTION_ID)?.expiresAt()).toBeNull();
  });

  it("copies out its filter indices, the only accessor that copies", () => {
    expect(Array.from(record().filterIndices())).toEqual([0, 1]);
  });

  it("names its sealed fields and addresses each descriptor", () => {
    const connection = record();
    expect(connection.fieldNames()).toEqual(["api_key", "secret"]);
    const descriptor = connection.field("api_key");
    expect(descriptor?.sealedLen).toBe(SEALED.byteLength);
    expect(descriptor?.state).toBe(FieldState.Sealed);
    expect(connection.field("nonexistent")).toBeUndefined();
  });

  it("returns the envelope while sealed and the plaintext once open", () => {
    const bundle = fixture();
    const bundleView = readBundle(bundle.bytes);
    const connection = bundleView.lookup(CONNECTION_ID);
    const descriptor = connection?.field("api_key");
    if (connection === undefined || descriptor === undefined) {
      throw new Error("the fixture must carry a sealed api_key");
    }
    expect(connection.fieldBytes(descriptor)).toEqual(SEALED);

    const plaintext = TEXT.encode("sk-live-plaintext");
    const opened = bundleView.writeBack(descriptor, plaintext);
    expect(opened.state).toBe(FieldState.Open);
    // The snapshot the caller still holds says "sealed"; the buffer says otherwise.
    expect(connection.fieldBytes(descriptor)).toEqual(plaintext);
    expect(connection.fieldBytes(opened)).toEqual(plaintext);
  });

  it("is addressable directly by record offset", () => {
    const bundle = fixture();
    const bundleView = readBundle(bundle.bytes);
    const offset = bundle.recordOffsets[0] as number;
    expect(bundleView.connectionAt(offset).recordOffset).toBe(offset);
    expect(() => bundleView.connectionAt(offset + 1)).toThrow(BundleFormatError);
    expect(() => bundleView.connectionAt(bundle.connOffset + bundle.connLength)).toThrow(
      BundleFormatError,
    );
  });

  it("has no addressable records at all when CONN is absent", () => {
    expect(() => readBundle(buildBundle({ omit: ["CONN"] }).bytes).connectionAt(0)).toThrow(
      BundleFormatError,
    );
  });
});

// ---------------------------------------------------------------------------
// Corrupt variable-length blobs
// ---------------------------------------------------------------------------

describe("a corrupt record is refused rather than misread", () => {
  const corrupt = (patch: (view: DataView, recordOffset: number) => void) => {
    const bundle = fixture();
    patch(new DataView(bundle.bytes.buffer), bundle.recordOffsets[0] as number);
    const found = readBundle(bundle.bytes).lookup(CONNECTION_ID);
    if (found === undefined) {
      throw new Error("the record must still be findable");
    }
    return found;
  };

  it("refuses a target that runs past the buffer", () => {
    const record = corrupt((view, at) => {
      view.setUint32(at + CONN_OFFSET.TARGET_LENGTH, 0xffff, true);
    });
    expect(() => record.target()).toThrow(/outside the buffer/);
  });

  it("refuses a visible map that runs past the buffer", () => {
    const record = corrupt((view, at) => {
      view.setUint32(at + CONN_OFFSET.VISIBLE_LENGTH, 0xffff, true);
    });
    expect(() => record.visibleKeys()).toThrow(/outside the buffer/);
  });

  it("refuses a visible entry header cut short by its own length", () => {
    const record = corrupt((view, at) => {
      view.setUint32(at + CONN_OFFSET.VISIBLE_LENGTH, 2, true);
    });
    expect(() => record.visibleKeys()).toThrow(/a visible entry runs past/);
  });

  it("refuses a visible key that runs past the map", () => {
    const record = corrupt((view, at) => {
      view.setUint32(at + CONN_OFFSET.VISIBLE_LENGTH, 6, true);
    });
    expect(() => record.visibleKeys()).toThrow(/a visible key runs past/);
  });

  it("refuses a string value whose length field is cut short", () => {
    const record = corrupt((view, at) => {
      // "provider" is eight bytes, so the entry's head alone is eleven.
      view.setUint32(at + CONN_OFFSET.VISIBLE_LENGTH, 12, true);
    });
    expect(() => record.visibleKeys()).toThrow(/a visible string's length runs past/);
  });

  it("refuses a string value that runs past the map", () => {
    const record = corrupt((view, at) => {
      view.setUint32(at + CONN_OFFSET.VISIBLE_LENGTH, 16, true);
    });
    expect(() => record.visibleKeys()).toThrow(/a visible string runs past/);
  });

  it("refuses a number value that runs past the map", () => {
    const record = corrupt((view, at) => {
      const visibleAt = view.getUint32(at + CONN_OFFSET.VISIBLE_OFFSET, true);
      // Cut the map to the string entry plus the number entry's head.
      view.setUint32(at + CONN_OFFSET.VISIBLE_LENGTH, entryEnd(view, visibleAt) + 13, true);
    });
    expect(() => record.visibleKeys()).toThrow(/a visible number runs past/);
  });

  it("refuses a boolean value that runs past the map", () => {
    const record = corrupt((view, at) => {
      const visibleAt = view.getUint32(at + CONN_OFFSET.VISIBLE_OFFSET, true);
      const afterString = entryEnd(view, visibleAt);
      view.setUint32(at + CONN_OFFSET.VISIBLE_LENGTH, afterString + 13 + 8 + 10, true);
    });
    expect(() => record.visibleKeys()).toThrow(/a visible boolean runs past/);
  });

  it("refuses an unknown visible value type", () => {
    const record = corrupt((view, at) => {
      view.setUint8(view.getUint32(at + CONN_OFFSET.VISIBLE_OFFSET, true), 9);
    });
    expect(() => record.visibleKeys()).toThrow(/unknown visible value type 9/);
  });

  it("refuses filter indices that run past the buffer", () => {
    const record = corrupt((view, at) => {
      view.setUint32(at + CONN_OFFSET.FILTERS_COUNT, 0xffff, true);
    });
    expect(() => record.filterIndices()).toThrow(/outside the buffer/);
  });

  it("refuses a field-name table that runs past the buffer", () => {
    const record = corrupt((view, at) => {
      view.setUint32(at + CONN_OFFSET.FIELD_NAMES_OFFSET, 0xfffffff0, true);
    });
    expect(() => record.fieldNames()).toThrow(/runs past the end of its section/);
  });

  it("refuses a field name longer than the buffer", () => {
    const record = corrupt((view, at) => {
      view.setUint16(view.getUint32(at + CONN_OFFSET.FIELD_NAMES_OFFSET, true), 0xffff, true);
    });
    expect(() => record.fieldNames()).toThrow(/outside the buffer/);
  });
});

/** The end of the first (string-valued) visible entry, relative to the map. */
function entryEnd(view: DataView, visibleAt: number): number {
  const keyLength = view.getUint16(visibleAt + 1, true);
  const valueLength = view.getUint32(visibleAt + 3 + keyLength, true);
  return 3 + keyLength + 4 + valueLength;
}

// ---------------------------------------------------------------------------
// Groups, buckets and filters
// ---------------------------------------------------------------------------

describe("key groups", () => {
  const bundleView = () => readBundle(fixture().bytes);

  it("reads a group in place", () => {
    const group = bundleView().group(0);
    expect(group?.groupIndex).toBe(0);
    expect(group?.groupId()).toBe(GROUP_ID);
    expect(group?.groupIdBytes().byteLength).toBe(16);
    expect(group?.publicKey()).toEqual(new Uint8Array(32).fill(0x33));
    expect(group?.generation()).toBe(7);
    expect(group?.bucketSize).toBe(1);
  });

  it("reports nothing for an index that is not a group", () => {
    const view = bundleView();
    expect(view.group(1)).toBeUndefined();
    expect(view.group(-1)).toBeUndefined();
    expect(view.group(0.5)).toBeUndefined();
    expect(readBundle(buildBundle({ omit: ["GRUP"] }).bytes).group(0)).toBeUndefined();
  });

  it("finds a group by its id and refuses anything that is not one", () => {
    const view = bundleView();
    expect(view.groupById(GROUP_ID)?.groupIndex).toBe(0);
    expect(view.groupById("11111111-2222-3333-4444-555555555556")).toBeUndefined();
    expect(view.groupById("not-a-uuid")).toBeUndefined();
  });

  it("reads a bucket entry and finds one by key id", () => {
    const group = bundleView().group(0);
    const entry = group?.bucketEntry(0);
    expect(entry?.keyIdHex()).toBe(KEY_ID);
    expect(entry?.keyIdBytes().byteLength).toBe(16);
    expect(entry?.wrapped()).toEqual(new Uint8Array(60).fill(0x44));
    expect(group?.findBucketEntry(KEY_ID)?.entryOffset).toBe(entry?.entryOffset);
    expect(group?.findBucketEntry("f".repeat(32))).toBeUndefined();
    expect(group?.findBucketEntry("not-a-key-id")).toBeUndefined();
    expect(group?.bucketEntry(1)).toBeUndefined();
    expect(group?.bucketEntry(-1)).toBeUndefined();
    expect(group?.bucketEntry(0.5)).toBeUndefined();
  });

  it("caches the private half the way a field is cached", () => {
    const bundle = fixture();
    const view = readBundle(bundle.bytes);
    const group = view.group(0);
    const descriptor = group?.privateKeyDescriptor();
    if (descriptor === undefined) {
      throw new Error("a group must carry a private-half descriptor");
    }
    expect(descriptor.state).toBe(FieldState.Sealed);
    expect(descriptor.sealedLen).toBe(60);

    const priv = new Uint8Array(32).fill(0x66);
    view.writeBack(descriptor, priv);
    expect(view.group(0)?.privateKeyDescriptor()).toEqual({
      descriptorOffset: descriptor.descriptorOffset,
      strsOffset: descriptor.strsOffset,
      sealedLen: 60,
      plainLen: 32,
      state: FieldState.Open,
    });
  });
});

describe("filters", () => {
  it("reads a filter's kind and arguments without instantiating anything", () => {
    const view = readBundle(fixture().bytes);
    const filter = view.filter(1);
    expect(filter?.filterIndex).toBe(1);
    expect(filter?.kind).toBe(2);
    expect(filter?.args()).toEqual(Uint8Array.of(9));
  });

  it("reports nothing for an index that is not a filter", () => {
    const view = readBundle(fixture().bytes);
    expect(view.filter(2)).toBeUndefined();
    expect(view.filter(-1)).toBeUndefined();
    expect(view.filter(1.5)).toBeUndefined();
    expect(readBundle(buildBundle({ omit: ["FILT"] }).bytes).filter(0)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Field descriptors and the write-back
// ---------------------------------------------------------------------------

describe("readFieldDescriptor", () => {
  const descriptorBytes = (state: number): Uint8Array => {
    const bytes = new Uint8Array(FIELD_DESCRIPTOR_BYTES);
    const view = new DataView(bytes.buffer);
    view.setUint32(FIELD_DESCRIPTOR_OFFSET.STRS_OFFSET, 100, true);
    view.setUint32(FIELD_DESCRIPTOR_OFFSET.SEALED_LEN, 64, true);
    view.setUint32(FIELD_DESCRIPTOR_OFFSET.PLAIN_LEN, 4, true);
    view.setUint8(FIELD_DESCRIPTOR_OFFSET.STATE, state);
    return bytes;
  };

  it("reads the four fields and the state flag", () => {
    expect(readFieldDescriptor(descriptorBytes(FieldState.Open), 0)).toEqual({
      descriptorOffset: 0,
      strsOffset: 100,
      sealedLen: 64,
      plainLen: 4,
      state: FieldState.Open,
    });
  });

  it("refuses an offset outside the buffer", () => {
    const bytes = descriptorBytes(FieldState.Sealed);
    expect(() => readFieldDescriptor(bytes, 1)).toThrow(RangeError);
    expect(() => readFieldDescriptor(bytes, -1)).toThrow(RangeError);
    expect(() => readFieldDescriptor(bytes, 0.5)).toThrow(RangeError);
  });

  it("refuses a state that is neither sealed nor open", () => {
    expect(() => readFieldDescriptor(descriptorBytes(2), 0)).toThrow(/state is 0 or 1/);
  });
});

describe("writeBackPlaintext", () => {
  const slotOffset = 32;
  const scratch = (sealedLen: number) => {
    const buffer = new Uint8Array(128);
    const view = new DataView(buffer.buffer);
    view.setUint32(FIELD_DESCRIPTOR_OFFSET.STRS_OFFSET, slotOffset, true);
    view.setUint32(FIELD_DESCRIPTOR_OFFSET.SEALED_LEN, sealedLen, true);
    return {
      buffer,
      descriptor: {
        descriptorOffset: 0,
        strsOffset: slotOffset,
        sealedLen,
        plainLen: 0,
        state: FieldState.Sealed,
      },
    };
  };

  it("writes the plaintext into the slot its ciphertext occupied", () => {
    const { buffer, descriptor } = scratch(64);
    const plaintext = TEXT.encode("hunter2");
    const updated = writeBackPlaintext(buffer, descriptor, plaintext);

    expect(buffer.subarray(slotOffset, slotOffset + plaintext.byteLength)).toEqual(plaintext);
    expect(updated).toEqual({
      descriptorOffset: 0,
      strsOffset: slotOffset,
      sealedLen: 64,
      plainLen: plaintext.byteLength,
      state: FieldState.Open,
    });
    expect(readFieldDescriptor(buffer, 0)).toEqual(updated);
  });

  it("publishes the state flag last, after the bytes and the length", () => {
    const { buffer, descriptor } = scratch(64);
    const order: string[] = [];
    const set = Uint8Array.prototype.set;
    const setUint32 = DataView.prototype.setUint32;
    const setUint8 = DataView.prototype.setUint8;

    vi.spyOn(Uint8Array.prototype, "set").mockImplementation(function (
      this: Uint8Array,
      array: ArrayLike<number>,
      offset?: number,
    ) {
      order.push("bytes");
      Reflect.apply(set, this, [array, offset]);
    });
    vi.spyOn(DataView.prototype, "setUint32").mockImplementation(function (
      this: DataView,
      byteOffset: number,
      value: number,
      littleEndian?: boolean,
    ) {
      order.push("plain_len");
      Reflect.apply(setUint32, this, [byteOffset, value, littleEndian]);
    });
    vi.spyOn(DataView.prototype, "setUint8").mockImplementation(function (
      this: DataView,
      byteOffset: number,
      value: number,
    ) {
      order.push("state");
      Reflect.apply(setUint8, this, [byteOffset, value]);
    });

    try {
      writeBackPlaintext(buffer, descriptor, TEXT.encode("hunter2"));
    } finally {
      vi.restoreAllMocks();
    }
    expect(order).toEqual(["bytes", "plain_len", "state"]);
  });

  it("is idempotent, so a duplicated open needs no lock", () => {
    const { buffer, descriptor } = scratch(64);
    const plaintext = TEXT.encode("hunter2");
    const first = writeBackPlaintext(buffer, descriptor, plaintext);
    const second = writeBackPlaintext(buffer, descriptor, plaintext);
    expect(second).toEqual(first);
  });

  it("refuses a plaintext larger than the slot its ciphertext occupied", () => {
    const { buffer, descriptor } = scratch(4);
    expect(() => writeBackPlaintext(buffer, descriptor, new Uint8Array(5))).toThrow(RangeError);
  });

  it("refuses a slot outside the buffer", () => {
    const { buffer } = scratch(64);
    const past = {
      descriptorOffset: 0,
      strsOffset: 120,
      sealedLen: 64,
      plainLen: 0,
      state: FieldState.Sealed,
    } as const;
    expect(() => writeBackPlaintext(buffer, past, new Uint8Array(16))).toThrow(
      /outside the buffer/,
    );
    const negative = { ...past, strsOffset: -1 } as const;
    expect(() => writeBackPlaintext(buffer, negative, new Uint8Array(1))).toThrow(RangeError);
  });

  it("refuses a descriptor outside the buffer", () => {
    const { buffer } = scratch(64);
    const base = { strsOffset: 0, sealedLen: 64, plainLen: 0, state: FieldState.Sealed } as const;
    expect(() =>
      writeBackPlaintext(buffer, { ...base, descriptorOffset: 120 }, new Uint8Array(1)),
    ).toThrow(/field descriptor offset/);
    expect(() =>
      writeBackPlaintext(buffer, { ...base, descriptorOffset: -1 }, new Uint8Array(1)),
    ).toThrow(/field descriptor offset/);
  });
});

// ---------------------------------------------------------------------------
// zeroTail and the decoy
// ---------------------------------------------------------------------------

describe("zeroTail", () => {
  it("zeroes everything past the new generation's length", () => {
    const buffer = new Uint8Array(8).fill(0xaa);
    zeroTail(buffer, 3);
    expect(Array.from(buffer)).toEqual([0xaa, 0xaa, 0xaa, 0, 0, 0, 0, 0]);
  });

  it("leaves a buffer that is exactly full alone", () => {
    const buffer = new Uint8Array(4).fill(0xaa);
    zeroTail(buffer, 4);
    expect(Array.from(buffer)).toEqual([0xaa, 0xaa, 0xaa, 0xaa]);
  });

  it("refuses a length that is not inside the buffer", () => {
    const buffer = new Uint8Array(4);
    expect(() => zeroTail(buffer, 5)).toThrow(RangeError);
    expect(() => zeroTail(buffer, -1)).toThrow(RangeError);
    expect(() => zeroTail(buffer, 1.5)).toThrow(RangeError);
  });
});

describe("decoyUnwrap", () => {
  it("spends the time a real unwrap would, and reports nothing", async () => {
    await expect(decoyUnwrap()).resolves.toBeUndefined();
  });

  it("costs enough to be worth doing", async () => {
    const started = performance.now();
    await decoyUnwrap();
    expect(performance.now() - started).toBeGreaterThan(0);
  });
});
