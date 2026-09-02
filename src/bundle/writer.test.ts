/**
 * The writer's tests read the bytes back through a bare `DataView` and the
 * layout constants, deliberately not through the reader: a bug shared by both
 * halves of one module would otherwise cancel itself out and the round trip
 * would still pass.
 */

import { describe, expect, it } from "vitest";
import { base64Encode, hexDecode, utf8Decode } from "../encoding.js";
import type {
  BundleInput,
  ConnectionInput,
  KeyGroup,
  PublicKey,
  SealedEnvelope,
} from "../types.js";
import { asPublicKey, BundleCapacityError, SEAL_ALGORITHM } from "../types.js";
import {
  BUCKET_ENTRY_BYTES,
  BUCKET_ENTRY_OFFSET,
  BUNDLE_MAGIC,
  bucketEntryOffset,
  CHECKSUM_BYTES,
  CONN_OFFSET,
  CONN_RECORD_BYTES,
  connRecordOffset,
  FIELD_DESCRIPTOR_OFFSET,
  FILT_ENTRY_OFFSET,
  fieldDescriptorOffset,
  filtEntryOffset,
  GRUP_OFFSET,
  GRUP_RECORD_BYTES,
  grupRecordOffset,
  HEADER_BYTES,
  HEADER_OFFSET,
  INDEX_SLOT_OFFSET,
  indexSlotOffset,
  SECTION_ENTRY_OFFSET,
  SECTION_KIND,
  sectionEntryOffset,
} from "./layout.js";
import {
  BUNDLE_MAX_BYTES,
  computeChecksum,
  measureBundle,
  writeBundle,
  writeBundleWithChecksum,
  writeChecksum,
} from "./writer.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const GROUP_A = "11111111-2222-4333-8444-555555555555";
const GROUP_B = "99999999-8888-4777-8666-555555555555";
const KEY_ID_A = "0123456789abcdef0123456789abcdef";
const KEY_ID_B = "fedcba9876543210fedcba9876543210";

/** A UUID whose last four bytes decide the index bucket and first four the fingerprint. */
function uuid(high: string, low: string): string {
  return `${high}-2222-4333-8444-5555${low}`;
}

const UUID_ONE = uuid("00000001", "00000010");
const UUID_TWO = uuid("00000002", "00000020");

function connectionId(id: string): string {
  return id;
}

/** `plaintextLength + 60`, so the payload is a plausible envelope. */
function envelope(plaintextLength: number, fill = 0x41): SealedEnvelope {
  const payload = new Uint8Array(plaintextLength + 60).fill(fill);
  return `${SEAL_ALGORITHM}:${base64Encode(payload)}`;
}

function bytes(length: number, fill: number): Uint8Array {
  return new Uint8Array(length).fill(fill);
}

function group(groupId: string, overrides: Partial<KeyGroup> = {}): KeyGroup {
  return {
    groupId,
    publicKey: asPublicKey(bytes(32, 0x0b)),
    generation: 1,
    bucket: [{ keyId: KEY_ID_A, wrapped: bytes(60, 0x0c) }],
    ...overrides,
  };
}

function connection(overrides: Partial<ConnectionInput> = {}): ConnectionInput {
  return {
    connectionId: connectionId(UUID_ONE),
    groupId: GROUP_A,
    target: "https://api.example.test",
    visible: { provider: "example", rate_limit: 10, sandbox: true },
    sealed: { api_key: envelope(16) },
    ...overrides,
  };
}

function bundle(overrides: Partial<BundleInput> = {}): BundleInput {
  return {
    header: { version: 1, generation: 7n, builtAt: 1_700_000_000_000n },
    groups: [group(GROUP_A)],
    connections: [connection()],
    filters: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Read-back helpers
// ---------------------------------------------------------------------------

function viewOf(buffer: Uint8Array): DataView {
  return new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
}

interface Section {
  readonly offset: number;
  readonly length: number;
  readonly count: number;
}

function sections(buffer: Uint8Array): Map<number, Section> {
  const view = viewOf(buffer);
  const found = new Map<number, Section>();
  const count = view.getUint32(HEADER_OFFSET.SECTIONS, true);
  for (let index = 0; index < count; index += 1) {
    const at = sectionEntryOffset(index);
    found.set(view.getUint32(at + SECTION_ENTRY_OFFSET.KIND, true), {
      offset: view.getUint32(at + SECTION_ENTRY_OFFSET.OFFSET, true),
      length: view.getUint32(at + SECTION_ENTRY_OFFSET.LENGTH, true),
      count: view.getUint32(at + SECTION_ENTRY_OFFSET.COUNT, true),
    });
  }
  return found;
}

function section(buffer: Uint8Array, kind: number): Section {
  const found = sections(buffer).get(kind);
  if (found === undefined) {
    throw new Error(`section ${kind} is missing`);
  }
  return found;
}

/** The reader's own lookup, written out here so the index is tested end to end. */
function lookup(buffer: Uint8Array, id: string): number | undefined {
  const view = viewOf(buffer);
  const indx = section(buffer, SECTION_KIND.INDX);
  const uuidBytes = hexDecode(id.replaceAll("-", ""));
  const idView = viewOf(uuidBytes);
  const low = idView.getUint32(12, false);
  const high = idView.getUint32(0, false);
  const mask = indx.count - 1;
  let slot = low & mask;
  for (let probe = 0; probe < indx.count; probe += 1) {
    const at = indexSlotOffset(indx.offset, slot);
    const recordOffset = view.getUint32(at + INDEX_SLOT_OFFSET.CONN_OFFSET, true);
    if (recordOffset === 0) {
      return undefined;
    }
    if (view.getUint32(at + INDEX_SLOT_OFFSET.FINGERPRINT, true) === high) {
      const stored = buffer.subarray(
        recordOffset + CONN_OFFSET.ID,
        recordOffset + CONN_OFFSET.ID + 16,
      );
      if (stored.every((byte, index) => byte === uuidBytes[index])) {
        return recordOffset;
      }
    }
    slot = (slot + 1) & mask;
  }
  return undefined;
}

function stringAt(buffer: Uint8Array, offset: number, length: number): string {
  return utf8Decode(buffer.subarray(offset, offset + length));
}

function targetOf(buffer: Uint8Array, recordOffset: number): string {
  const view = viewOf(buffer);
  return stringAt(
    buffer,
    view.getUint32(recordOffset + CONN_OFFSET.TARGET_OFFSET, true),
    view.getUint32(recordOffset + CONN_OFFSET.TARGET_LENGTH, true),
  );
}

/**
 * Decode the packed `visible` map from the documented layout alone:
 * `type u8 | key_len u16 | key utf8 | value`, where the value is
 * `len u32 || utf8` for type 0, a `float64` for type 1 and a `u8` for type 2.
 *
 * Written out here rather than borrowed from `reader.ts`, for the reason at the
 * top of this file: the two are independent implementations of one document.
 */
function visibleOf(buffer: Uint8Array, recordOffset: number): Record<string, unknown> {
  const view = viewOf(buffer);
  const start = view.getUint32(recordOffset + CONN_OFFSET.VISIBLE_OFFSET, true);
  const end = start + view.getUint32(recordOffset + CONN_OFFSET.VISIBLE_LENGTH, true);

  const decoded: Record<string, unknown> = {};
  let cursor = start;
  while (cursor < end) {
    const type = view.getUint8(cursor);
    const keyLength = view.getUint16(cursor + 1, true);
    cursor += 3;
    const key = stringAt(buffer, cursor, keyLength);
    cursor += keyLength;

    if (type === 0) {
      const length = view.getUint32(cursor, true);
      cursor += 4;
      decoded[key] = stringAt(buffer, cursor, length);
      cursor += length;
    } else if (type === 1) {
      decoded[key] = view.getFloat64(cursor, true);
      cursor += 8;
    } else if (type === 2) {
      decoded[key] = view.getUint8(cursor) !== 0;
      cursor += 1;
    } else {
      throw new Error(`unknown visible value type ${type}`);
    }
  }
  return decoded;
}

function fieldNamesOf(buffer: Uint8Array, recordOffset: number): string[] {
  const view = viewOf(buffer);
  const count = view.getUint32(recordOffset + CONN_OFFSET.FIELD_COUNT, true);
  let cursor = view.getUint32(recordOffset + CONN_OFFSET.FIELD_NAMES_OFFSET, true);
  const names: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const length = view.getUint16(cursor, true);
    names.push(stringAt(buffer, cursor + 2, length));
    cursor += 2 + length;
  }
  return names;
}

function filterIndicesOf(buffer: Uint8Array, recordOffset: number): number[] {
  const view = viewOf(buffer);
  const offset = view.getUint32(recordOffset + CONN_OFFSET.FILTERS_OFFSET, true);
  const count = view.getUint32(recordOffset + CONN_OFFSET.FILTERS_COUNT, true);
  const indices: number[] = [];
  for (let index = 0; index < count; index += 1) {
    indices.push(view.getUint32(offset + index * 4, true));
  }
  return indices;
}

interface Descriptor {
  readonly strsOffset: number;
  readonly sealedLen: number;
  readonly plainLen: number;
  readonly state: number;
}

function descriptorAt(buffer: Uint8Array, at: number): Descriptor {
  const view = viewOf(buffer);
  return {
    strsOffset: view.getUint32(at + FIELD_DESCRIPTOR_OFFSET.STRS_OFFSET, true),
    sealedLen: view.getUint32(at + FIELD_DESCRIPTOR_OFFSET.SEALED_LEN, true),
    plainLen: view.getUint32(at + FIELD_DESCRIPTOR_OFFSET.PLAIN_LEN, true),
    state: view.getUint8(at + FIELD_DESCRIPTOR_OFFSET.STATE),
  };
}

// ---------------------------------------------------------------------------
// Header and section table
// ---------------------------------------------------------------------------

describe("the header", () => {
  it("carries the magic, the version and the compiler's metadata", () => {
    const buffer = writeBundle(bundle());
    const view = viewOf(buffer);

    expect(stringAt(buffer, HEADER_OFFSET.MAGIC, 8)).toBe(BUNDLE_MAGIC);
    expect(view.getUint16(HEADER_OFFSET.VERSION, true)).toBe(1);
    expect(view.getUint16(HEADER_OFFSET.FLAGS, true)).toBe(0);
    expect(view.getBigUint64(HEADER_OFFSET.GENERATION, true)).toBe(7n);
    expect(Array.from(buffer.subarray(HEADER_OFFSET.RESERVED, HEADER_OFFSET.RESERVED + 4))).toEqual(
      [0, 0, 0, 0],
    );
    expect(view.getBigUint64(HEADER_OFFSET.BUILT_AT, true)).toBe(1_700_000_000_000n);
    expect(view.getUint32(HEADER_OFFSET.SECTIONS, true)).toBe(5);
  });

  it("leaves the checksum zero until it is stamped", () => {
    const buffer = writeBundle(bundle());
    const checksum = buffer.subarray(
      HEADER_OFFSET.CHECKSUM,
      HEADER_OFFSET.CHECKSUM + CHECKSUM_BYTES,
    );
    expect(checksum.every((byte) => byte === 0)).toBe(true);
  });

  it("refuses to stamp a version it does not implement", () => {
    // One layout, one number. A caller-chosen version would let the writer emit
    // a bundle no reader accepts, and the mismatch would only surface as a
    // refusal at load on some other machine.
    expect(() => writeBundle(bundle({ header: { ...bundle().header, version: 2 } }))).toThrow(
      /bundle version must be 1/,
    );
    expect(() => writeBundle(bundle({ header: { ...bundle().header, version: 0 } }))).toThrow(
      RangeError,
    );
  });

  it.each([
    ["a version below one", { version: 0 }],
    ["a fractional version", { version: 1.5 }],
    ["a version past a uint16", { version: 70000 }],
  ])("refuses %s", (_label, overrides) => {
    expect(() => writeBundle(bundle({ header: { ...bundle().header, ...overrides } }))).toThrow(
      RangeError,
    );
  });

  it.each([
    ["a negative generation", { generation: -1n }],
    ["a generation past a uint64", { generation: 2n ** 64n }],
    ["a negative built_at", { builtAt: -1n }],
  ])("refuses %s", (_label, overrides) => {
    expect(() => writeBundle(bundle({ header: { ...bundle().header, ...overrides } }))).toThrow(
      RangeError,
    );
  });
});

describe("the section table", () => {
  it("names all five sections in buffer order, contiguously", () => {
    const buffer = writeBundle(bundle({ filters: [{ kind: 1, args: bytes(4, 0x09) }] }));
    const table = sections(buffer);
    const order = [
      SECTION_KIND.INDX,
      SECTION_KIND.CONN,
      SECTION_KIND.GRUP,
      SECTION_KIND.FILT,
      SECTION_KIND.STRS,
    ];

    let cursor = HEADER_BYTES + 5 * 16;
    for (const kind of order) {
      const entry = table.get(kind);
      expect(entry).toBeDefined();
      expect(entry?.offset).toBe(cursor);
      cursor += entry?.length ?? 0;
    }
    expect(cursor).toBe(buffer.byteLength);
  });

  it("counts records rather than bytes", () => {
    const buffer = writeBundle(
      bundle({
        groups: [
          group(GROUP_A),
          group(GROUP_B, { bucket: [{ keyId: KEY_ID_B, wrapped: bytes(60, 1) }] }),
        ],
        connections: [connection(), connection({ connectionId: connectionId(UUID_TWO) })],
        filters: [
          { kind: 1, args: bytes(2, 1) },
          { kind: 2, args: bytes(3, 2) },
        ],
      }),
    );
    expect(section(buffer, SECTION_KIND.CONN).count).toBe(2);
    expect(section(buffer, SECTION_KIND.GRUP).count).toBe(2);
    expect(section(buffer, SECTION_KIND.FILT).count).toBe(2);
    expect(section(buffer, SECTION_KIND.CONN).length).toBe(2 * CONN_RECORD_BYTES);
    expect(section(buffer, SECTION_KIND.GRUP).length).toBe(
      2 * GRUP_RECORD_BYTES + 2 * BUCKET_ENTRY_BYTES,
    );
  });
});

// ---------------------------------------------------------------------------
// INDX
// ---------------------------------------------------------------------------

describe("the index", () => {
  it("holds at least four slots per connection, as a power of two", () => {
    const connections = Array.from({ length: 3 }, (_unused, index) =>
      connection({ connectionId: connectionId(uuid("0000000a", `0000000${index}`)) }),
    );
    const indx = section(writeBundle(bundle({ connections })), SECTION_KIND.INDX);
    expect(indx.count).toBe(16);
    expect(indx.length).toBe(16 * 8);
  });

  it("addresses every connection it wrote", () => {
    const ids = [UUID_ONE, UUID_TWO, uuid("0000dead", "0000beef")];
    const buffer = writeBundle(
      bundle({ connections: ids.map((id) => connection({ connectionId: connectionId(id) })) }),
    );
    const connOffset = section(buffer, SECTION_KIND.CONN).offset;

    ids.forEach((id, index) => {
      expect(lookup(buffer, connectionId(id))).toBe(connRecordOffset(connOffset, index));
    });
  });

  it("linear-probes two ids that share a bucket", () => {
    // Identical low 32 bits, so both hash to one slot; different high bits, so
    // the fingerprints still tell them apart.
    const first = uuid("00000001", "0000abcd");
    const second = uuid("00000002", "0000abcd");
    const buffer = writeBundle(
      bundle({
        connections: [
          connection({ connectionId: connectionId(first) }),
          connection({ connectionId: connectionId(second), target: "https://second.test" }),
        ],
      }),
    );

    const firstOffset = lookup(buffer, connectionId(first));
    const secondOffset = lookup(buffer, connectionId(second));
    expect(firstOffset).toBeDefined();
    expect(secondOffset).not.toBe(firstOffset);
    expect(targetOf(buffer, secondOffset ?? 0)).toBe("https://second.test");
  });

  it("leaves an unknown id unresolved", () => {
    const buffer = writeBundle(bundle());
    expect(lookup(buffer, connectionId(uuid("0000ffff", "0000ffff")))).toBeUndefined();
  });

  it("refuses more connections than the index can address", () => {
    const connections = Array.from({ length: 65537 }, (_unused, index) =>
      connection({
        connectionId: connectionId(uuid("00000001", index.toString(16).padStart(8, "0"))),
      }),
    );
    expect(() => writeBundle(bundle({ connections }))).toThrow(BundleCapacityError);
  });
});

// ---------------------------------------------------------------------------
// CONN
// ---------------------------------------------------------------------------

describe("a connection record", () => {
  it("stores the visible configuration, the target and the group index", () => {
    const buffer = writeBundle(
      bundle({
        groups: [group(GROUP_B), group(GROUP_A)],
        connections: [connection({ groupId: GROUP_A })],
      }),
    );
    const at = lookup(buffer, connectionId(UUID_ONE)) ?? 0;

    expect(viewOf(buffer).getUint32(at + CONN_OFFSET.GROUP_INDEX, true)).toBe(1);
    expect(targetOf(buffer, at)).toBe("https://api.example.test");
    expect(visibleOf(buffer, at)).toEqual({ provider: "example", rate_limit: 10, sandbox: true });
  });

  it("distinguishes the two booleans, which share one byte and differ only in it", () => {
    const buffer = writeBundle(
      bundle({
        connections: [connection({ visible: { streaming: false, sandbox: true } })],
      }),
    );
    const at = lookup(buffer, connectionId(UUID_ONE)) ?? 0;
    expect(visibleOf(buffer, at)).toEqual({ streaming: false, sandbox: true });
  });

  it("keeps a visible number a float64, fraction and sign intact", () => {
    const buffer = writeBundle(
      bundle({ connections: [connection({ visible: { budget: -0.5, ceiling: 2 ** 53 } })] }),
    );
    const at = lookup(buffer, connectionId(UUID_ONE)) ?? 0;
    expect(visibleOf(buffer, at)).toEqual({ budget: -0.5, ceiling: 2 ** 53 });
  });

  it("stores expires_at as unix millis, and zero for a connection that does not expire", () => {
    const withExpiry = writeBundle(
      bundle({ connections: [connection({ expiresAt: 1_800_000_000_000 })] }),
    );
    const withoutExpiry = writeBundle(bundle({ connections: [connection({ expiresAt: null })] }));
    const omitted = writeBundle(bundle());

    const read = (buffer: Uint8Array): bigint =>
      viewOf(buffer).getBigUint64(
        (lookup(buffer, connectionId(UUID_ONE)) ?? 0) + CONN_OFFSET.EXPIRES_AT,
        true,
      );

    expect(read(withExpiry)).toBe(1_800_000_000_000n);
    expect(read(withoutExpiry)).toBe(0n);
    expect(read(omitted)).toBe(0n);
  });

  it("stores filter indices, and an empty list when there are none", () => {
    const buffer = writeBundle(
      bundle({
        filters: [
          { kind: 10, args: bytes(1, 1) },
          { kind: 11, args: bytes(1, 2) },
        ],
        connections: [
          connection({ filters: [1, 0] }),
          connection({ connectionId: connectionId(UUID_TWO) }),
        ],
      }),
    );

    expect(filterIndicesOf(buffer, lookup(buffer, connectionId(UUID_ONE)) ?? 0)).toEqual([1, 0]);
    expect(filterIndicesOf(buffer, lookup(buffer, connectionId(UUID_TWO)) ?? 0)).toEqual([]);
  });

  it("names its sealed fields in descriptor order", () => {
    const buffer = writeBundle(
      bundle({
        connections: [
          connection({ sealed: { api_key: envelope(16), refresh_token: envelope(200) } }),
        ],
      }),
    );
    const at = lookup(buffer, connectionId(UUID_ONE)) ?? 0;

    expect(fieldNamesOf(buffer, at)).toEqual(["api_key", "refresh_token"]);
    expect(descriptorAt(buffer, fieldDescriptorOffset(at, 0)).sealedLen).toBe(76);
    expect(descriptorAt(buffer, fieldDescriptorOffset(at, 1)).sealedLen).toBe(260);
  });

  it("writes every field sealed, with room for the plaintext its envelope carries", () => {
    const buffer = writeBundle(
      bundle({ connections: [connection({ sealed: { pw: envelope(9) } })] }),
    );
    const at = lookup(buffer, connectionId(UUID_ONE)) ?? 0;
    const descriptor = descriptorAt(buffer, fieldDescriptorOffset(at, 0));

    expect(descriptor.state).toBe(0);
    expect(descriptor.plainLen).toBe(0);
    expect(descriptor.sealedLen).toBe(69);
    // The write-back invariant: the plaintext is 60 bytes shorter, so it fits.
    expect(descriptor.sealedLen - 60).toBe(9);
    expect(descriptor.strsOffset + descriptor.sealedLen).toBeLessThanOrEqual(buffer.byteLength);
  });

  it("stores the envelope payload without its algorithm prefix", () => {
    const payload = new Uint8Array(64).fill(0x37);
    const buffer = writeBundle(
      bundle({
        connections: [
          connection({ sealed: { api_key: `${SEAL_ALGORITHM}:${base64Encode(payload)}` } }),
        ],
      }),
    );
    const at = lookup(buffer, connectionId(UUID_ONE)) ?? 0;
    const descriptor = descriptorAt(buffer, fieldDescriptorOffset(at, 0));

    expect([
      ...buffer.subarray(descriptor.strsOffset, descriptor.strsOffset + descriptor.sealedLen),
    ]).toEqual([...payload]);
  });

  it("gives two fields with identical envelopes separate slots", () => {
    const shared = envelope(16, 0x5a);
    const buffer = writeBundle(
      bundle({ connections: [connection({ sealed: { a: shared, b: shared } })] }),
    );
    const at = lookup(buffer, connectionId(UUID_ONE)) ?? 0;

    expect(descriptorAt(buffer, fieldDescriptorOffset(at, 0)).strsOffset).not.toBe(
      descriptorAt(buffer, fieldDescriptorOffset(at, 1)).strsOffset,
    );
  });

  it("stores a connection with no sealed fields at all", () => {
    const buffer = writeBundle(bundle({ connections: [connection({ sealed: {} })] }));
    const at = lookup(buffer, connectionId(UUID_ONE)) ?? 0;

    expect(viewOf(buffer).getUint32(at + CONN_OFFSET.FIELD_COUNT, true)).toBe(0);
    expect(fieldNamesOf(buffer, at)).toEqual([]);
  });

  it.each([
    [
      "a group that is not in the bundle",
      { groupId: "00000000-0000-4000-8000-000000000000" },
      RangeError,
    ],
    [
      "an envelope with the wrong algorithm",
      { sealed: { a: "aes-gcm:AAAA" as SealedEnvelope } },
      RangeError,
    ],
    [
      "an envelope with no algorithm at all",
      { sealed: { a: "AAAA" as SealedEnvelope } },
      RangeError,
    ],
    [
      "an envelope shorter than its own overhead",
      { sealed: { a: `${SEAL_ALGORITHM}:${base64Encode(bytes(59, 1))}` as SealedEnvelope } },
      RangeError,
    ],
    ["a filter index past the filter list", { filters: [0] }, RangeError],
    ["a fractional filter index", { filters: [0.5] }, RangeError],
    ["a negative filter index", { filters: [-1] }, RangeError],
    ["a non-finite visible number", { visible: { rate: Number.POSITIVE_INFINITY } }, RangeError],
    ["a fractional expires_at", { expiresAt: 1.5 }, RangeError],
    ["a negative expires_at", { expiresAt: -1 }, RangeError],
    ["a connection id that is not <shard>_<uuid>", { connectionId: "not-an-id" }, Error],
  ])("refuses %s", (_label, overrides, expected) => {
    expect(() => writeBundle(bundle({ connections: [connection(overrides)] }))).toThrow(expected);
  });

  it("refuses more sealed fields than a record holds", () => {
    const sealed = Object.fromEntries(
      Array.from({ length: 9 }, (_unused, index) => [`field_${index}`, envelope(1, index)]),
    );
    expect(() => writeBundle(bundle({ connections: [connection({ sealed })] }))).toThrow(
      BundleCapacityError,
    );
  });

  it("refuses a visible key longer than its length prefix", () => {
    const visible = { ["k".repeat(70000)]: "v" };
    expect(() => writeBundle(bundle({ connections: [connection({ visible })] }))).toThrow(
      RangeError,
    );
  });

  it("refuses a field name longer than its length prefix", () => {
    const sealed = { ["x".repeat(70000)]: envelope(1) };
    expect(() => writeBundle(bundle({ connections: [connection({ sealed })] }))).toThrow(
      RangeError,
    );
  });

  it("refuses two connections with the same id", () => {
    expect(() =>
      writeBundle(
        bundle({ connections: [connection(), connection({ target: "https://b.test" })] }),
      ),
    ).toThrow(RangeError);
  });
});

// ---------------------------------------------------------------------------
// GRUP
// ---------------------------------------------------------------------------

describe("a key group record", () => {
  it("stores the public half in the clear, with the group's own generation", () => {
    const publicKey = asPublicKey(bytes(32, 0x2a));
    const buffer = writeBundle(bundle({ groups: [group(GROUP_A, { publicKey, generation: 4 })] }));
    const at = grupRecordOffset(section(buffer, SECTION_KIND.GRUP).offset, 0);

    expect([...buffer.subarray(at + GRUP_OFFSET.GROUP_ID, at + GRUP_OFFSET.GROUP_ID + 16)]).toEqual(
      [...hexDecode(GROUP_A.replaceAll("-", ""))],
    );
    expect([
      ...buffer.subarray(at + GRUP_OFFSET.PUBLIC_KEY, at + GRUP_OFFSET.PUBLIC_KEY + 32),
    ]).toEqual([...publicKey]);
    expect(viewOf(buffer).getUint32(at + GRUP_OFFSET.GENERATION, true)).toBe(4);
  });

  it("writes a counter of zero as zero, and never invents one", () => {
    // `KeyGroup.generation` is required, so zero here is a claim the caller
    // made — a group that has never rotated — not a field the writer filled in.
    const buffer = writeBundle(bundle({ groups: [group(GROUP_A, { generation: 0 })] }));
    const at = grupRecordOffset(section(buffer, SECTION_KIND.GRUP).offset, 0);
    expect(viewOf(buffer).getUint32(at + GRUP_OFFSET.GENERATION, true)).toBe(0);
  });

  it("nests every bucket after the fixed-width records", () => {
    const buffer = writeBundle(
      bundle({
        groups: [
          group(GROUP_A, {
            bucket: [
              { keyId: KEY_ID_A, wrapped: bytes(60, 0x11) },
              { keyId: KEY_ID_B, wrapped: bytes(60, 0x22) },
            ],
          }),
          group(GROUP_B),
        ],
      }),
    );
    const view = viewOf(buffer);
    const grup = section(buffer, SECTION_KIND.GRUP);
    const first = grupRecordOffset(grup.offset, 0);
    const second = grupRecordOffset(grup.offset, 1);

    expect(view.getUint32(first + GRUP_OFFSET.BUCKET_COUNT, true)).toBe(2);
    expect(view.getUint32(first + GRUP_OFFSET.BUCKET_OFFSET, true)).toBe(
      grup.offset + 2 * GRUP_RECORD_BYTES,
    );
    expect(view.getUint32(second + GRUP_OFFSET.BUCKET_OFFSET, true)).toBe(
      grup.offset + 2 * GRUP_RECORD_BYTES + 2 * BUCKET_ENTRY_BYTES,
    );
  });

  it("stores each bucket entry's key id and wrapped private half", () => {
    const wrapped = bytes(60, 0x33);
    const buffer = writeBundle(
      bundle({ groups: [group(GROUP_A, { bucket: [{ keyId: KEY_ID_B, wrapped }] })] }),
    );
    const view = viewOf(buffer);
    const record = grupRecordOffset(section(buffer, SECTION_KIND.GRUP).offset, 0);
    const entry = bucketEntryOffset(view.getUint32(record + GRUP_OFFSET.BUCKET_OFFSET, true), 0);

    expect([
      ...buffer.subarray(
        entry + BUCKET_ENTRY_OFFSET.KEY_ID,
        entry + BUCKET_ENTRY_OFFSET.KEY_ID + 16,
      ),
    ]).toEqual([...hexDecode(KEY_ID_B)]);
    const wrappedOffset = view.getUint32(entry + BUCKET_ENTRY_OFFSET.WRAPPED_OFFSET, true);
    const wrappedLength = view.getUint32(entry + BUCKET_ENTRY_OFFSET.WRAPPED_LENGTH, true);
    expect(wrappedLength).toBe(60);
    expect([...buffer.subarray(wrappedOffset, wrappedOffset + wrappedLength)]).toEqual([
      ...wrapped,
    ]);
  });

  it("gives the private half a scratch slot that overlaps no bucket entry", () => {
    const buffer = writeBundle(
      bundle({
        groups: [
          group(GROUP_A, {
            bucket: [
              { keyId: KEY_ID_A, wrapped: bytes(60, 0x11) },
              { keyId: KEY_ID_B, wrapped: bytes(76, 0x22) },
            ],
          }),
        ],
      }),
    );
    const view = viewOf(buffer);
    const record = grupRecordOffset(section(buffer, SECTION_KIND.GRUP).offset, 0);
    const descriptor = descriptorAt(buffer, record + GRUP_OFFSET.PRIVATE_DESCRIPTOR);
    const bucketOffset = view.getUint32(record + GRUP_OFFSET.BUCKET_OFFSET, true);

    // Sized by the widest entry, so an unwrap of either one fits.
    expect(descriptor.sealedLen).toBe(76);
    expect(descriptor.state).toBe(0);
    expect(descriptor.plainLen).toBe(0);
    for (let index = 0; index < 2; index += 1) {
      const entry = bucketEntryOffset(bucketOffset, index);
      const wrappedOffset = view.getUint32(entry + BUCKET_ENTRY_OFFSET.WRAPPED_OFFSET, true);
      const wrappedLength = view.getUint32(entry + BUCKET_ENTRY_OFFSET.WRAPPED_LENGTH, true);
      const disjoint =
        descriptor.strsOffset + descriptor.sealedLen <= wrappedOffset ||
        wrappedOffset + wrappedLength <= descriptor.strsOffset;
      expect(disjoint).toBe(true);
    }
  });

  it.each([
    ["an id that is not a UUID", { groupId: "not-a-uuid" }],
    ["a public key that is not 32 bytes", { publicKey: bytes(31, 1) as PublicKey }],
    ["a generation that is not a uint32", { generation: -1 }],
    ["an empty bucket", { bucket: [] }],
    [
      "a key id that is not 32 hex characters",
      { bucket: [{ keyId: "abc", wrapped: bytes(60, 1) }] },
    ],
    ["an uppercase key id", { bucket: [{ keyId: KEY_ID_A.toUpperCase(), wrapped: bytes(60, 1) }] }],
    [
      "the same key id twice",
      {
        bucket: [
          { keyId: KEY_ID_A, wrapped: bytes(60, 1) },
          { keyId: KEY_ID_A, wrapped: bytes(60, 2) },
        ],
      },
    ],
  ])("refuses %s", (_label, overrides) => {
    expect(() => writeBundle(bundle({ groups: [group(GROUP_A, overrides)] }))).toThrow(RangeError);
  });

  it("refuses the same group twice", () => {
    expect(() => writeBundle(bundle({ groups: [group(GROUP_A), group(GROUP_A)] }))).toThrow(
      RangeError,
    );
  });
});

// ---------------------------------------------------------------------------
// FILT and STRS
// ---------------------------------------------------------------------------

describe("the filter section", () => {
  it("stores a kind and a pointer to arguments held in the arena", () => {
    const args = bytes(5, 0x77);
    const buffer = writeBundle(
      bundle({ filters: [{ kind: 3, args }], connections: [connection({ filters: [0] })] }),
    );
    const view = viewOf(buffer);
    const at = filtEntryOffset(section(buffer, SECTION_KIND.FILT).offset, 0);

    expect(view.getUint32(at + FILT_ENTRY_OFFSET.KIND, true)).toBe(3);
    expect(view.getUint32(at + FILT_ENTRY_OFFSET.ARGS_LENGTH, true)).toBe(5);
    const argsOffset = view.getUint32(at + FILT_ENTRY_OFFSET.ARGS_OFFSET, true);
    expect([...buffer.subarray(argsOffset, argsOffset + 5)]).toEqual([...args]);
  });

  it("refuses a kind that is not a uint32", () => {
    expect(() => writeBundle(bundle({ filters: [{ kind: -1, args: bytes(1, 1) }] }))).toThrow(
      RangeError,
    );
  });
});

describe("the value arena", () => {
  it("stores a value repeated across connections exactly once", () => {
    const buffer = writeBundle(
      bundle({
        connections: [connection(), connection({ connectionId: connectionId(UUID_TWO) })],
      }),
    );
    const view = viewOf(buffer);
    const first = lookup(buffer, connectionId(UUID_ONE)) ?? 0;
    const second = lookup(buffer, connectionId(UUID_TWO)) ?? 0;

    expect(view.getUint32(second + CONN_OFFSET.TARGET_OFFSET, true)).toBe(
      view.getUint32(first + CONN_OFFSET.TARGET_OFFSET, true),
    );
    expect(view.getUint32(second + CONN_OFFSET.VISIBLE_OFFSET, true)).toBe(
      view.getUint32(first + CONN_OFFSET.VISIBLE_OFFSET, true),
    );
  });

  it("interns a value larger than one hashing chunk", () => {
    const target = `https://${"a".repeat(9000)}.test`;
    const buffer = writeBundle(
      bundle({
        connections: [
          connection({ target }),
          connection({ connectionId: connectionId(UUID_TWO), target }),
        ],
      }),
    );
    const view = viewOf(buffer);
    const first = lookup(buffer, connectionId(UUID_ONE)) ?? 0;
    const second = lookup(buffer, connectionId(UUID_TWO)) ?? 0;

    expect(targetOf(buffer, first)).toBe(target);
    expect(view.getUint32(second + CONN_OFFSET.TARGET_OFFSET, true)).toBe(
      view.getUint32(first + CONN_OFFSET.TARGET_OFFSET, true),
    );
  });

  it("holds utf-8, not latin-1", () => {
    const buffer = writeBundle(
      bundle({ connections: [connection({ visible: { region: "Köln — 東京" } })] }),
    );
    expect(visibleOf(buffer, lookup(buffer, connectionId(UUID_ONE)) ?? 0)).toEqual({
      region: "Köln — 東京",
    });
  });
});

// ---------------------------------------------------------------------------
// Size, capacity and the checksum
// ---------------------------------------------------------------------------

describe("measureBundle", () => {
  it("predicts the exact length writeBundle produces", () => {
    const input = bundle({
      groups: [group(GROUP_A), group(GROUP_B)],
      connections: [
        connection(),
        connection({
          connectionId: connectionId(UUID_TWO),
          groupId: GROUP_B,
          sealed: { a: envelope(3), b: envelope(300) },
          filters: [0],
        }),
      ],
      filters: [{ kind: 1, args: bytes(8, 3) }],
    });
    expect(measureBundle(input)).toBe(writeBundle(input).byteLength);
  });

  it("measures an empty generation", () => {
    const input = bundle({ groups: [], connections: [], filters: [] });
    expect(measureBundle(input)).toBe(writeBundle(input).byteLength);
    expect(writeBundle(input).byteLength).toBe(HEADER_BYTES + 5 * 16 + 8 * 8);
  });

  it("refuses a generation over the ten mebibyte cap", () => {
    const input = bundle({
      connections: [connection({ visible: { blob: "x".repeat(BUNDLE_MAX_BYTES + 1) } })],
    });
    expect(() => measureBundle(input)).toThrow(BundleCapacityError);
    expect(() => writeBundle(input)).toThrow(/over the 10485760 byte limit/);
  });
});

describe("the checksum", () => {
  it("covers everything after the header", async () => {
    const buffer = writeBundle(bundle());
    const before = await computeChecksum(buffer);

    buffer[buffer.byteLength - 1] = (buffer[buffer.byteLength - 1] ?? 0) ^ 0xff;
    const after = await computeChecksum(buffer);

    expect(before.byteLength).toBe(CHECKSUM_BYTES);
    expect([...after]).not.toEqual([...before]);
  });

  it("ignores the header, so stamping it does not invalidate it", async () => {
    const buffer = await writeBundleWithChecksum(bundle());
    const stamped = buffer.subarray(
      HEADER_OFFSET.CHECKSUM,
      HEADER_OFFSET.CHECKSUM + CHECKSUM_BYTES,
    );
    expect([...(await computeChecksum(buffer))]).toEqual([...stamped]);
    expect(stamped.some((byte) => byte !== 0)).toBe(true);
  });

  it("is the SHA-256 prefix of the bytes after the header", async () => {
    const buffer = writeBundle(bundle());
    const digest = new Uint8Array(
      await globalThis.crypto.subtle.digest(
        "SHA-256",
        new Uint8Array(buffer.subarray(HEADER_BYTES)),
      ),
    );
    expect([...(await computeChecksum(buffer))]).toEqual([...digest.slice(0, CHECKSUM_BYTES)]);
  });

  it("digests a shared buffer to the same value as a plain one", async () => {
    // Web Crypto rejects a view over a SharedArrayBuffer outright, so the writer
    // has to snapshot it; the digest must still be the digest of those bytes.
    const buffer = writeBundle(bundle());
    const shared = new Uint8Array(new SharedArrayBuffer(buffer.byteLength));
    shared.set(buffer);

    expect([...(await computeChecksum(shared))]).toEqual([...(await computeChecksum(buffer))]);
  });

  it("refuses a checksum of the wrong width", () => {
    const buffer = writeBundle(bundle());
    expect(() => writeChecksum(buffer, bytes(CHECKSUM_BYTES - 1, 1))).toThrow(RangeError);
  });

  it.each([
    ["computeChecksum", async (buffer: Uint8Array) => computeChecksum(buffer)],
    [
      "writeChecksum",
      async (buffer: Uint8Array) => writeChecksum(buffer, bytes(CHECKSUM_BYTES, 1)),
    ],
  ])("refuses a buffer too short to hold a header in %s", async (_label, act) => {
    await expect(act(bytes(HEADER_BYTES - 1, 0))).rejects.toThrow(RangeError);
  });
});

describe("writeBundleWithChecksum", () => {
  it("produces the same bytes as writeBundle, plus the stamp", async () => {
    const input = bundle();
    const plain = writeBundle(input);
    const stamped = await writeBundleWithChecksum(input);

    expect(stamped.byteLength).toBe(plain.byteLength);
    expect([...stamped.subarray(HEADER_BYTES)]).toEqual([...plain.subarray(HEADER_BYTES)]);
    expect([...stamped.subarray(0, HEADER_OFFSET.CHECKSUM)]).toEqual([
      ...plain.subarray(0, HEADER_OFFSET.CHECKSUM),
    ]);
  });
});
