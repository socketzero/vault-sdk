import { describe, expect, it } from "vitest";
import { BundleCapacityError, BundleFormatError } from "../types.js";
import {
  BUCKET_ENTRY_BYTES,
  BUNDLE_MAGIC,
  BUNDLE_MAGIC_BYTES,
  bucketEntryOffset,
  bucketOf,
  CHECKSUM_BYTES,
  CONN_HEADER_BYTES,
  CONN_MAX_FIELDS,
  CONN_RECORD_BYTES,
  CONNECTION_ID_BYTES,
  connRecordOffset,
  FIELD_DESCRIPTOR_BYTES,
  FILT_ENTRY_BYTES,
  fieldDescriptorOffset,
  filtEntryOffset,
  GRUP_RECORD_BYTES,
  grupRecordOffset,
  HEADER_BYTES,
  HEADER_OFFSET,
  INDEX_MAX_SLOTS,
  INDEX_MIN_SLOTS,
  INDEX_MIN_SLOTS_PER_CONNECTION,
  INDEX_SLOT_BYTES,
  indexSlotCount,
  indexSlotOffset,
  parseConnectionId,
  SECTION_ENTRY_BYTES,
  SECTION_KIND,
  SECTION_TABLE_OFFSET,
  SHARD_PREFIX_BYTES,
  sectionEntryOffset,
  sectionKindName,
  uuidHigh32,
  uuidLow32,
} from "./layout.js";

/** `0192f3a4-b5c6-7d8e-9f01-234567890abc` under the shard `abcd`. */
const SAMPLE_ID = "abcd_0192f3a4-b5c6-7d8e-9f01-234567890abc";
const SAMPLE_UUID = Uint8Array.from([
  0x01, 0x92, 0xf3, 0xa4, 0xb5, 0xc6, 0x7d, 0x8e, 0x9f, 0x01, 0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc,
]);

describe("header constants", () => {
  it("spells the magic identically as text and as bytes", () => {
    expect(new TextDecoder().decode(BUNDLE_MAGIC_BYTES)).toBe(BUNDLE_MAGIC);
    expect(BUNDLE_MAGIC_BYTES).toHaveLength(8);
  });

  it("fits every header field, checksum included, inside the fixed 64 bytes", () => {
    expect(HEADER_OFFSET.CHECKSUM + CHECKSUM_BYTES).toBe(HEADER_BYTES);
    expect(HEADER_OFFSET.SHARD + SHARD_PREFIX_BYTES).toBe(HEADER_OFFSET.BUILT_AT);
  });

  it("starts the section table immediately after the header", () => {
    expect(SECTION_TABLE_OFFSET).toBe(HEADER_BYTES);
  });
});

describe("record widths", () => {
  it("keeps a connection record fixed width, which is what makes it addressable", () => {
    expect(CONN_RECORD_BYTES).toBe(CONN_HEADER_BYTES + CONN_MAX_FIELDS * FIELD_DESCRIPTOR_BYTES);
  });
});

describe("sectionKindName", () => {
  it("decodes each kind back to the four characters it was built from", () => {
    expect(sectionKindName(SECTION_KIND.INDX)).toBe("INDX");
    expect(sectionKindName(SECTION_KIND.CONN)).toBe("CONN");
    expect(sectionKindName(SECTION_KIND.GRUP)).toBe("GRUP");
    expect(sectionKindName(SECTION_KIND.FILT)).toBe("FILT");
    expect(sectionKindName(SECTION_KIND.STRS)).toBe("STRS");
  });

  it("replaces bytes that are not printable ASCII, so a corrupt kind is log-safe", () => {
    expect(sectionKindName(0x00_00_00_41)).toBe("A???");
    expect(sectionKindName(0xff_7f_20_7e)).toBe("~ ??");
  });

  it("rejects a value that is not a uint32", () => {
    expect(() => sectionKindName(-1)).toThrow(BundleFormatError);
    expect(() => sectionKindName(1.5)).toThrow(BundleFormatError);
    expect(() => sectionKindName(0x1_0000_0000)).toThrow(BundleFormatError);
  });
});

describe("indexSlotCount", () => {
  it("gives an empty shard the floor rather than an unmaskable table", () => {
    expect(indexSlotCount(0)).toBe(INDEX_MIN_SLOTS);
  });

  it("gives a single connection the floor too, not 4 slots", () => {
    expect(indexSlotCount(1)).toBe(INDEX_MIN_SLOTS);
    expect(indexSlotCount(2)).toBe(INDEX_MIN_SLOTS);
  });

  it("rounds up to the next power of two once 4x the count exceeds the floor", () => {
    expect(indexSlotCount(3)).toBe(16);
    expect(indexSlotCount(4)).toBe(16);
    expect(indexSlotCount(5)).toBe(32);
    expect(indexSlotCount(1000)).toBe(4096);
  });

  it("never lets the load factor exceed 0.25", () => {
    for (let count = 0; count <= 300; count += 1) {
      const slots = indexSlotCount(count);
      expect(slots).toBeGreaterThanOrEqual(count * INDEX_MIN_SLOTS_PER_CONNECTION);
      expect(slots & (slots - 1)).toBe(0);
    }
  });

  it("fills the shard's table exactly at capacity", () => {
    const capacity = INDEX_MAX_SLOTS / INDEX_MIN_SLOTS_PER_CONNECTION;
    expect(indexSlotCount(capacity)).toBe(INDEX_MAX_SLOTS);
    expect(() => indexSlotCount(capacity + 1)).toThrow(BundleCapacityError);
  });

  it("rejects a count that is not a non-negative integer", () => {
    expect(() => indexSlotCount(-1)).toThrow(BundleFormatError);
    expect(() => indexSlotCount(2.5)).toThrow(BundleFormatError);
    expect(() => indexSlotCount(Number.NaN)).toThrow(BundleFormatError);
  });
});

describe("bucketOf", () => {
  it("masks the low bits and nothing else", () => {
    expect(bucketOf(0x0000_1234, 8)).toBe(4);
    expect(bucketOf(0xffff_ffff, 16)).toBe(15);
    expect(bucketOf(0x0000_0000, INDEX_MAX_SLOTS)).toBe(0);
  });

  it("ignores the high bits entirely, so the fingerprint stays independent", () => {
    expect(bucketOf(0xffff_ff05, 8)).toBe(bucketOf(0x0000_0005, 8));
  });

  it("rejects a slot count that is not a positive power of two", () => {
    expect(() => bucketOf(1, 0)).toThrow(BundleFormatError);
    expect(() => bucketOf(1, -8)).toThrow(BundleFormatError);
    expect(() => bucketOf(1, 12)).toThrow(BundleFormatError);
    expect(() => bucketOf(1, 8.5)).toThrow(BundleFormatError);
    expect(() => bucketOf(1, 2 ** 31)).toThrow(BundleFormatError);
  });

  it("rejects a low word that is not a uint32", () => {
    expect(() => bucketOf(-1, 8)).toThrow(BundleFormatError);
  });
});

describe("uuidHigh32 and uuidLow32", () => {
  it("reads the first and last four bytes big-endian", () => {
    expect(uuidHigh32(SAMPLE_UUID)).toBe(0x0192f3a4);
    expect(uuidLow32(SAMPLE_UUID)).toBe(0x67890abc);
  });

  it("stays unsigned when the top bit is set", () => {
    const high = new Uint8Array(CONNECTION_ID_BYTES).fill(0xff);
    expect(uuidHigh32(high)).toBe(0xffffffff);
    expect(uuidLow32(high)).toBe(0xffffffff);
  });

  it("reads through a view's own offset rather than the whole backing buffer", () => {
    const backing = new Uint8Array(CONNECTION_ID_BYTES + 8);
    backing.set(SAMPLE_UUID, 5);
    const view = backing.subarray(5, 5 + CONNECTION_ID_BYTES);
    expect(uuidHigh32(view)).toBe(0x0192f3a4);
    expect(uuidLow32(view)).toBe(0x67890abc);
  });

  it("rejects anything that is not sixteen bytes", () => {
    expect(() => uuidHigh32(new Uint8Array(15))).toThrow(BundleFormatError);
    expect(() => uuidLow32(new Uint8Array(17))).toThrow(BundleFormatError);
  });
});

describe("offset arithmetic", () => {
  it("strides each section by its own record width", () => {
    expect(indexSlotOffset(1024, 0)).toBe(1024);
    expect(indexSlotOffset(1024, 3)).toBe(1024 + 3 * INDEX_SLOT_BYTES);
    expect(sectionEntryOffset(0)).toBe(SECTION_TABLE_OFFSET);
    expect(sectionEntryOffset(4)).toBe(SECTION_TABLE_OFFSET + 4 * SECTION_ENTRY_BYTES);
    expect(connRecordOffset(2048, 7)).toBe(2048 + 7 * CONN_RECORD_BYTES);
    expect(grupRecordOffset(4096, 2)).toBe(4096 + 2 * GRUP_RECORD_BYTES);
    expect(bucketEntryOffset(512, 3)).toBe(512 + 3 * BUCKET_ENTRY_BYTES);
    expect(filtEntryOffset(256, 5)).toBe(256 + 5 * FILT_ENTRY_BYTES);
  });

  it("places field descriptors after the fixed part of the record", () => {
    expect(fieldDescriptorOffset(2048, 0)).toBe(2048 + CONN_HEADER_BYTES);
    expect(fieldDescriptorOffset(2048, CONN_MAX_FIELDS - 1)).toBe(
      2048 + CONN_RECORD_BYTES - FIELD_DESCRIPTOR_BYTES,
    );
  });

  it("refuses a field index that would run into the next record", () => {
    expect(() => fieldDescriptorOffset(2048, CONN_MAX_FIELDS)).toThrow(BundleFormatError);
    expect(() => fieldDescriptorOffset(2048, -1)).toThrow(BundleFormatError);
    expect(() => fieldDescriptorOffset(2048, 1.5)).toThrow(BundleFormatError);
  });
});

describe("parseConnectionId", () => {
  it("splits the shard prefix from the sixteen UUID bytes", () => {
    const parsed = parseConnectionId(SAMPLE_ID);
    expect(parsed.shard).toBe("abcd");
    expect(parsed.uuid).toEqual(SAMPLE_UUID);
  });

  it("produces the bytes the index addresses with", () => {
    const { uuid } = parseConnectionId(SAMPLE_ID);
    expect(uuidHigh32(uuid)).toBe(0x0192f3a4);
    expect(bucketOf(uuidLow32(uuid), 8)).toBe(0xbc & 7);
  });

  it("handles the all-zero and all-f UUIDs", () => {
    expect(parseConnectionId("aaaa_00000000-0000-0000-0000-000000000000").uuid).toEqual(
      new Uint8Array(CONNECTION_ID_BYTES),
    );
    expect(parseConnectionId("zzzz_ffffffff-ffff-ffff-ffff-ffffffffffff").uuid).toEqual(
      new Uint8Array(CONNECTION_ID_BYTES).fill(0xff),
    );
  });

  it.each([
    ["empty", ""],
    ["no shard", "0192f3a4-b5c6-7d8e-9f01-234567890abc"],
    ["short shard", "abc_0192f3a4-b5c6-7d8e-9f01-234567890abc"],
    ["long shard", "abcde_0192f3a4-b5c6-7d8e-9f01-234567890abc"],
    ["uppercase shard", "ABCD_0192f3a4-b5c6-7d8e-9f01-234567890abc"],
    ["uppercase uuid", "abcd_0192F3A4-b5c6-7d8e-9f01-234567890abc"],
    ["hyphen instead of underscore", "abcd-0192f3a4-b5c6-7d8e-9f01-234567890abc"],
    ["unhyphenated uuid", "abcd_0192f3a4b5c67d8e9f01234567890abc"],
    ["misplaced hyphens", "abcd_0192f3a4-b5c67d8e-9f01-2345-67890abc"],
    ["truncated uuid", "abcd_0192f3a4-b5c6-7d8e-9f01-234567890ab"],
    ["trailing text", "abcd_0192f3a4-b5c6-7d8e-9f01-234567890abc "],
  ])("rejects %s", (_label, id) => {
    expect(() => parseConnectionId(id)).toThrow(BundleFormatError);
  });
});
