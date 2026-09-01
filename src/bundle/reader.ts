/**
 * The bundle reader. Used by the shard on the hot path, and by tooling offline.
 *
 * **The bundle is never deserialised.** There is no parse step, no object graph
 * and no instantiation. `readBundle` returns accessors that compute offsets and
 * read through one `DataView` over the caller's buffer, for the life of the
 * isolate. A 10 MiB bundle materialised as objects would end the isolate.
 *
 * A reader must not deserialise, must not copy, must not eagerly open, and must
 * not trust an unknown `version`.
 *
 * ## The variable-length encodings this reader agrees with the writer on
 *
 * `layout.ts` fixes every fixed-width record. It does not fix the three packed
 * blobs those records point at, so they are written down here, once:
 *
 * - **visible map** — `VISIBLE_OFFSET .. +VISIBLE_LENGTH`, a run of entries:
 *   `type u8 | key_len u16 | key utf8 | value`, where the value is
 *   `len u32 || utf8` for type 0, a `float64` for type 1, and a `u8` for type 2.
 *   A packed scan of a handful of entries, rather than JSON, because the shard
 *   routes and refuses on this before touching any secret — a `JSON.parse` per
 *   request is exactly the per-record allocation the format exists to avoid.
 * - **field names** — `FIELD_NAMES_OFFSET`, `FIELD_COUNT` entries of
 *   `name_len u16 | name utf8`, positionally matching the record's descriptors.
 * - **filter indices** — `FILTERS_OFFSET`, `FILTERS_COUNT` little-endian `u32`.
 *
 * Every `*_OFFSET` into `STRS` is **absolute**, not relative to the section.
 * `writeBackPlaintext` is handed a buffer and a descriptor and nothing else, so
 * a descriptor's `strs_offset` has to stand on its own; the rest follow it for
 * consistency.
 */

import { hexDecode, hexEncode, timingSafeEqual, utf8Decode, utf8Encode } from "../encoding.js";
import {
  type BucketEntryView,
  BundleFormatError,
  type BundleHeader,
  type BundleView,
  type ConnectionRecord,
  type FieldDescriptor,
  FieldState,
  type FilterArgsView,
  type KeyGroupView,
  type SectionEntry,
  type SectionKindName,
  UnsupportedBundleVersionError,
  type VisibleValue,
} from "../types.js";
import {
  BUCKET_ENTRY_OFFSET,
  BUNDLE_MAGIC,
  BUNDLE_MAGIC_BYTES,
  BUNDLE_VERSION,
  bucketEntryOffset,
  bucketOf,
  CHECKSUM_ALGORITHM,
  CHECKSUM_BYTES,
  CONN_OFFSET,
  CONN_RECORD_BYTES,
  CONNECTION_ID_BYTES,
  FIELD_DESCRIPTOR_BYTES,
  FIELD_DESCRIPTOR_OFFSET,
  FILT_ENTRY_OFFSET,
  fieldDescriptorOffset,
  filtEntryOffset,
  GRUP_OFFSET,
  grupRecordOffset,
  HEADER_BYTES,
  HEADER_OFFSET,
  INDEX_EMPTY_SLOT,
  INDEX_SLOT_BYTES,
  INDEX_SLOT_OFFSET,
  indexSlotOffset,
  KEY_ID_BYTES,
  parseConnectionId,
  SECTION_ENTRY_BYTES,
  SECTION_ENTRY_OFFSET,
  SECTION_KIND,
  SECTION_TABLE_OFFSET,
  SHARD_PREFIX_BYTES,
  sectionEntryOffset,
  sectionKindName,
  uuidHigh32,
  uuidLow32,
} from "./layout.js";

/** The three value types a `visible` entry can carry. */
const VISIBLE_TYPE = {
  String: 0,
  Number: 1,
  Boolean: 2,
} as const;

/** K1's public half, in the clear. */
const PUBLIC_KEY_BYTES = 32;

/** A group id is a UUID, and `groupById` accepts only its canonical form. */
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A key id as the API writes it: 32 lowercase hex characters. */
const KEY_ID_PATTERN = /^[0-9a-f]{32}$/;

// ---------------------------------------------------------------------------
// Free functions over a raw buffer
// ---------------------------------------------------------------------------

/** A view over the whole of `bytes`, whichever slice of an ArrayBuffer it is. */
function viewOf(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

/**
 * Bound a read inside the blob it belongs to, not merely inside the buffer.
 *
 * A length that runs past its own section still lands on readable bytes, so a
 * `DataView` would happily return the neighbouring record's data instead of
 * failing.
 */
function need(cursor: number, bytesNeeded: number, end: number, what: string): void {
  if (cursor + bytesNeeded > end) {
    throw new BundleFormatError(`${what} runs past the end of its section`);
  }
}

/** Read one field descriptor in place. */
export function readFieldDescriptor(buffer: Uint8Array, descriptorOffset: number): FieldDescriptor {
  if (
    !Number.isInteger(descriptorOffset) ||
    descriptorOffset < 0 ||
    descriptorOffset + FIELD_DESCRIPTOR_BYTES > buffer.byteLength
  ) {
    throw new RangeError(`field descriptor offset ${descriptorOffset} is outside the buffer`);
  }
  const view = viewOf(buffer);
  const state = view.getUint8(descriptorOffset + FIELD_DESCRIPTOR_OFFSET.STATE);
  if (state !== FieldState.Sealed && state !== FieldState.Open) {
    throw new BundleFormatError(`a field descriptor's state is 0 or 1, got ${state}`);
  }
  return {
    descriptorOffset,
    strsOffset: view.getUint32(descriptorOffset + FIELD_DESCRIPTOR_OFFSET.STRS_OFFSET, true),
    sealedLen: view.getUint32(descriptorOffset + FIELD_DESCRIPTOR_OFFSET.SEALED_LEN, true),
    plainLen: view.getUint32(descriptorOffset + FIELD_DESCRIPTOR_OFFSET.PLAIN_LEN, true),
    state,
  };
}

/**
 * Write plaintext into the slot its own ciphertext occupied, and publish it.
 *
 * Order is load-bearing and synchronous: the plaintext bytes, then `plain_len`,
 * then `state = 1`, with no `await` between them. A reader that sees `state == 1`
 * must be guaranteed the bytes and the length are already there.
 *
 * The write always fits: an envelope is exactly 60 bytes larger than its
 * plaintext, unconditionally. The check below is against `sealedLen` rather than
 * `sealedLen - 60` because a group's wrapped private half occupies a slot of the
 * same shape and carries only 28 bytes of overhead.
 *
 * A duplicated open is harmless — two callers write identical bytes to identical
 * offsets and the second flag write is a no-op — which is why there is no lock
 * on this path.
 *
 * @param buffer the buffer the caller *started* from. The unwrap is async and a
 *   refresh can swap the active buffer mid-flight; writing into the newly active
 *   one would place plaintext at an offset that means something else.
 * @returns the descriptor as it now reads.
 * @throws {RangeError} if the plaintext does not fit the sealed slot.
 */
export function writeBackPlaintext(
  buffer: Uint8Array,
  descriptor: FieldDescriptor,
  plaintext: Uint8Array,
): FieldDescriptor {
  if (plaintext.byteLength > descriptor.sealedLen) {
    throw new RangeError(
      `plaintext of ${plaintext.byteLength} bytes does not fit a ${descriptor.sealedLen}-byte slot`,
    );
  }
  if (
    descriptor.strsOffset < 0 ||
    descriptor.strsOffset + plaintext.byteLength > buffer.byteLength
  ) {
    throw new RangeError(`the field's slot at ${descriptor.strsOffset} is outside the buffer`);
  }
  if (
    descriptor.descriptorOffset < 0 ||
    descriptor.descriptorOffset + FIELD_DESCRIPTOR_BYTES > buffer.byteLength
  ) {
    throw new RangeError(
      `field descriptor offset ${descriptor.descriptorOffset} is outside the buffer`,
    );
  }

  const view = viewOf(buffer);
  // One synchronous block: nothing may suspend between these three writes, and
  // the flag is published last so a concurrent reader never sees a half-open
  // field.
  buffer.set(plaintext, descriptor.strsOffset);
  view.setUint32(
    descriptor.descriptorOffset + FIELD_DESCRIPTOR_OFFSET.PLAIN_LEN,
    plaintext.byteLength,
    true,
  );
  view.setUint8(descriptor.descriptorOffset + FIELD_DESCRIPTOR_OFFSET.STATE, FieldState.Open);

  return {
    descriptorOffset: descriptor.descriptorOffset,
    strsOffset: descriptor.strsOffset,
    sealedLen: descriptor.sealedLen,
    plainLen: plaintext.byteLength,
    state: FieldState.Open,
  };
}

/**
 * Zero everything past `length`.
 *
 * Called on every load: after a swap the inactive buffer still holds the
 * previous generation's opened plaintext, and if the new bundle is shorter the
 * tail would never be overwritten at all. Residue must not outlive the
 * generation it belonged to.
 */
export function zeroTail(buffer: Uint8Array, length: number): void {
  if (!Number.isInteger(length) || length < 0 || length > buffer.byteLength) {
    throw new RangeError(`cannot zero past ${length} of a ${buffer.byteLength}-byte buffer`);
  }
  buffer.fill(0, length);
}

// ---------------------------------------------------------------------------
// The decoy unwrap
// ---------------------------------------------------------------------------

/** Fixed decoy material, so the decoy costs the same on every miss. */
const DECOY_KEY_MATERIAL = new Uint8Array(32).fill(0x5a);
const DECOY_SALT = new Uint8Array(16).fill(0xa5);
const DECOY_INFO = utf8Encode("socket0/v1/tmk-wrap");
/** `nonce(12) || ciphertext(32) || tag(16)`, the shape of a real bucket entry. */
const DECOY_ENTRY = new Uint8Array(60);

/**
 * Perform a dummy unwrap against a fixed decoy group.
 *
 * A miss costs one read and a hit costs a read, an unwrap and a decrypt; the
 * difference is observable and says whether a connection id exists. The shard
 * promises every pre-relay refusal is indistinguishable, and that promise has
 * to cover elapsed time. Roughly 0.03 ms, on a path that is already refusing.
 *
 * It derives *and* decrypts, because a real unwrap does both and a decoy that
 * skipped the derivation would leave half the difference measurable.
 */
export async function decoyUnwrap(): Promise<void> {
  const material = await crypto.subtle.importKey("raw", DECOY_KEY_MATERIAL, "HKDF", false, [
    "deriveKey",
  ]);
  const wrapKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: DECOY_SALT, info: DECOY_INFO },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  try {
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: DECOY_ENTRY.subarray(0, 12) },
      wrapKey,
      DECOY_ENTRY.subarray(12),
    );
  } catch {
    // Always fails, by construction. Spending the time is the entire point.
  }
}

// ---------------------------------------------------------------------------
// readBundle
// ---------------------------------------------------------------------------

/**
 * Open a view over a bundle.
 *
 * Validates the magic, the header size and the section table only; the checksum
 * is verified separately via `view.verifyChecksum()`, once, at load.
 *
 * @param buffer the bundle. Held by reference — the view reads and writes back
 *   into these exact bytes.
 * @throws {BundleFormatError} on a bad magic, a truncated header, or a section
 *   table that points outside the buffer.
 * @throws {UnsupportedBundleVersionError} on a version this reader does not
 *   know. Refuse the whole bundle and keep serving the previous generation:
 *   partial understanding of a security artifact is worse than none.
 */
export function readBundle(buffer: Uint8Array | ArrayBuffer): BundleView {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const view = viewOf(bytes);

  const header = readHeader(bytes, view);
  const sections = readSectionTable(bytes, view, header.sections);

  const indx = sections.get(SECTION_KIND.INDX);
  const conn = sections.get(SECTION_KIND.CONN);
  const grup = sections.get(SECTION_KIND.GRUP);
  const filt = sections.get(SECTION_KIND.FILT);

  const slots = indexSlots(indx);
  const connectionCount = conn?.count ?? 0;
  const groupCount = grup?.count ?? 0;

  // ---- shared primitives ------------------------------------------------

  /**
   * A view into the buffer, never a copy: the caller gets the bytes in place.
   *
   * Every offset reaching here was read as a `uint32` or computed from one, so
   * the only way out of the buffer is off the end.
   */
  function slice(offset: number, length: number, what: string): Uint8Array {
    if (offset + length > bytes.byteLength) {
      throw new BundleFormatError(`${what} at ${offset}+${length} is outside the buffer`);
    }
    return bytes.subarray(offset, offset + length);
  }

  function text(offset: number, length: number, what: string): string {
    return utf8Decode(slice(offset, length, what));
  }

  // ---- visible map ------------------------------------------------------

  /**
   * Walk the packed `visible` entries, stopping when `visit` says so.
   *
   * A linear scan, deliberately: the map holds a handful of routing hints, and a
   * per-record hash table would cost more to build at publish time than a scan
   * this short could ever save.
   */
  function walkVisible(
    start: number,
    length: number,
    visit: (key: string, value: VisibleValue) => boolean,
  ): void {
    slice(start, length, "the visible map");
    const end = start + length;
    let cursor = start;

    while (cursor < end) {
      need(cursor, 3, end, "a visible entry");
      const type = view.getUint8(cursor);
      const keyLength = view.getUint16(cursor + 1, true);
      cursor += 3;
      need(cursor, keyLength, end, "a visible key");
      const key = text(cursor, keyLength, "a visible key");
      cursor += keyLength;

      let value: VisibleValue;
      if (type === VISIBLE_TYPE.String) {
        need(cursor, 4, end, "a visible string's length");
        const valueLength = view.getUint32(cursor, true);
        cursor += 4;
        need(cursor, valueLength, end, "a visible string");
        value = text(cursor, valueLength, "a visible string");
        cursor += valueLength;
      } else if (type === VISIBLE_TYPE.Number) {
        need(cursor, 8, end, "a visible number");
        value = view.getFloat64(cursor, true);
        cursor += 8;
      } else if (type === VISIBLE_TYPE.Boolean) {
        need(cursor, 1, end, "a visible boolean");
        value = view.getUint8(cursor) !== 0;
        cursor += 1;
      } else {
        throw new BundleFormatError(`unknown visible value type ${type}`);
      }

      if (visit(key, value)) {
        return;
      }
    }
  }

  // ---- field names ------------------------------------------------------

  /** Walk `count` packed names, handing each one's bytes to `visit` by index. */
  function walkFieldNames(
    start: number,
    count: number,
    visit: (index: number, name: Uint8Array) => boolean,
  ): void {
    let cursor = start;
    for (let index = 0; index < count; index += 1) {
      need(cursor, 2, bytes.byteLength, "a field name's length");
      const nameLength = view.getUint16(cursor, true);
      cursor += 2;
      const name = slice(cursor, nameLength, "a field name");
      cursor += nameLength;
      if (visit(index, name)) {
        return;
      }
    }
  }

  // ---- connection records -----------------------------------------------

  function assertConnRecordOffset(recordOffset: number): void {
    const start = conn?.offset ?? 0;
    const addressable =
      conn !== undefined &&
      recordOffset >= start &&
      recordOffset + CONN_RECORD_BYTES <= start + conn.length &&
      (recordOffset - start) % CONN_RECORD_BYTES === 0;
    if (!addressable) {
      throw new BundleFormatError(`${recordOffset} is not the offset of a connection record`);
    }
  }

  function makeConnectionRecord(recordOffset: number): ConnectionRecord {
    const idOffset = recordOffset + CONN_OFFSET.ID;
    const fieldCount = view.getUint32(recordOffset + CONN_OFFSET.FIELD_COUNT, true);
    const fieldNamesOffset = view.getUint32(recordOffset + CONN_OFFSET.FIELD_NAMES_OFFSET, true);

    return {
      recordOffset,
      groupIndex: view.getUint32(recordOffset + CONN_OFFSET.GROUP_INDEX, true),

      idBytes: () => slice(idOffset, CONNECTION_ID_BYTES, "a connection id"),

      // Four word comparisons through the same view the index used, rather than
      // sixteen byte reads or a copy: the fingerprint is a filter and not a
      // proof, so this runs on every candidate hit.
      matchesId: (id: Uint8Array): boolean => {
        if (id.byteLength !== CONNECTION_ID_BYTES) {
          return false;
        }
        const candidate = viewOf(id);
        for (let word = 0; word < CONNECTION_ID_BYTES; word += 4) {
          if (view.getUint32(idOffset + word, false) !== candidate.getUint32(word, false)) {
            return false;
          }
        }
        return true;
      },

      target: () =>
        text(
          view.getUint32(recordOffset + CONN_OFFSET.TARGET_OFFSET, true),
          view.getUint32(recordOffset + CONN_OFFSET.TARGET_LENGTH, true),
          "the target",
        ),

      visibleKeys: () => {
        const keys: string[] = [];
        walkVisible(
          view.getUint32(recordOffset + CONN_OFFSET.VISIBLE_OFFSET, true),
          view.getUint32(recordOffset + CONN_OFFSET.VISIBLE_LENGTH, true),
          (key) => {
            keys.push(key);
            return false;
          },
        );
        return keys;
      },

      visible: (name: string): VisibleValue | undefined => {
        let found: VisibleValue | undefined;
        walkVisible(
          view.getUint32(recordOffset + CONN_OFFSET.VISIBLE_OFFSET, true),
          view.getUint32(recordOffset + CONN_OFFSET.VISIBLE_LENGTH, true),
          (key, value) => {
            if (key !== name) {
              return false;
            }
            found = value;
            return true;
          },
        );
        return found;
      },

      // Zero means "does not expire": the epoch itself is not a usable expiry.
      expiresAt: () => {
        const millis = view.getBigUint64(recordOffset + CONN_OFFSET.EXPIRES_AT, true);
        return millis === 0n ? null : Number(millis);
      },

      // The one accessor that copies. A run of uint32 in the buffer has no
      // alignment guarantee, so it cannot be aliased by a `Uint32Array`; it is a
      // handful of indices, not a credential.
      filterIndices: () => {
        const start = view.getUint32(recordOffset + CONN_OFFSET.FILTERS_OFFSET, true);
        const count = view.getUint32(recordOffset + CONN_OFFSET.FILTERS_COUNT, true);
        slice(start, count * 4, "the filter indices");
        const indices = new Uint32Array(count);
        for (let i = 0; i < count; i += 1) {
          indices[i] = view.getUint32(start + i * 4, true);
        }
        return indices;
      },

      fieldNames: () => {
        const names: string[] = [];
        walkFieldNames(fieldNamesOffset, fieldCount, (_index, name) => {
          names.push(utf8Decode(name));
          return false;
        });
        return names;
      },

      // Compares encoded bytes rather than decoding every name, so looking up
      // one field does not allocate a string per field it walks past.
      field: (name: string): FieldDescriptor | undefined => {
        const wanted = utf8Encode(name);
        let descriptor: FieldDescriptor | undefined;
        walkFieldNames(fieldNamesOffset, fieldCount, (index, candidate) => {
          if (!timingSafeEqual(wanted, candidate)) {
            return false;
          }
          descriptor = readFieldDescriptor(bytes, fieldDescriptorOffset(recordOffset, index));
          return true;
        });
        return descriptor;
      },

      // Re-reads the descriptor: another request may have opened this field
      // since the caller took its snapshot, and the live flag is what decides
      // whether these bytes are an envelope or the secret.
      fieldBytes: (descriptor: FieldDescriptor): Uint8Array => {
        const live = readFieldDescriptor(bytes, descriptor.descriptorOffset);
        const length = live.state === FieldState.Open ? live.plainLen : live.sealedLen;
        return slice(live.strsOffset, length, "a field");
      },
    };
  }

  function connectionAt(recordOffset: number): ConnectionRecord {
    assertConnRecordOffset(recordOffset);
    return makeConnectionRecord(recordOffset);
  }

  // ---- groups and filters -----------------------------------------------

  function makeBucketEntry(entryOffset: number): BucketEntryView {
    const keyId = (): Uint8Array =>
      slice(entryOffset + BUCKET_ENTRY_OFFSET.KEY_ID, KEY_ID_BYTES, "a key id");
    return {
      entryOffset,
      keyIdBytes: keyId,
      keyIdHex: () => hexEncode(keyId()),
      wrapped: () =>
        slice(
          view.getUint32(entryOffset + BUCKET_ENTRY_OFFSET.WRAPPED_OFFSET, true),
          view.getUint32(entryOffset + BUCKET_ENTRY_OFFSET.WRAPPED_LENGTH, true),
          "a wrapped private half",
        ),
    };
  }

  function group(index: number): KeyGroupView | undefined {
    if (grup === undefined || !Number.isInteger(index) || index < 0 || index >= groupCount) {
      return undefined;
    }
    const recordOffset = grupRecordOffset(grup.offset, index);
    const bucketOffset = view.getUint32(recordOffset + GRUP_OFFSET.BUCKET_OFFSET, true);
    const bucketSize = view.getUint32(recordOffset + GRUP_OFFSET.BUCKET_COUNT, true);
    const groupIdBytes = (): Uint8Array =>
      slice(recordOffset + GRUP_OFFSET.GROUP_ID, CONNECTION_ID_BYTES, "a group id");

    return {
      groupIndex: index,
      recordOffset,
      bucketSize,
      groupIdBytes,
      groupId: () => formatUuid(groupIdBytes()),
      publicKey: () =>
        slice(recordOffset + GRUP_OFFSET.PUBLIC_KEY, PUBLIC_KEY_BYTES, "a public half"),
      generation: () => view.getUint32(recordOffset + GRUP_OFFSET.GENERATION, true),
      bucketEntry: (entryIndex: number): BucketEntryView | undefined =>
        Number.isInteger(entryIndex) && entryIndex >= 0 && entryIndex < bucketSize
          ? makeBucketEntry(bucketEntryOffset(bucketOffset, entryIndex))
          : undefined,
      findBucketEntry: (keyId: string): BucketEntryView | undefined => {
        if (!KEY_ID_PATTERN.test(keyId)) {
          return undefined;
        }
        const wanted = hexDecode(keyId);
        for (let i = 0; i < bucketSize; i += 1) {
          const offset = bucketEntryOffset(bucketOffset, i);
          const candidate = slice(offset + BUCKET_ENTRY_OFFSET.KEY_ID, KEY_ID_BYTES, "a key id");
          if (timingSafeEqual(wanted, candidate)) {
            return makeBucketEntry(offset);
          }
        }
        return undefined;
      },
      privateKeyDescriptor: () =>
        readFieldDescriptor(bytes, recordOffset + GRUP_OFFSET.PRIVATE_DESCRIPTOR),
    };
  }

  function groupById(groupId: string): KeyGroupView | undefined {
    if (!UUID_PATTERN.test(groupId)) {
      return undefined;
    }
    const wanted = hexDecode(groupId.replaceAll("-", ""));
    for (let index = 0; index < groupCount; index += 1) {
      const candidate = group(index);
      if (candidate !== undefined && timingSafeEqual(wanted, candidate.groupIdBytes())) {
        return candidate;
      }
    }
    return undefined;
  }

  function filter(index: number): FilterArgsView | undefined {
    if (filt === undefined || !Number.isInteger(index) || index < 0 || index >= filt.count) {
      return undefined;
    }
    const entryOffset = filtEntryOffset(filt.offset, index);
    return {
      filterIndex: index,
      kind: view.getUint32(entryOffset + FILT_ENTRY_OFFSET.KIND, true),
      args: () =>
        slice(
          view.getUint32(entryOffset + FILT_ENTRY_OFFSET.ARGS_OFFSET, true),
          view.getUint32(entryOffset + FILT_ENTRY_OFFSET.ARGS_LENGTH, true),
          "a filter's arguments",
        ),
    };
  }

  // ---- lookup -----------------------------------------------------------

  /**
   * One masked slot read, a fingerprint compare, then a full id verify.
   *
   * A fingerprint mismatch is a miss resolved without reading `CONN` at all,
   * which is what makes a miss cost one read.
   */
  function lookup(connectionId: string): ConnectionRecord | undefined {
    if (indx === undefined || conn === undefined) {
      return undefined;
    }
    const id = tryParseConnectionId(connectionId);
    // An id names both the shard and the connection, so another shard's id
    // cannot be here and saying so costs nothing.
    if (id === undefined || id.shard !== header.shard) {
      return undefined;
    }

    const fingerprint = uuidHigh32(id.uuid);
    let slot = bucketOf(uuidLow32(id.uuid), slots);
    for (let probe = 0; probe < slots; probe += 1) {
      const slotOffset = indexSlotOffset(indx.offset, slot);
      const recordOffset = view.getUint32(slotOffset + INDEX_SLOT_OFFSET.CONN_OFFSET, true);
      if (recordOffset === INDEX_EMPTY_SLOT) {
        return undefined;
      }
      if (view.getUint32(slotOffset + INDEX_SLOT_OFFSET.FINGERPRINT, true) === fingerprint) {
        assertConnRecordOffset(recordOffset);
        const record = makeConnectionRecord(recordOffset);
        if (record.matchesId(id.uuid)) {
          return record;
        }
      }
      slot = (slot + 1) & (slots - 1);
    }
    // Reachable only in a table with no empty slot at all, which the 0.25 load
    // factor forbids; a corrupt index must still terminate.
    return undefined;
  }

  // ---- the view ---------------------------------------------------------

  let checksumVerification: Promise<boolean> | undefined;

  return {
    header,
    buffer: bytes,
    connectionCount,
    groupCount,

    section: (kind: SectionKindName) => sections.get(SECTION_KIND[kind]),

    // Verified once and memoised: a write-back mutates the covered bytes by
    // design, so a second computation would report a bundle as corrupt for
    // having done exactly what it is there to do.
    verifyChecksum: () => {
      checksumVerification ??= verifyChecksum(bytes);
      return checksumVerification;
    },

    lookup,
    connectionAt,
    group,
    groupById,
    filter,
    writeBack: (descriptor: FieldDescriptor, plaintext: Uint8Array) =>
      writeBackPlaintext(bytes, descriptor, plaintext),
  };
}

// ---------------------------------------------------------------------------
// Load-time validation
// ---------------------------------------------------------------------------

function readHeader(bytes: Uint8Array, view: DataView): BundleHeader {
  if (bytes.byteLength < HEADER_BYTES) {
    throw new BundleFormatError(
      `a bundle is at least ${HEADER_BYTES} bytes, got ${bytes.byteLength}`,
    );
  }
  for (let i = 0; i < BUNDLE_MAGIC_BYTES.byteLength; i += 1) {
    if (bytes[HEADER_OFFSET.MAGIC + i] !== BUNDLE_MAGIC_BYTES[i]) {
      throw new BundleFormatError(`not a bundle: the magic is not ${BUNDLE_MAGIC}`);
    }
  }

  const version = view.getUint16(HEADER_OFFSET.VERSION, true);
  if (version > BUNDLE_VERSION) {
    throw new UnsupportedBundleVersionError(version, BUNDLE_VERSION);
  }
  if (version < 1) {
    throw new BundleFormatError(`a bundle version is at least 1, got ${version}`);
  }

  const flags = view.getUint16(HEADER_OFFSET.FLAGS, true);
  if (flags !== 0) {
    // Reserved bits are reserved: a writer that set one meant something by it,
    // and this reader does not know what.
    throw new BundleFormatError(`the header flags are reserved and must be zero, got ${flags}`);
  }

  const sections = view.getUint32(HEADER_OFFSET.SECTIONS, true);
  if (SECTION_TABLE_OFFSET + sections * SECTION_ENTRY_BYTES > bytes.byteLength) {
    throw new BundleFormatError(`the section table of ${sections} entries is truncated`);
  }

  return {
    magic: BUNDLE_MAGIC,
    version,
    flags,
    generation: view.getBigUint64(HEADER_OFFSET.GENERATION, true),
    shard: utf8Decode(
      bytes.subarray(HEADER_OFFSET.SHARD, HEADER_OFFSET.SHARD + SHARD_PREFIX_BYTES),
    ),
    builtAt: view.getBigUint64(HEADER_OFFSET.BUILT_AT, true),
    sections,
  };
}

/**
 * Walk the section table into a map by kind.
 *
 * An unknown kind is kept and never looked at, which is what lets a new section
 * appear without a version bump.
 */
function readSectionTable(
  bytes: Uint8Array,
  view: DataView,
  count: number,
): Map<number, SectionEntry> {
  const tableEnd = SECTION_TABLE_OFFSET + count * SECTION_ENTRY_BYTES;
  const sections = new Map<number, SectionEntry>();

  for (let i = 0; i < count; i += 1) {
    const entryOffset = sectionEntryOffset(i);
    const entry: SectionEntry = {
      kind: view.getUint32(entryOffset + SECTION_ENTRY_OFFSET.KIND, true),
      offset: view.getUint32(entryOffset + SECTION_ENTRY_OFFSET.OFFSET, true),
      length: view.getUint32(entryOffset + SECTION_ENTRY_OFFSET.LENGTH, true),
      count: view.getUint32(entryOffset + SECTION_ENTRY_OFFSET.COUNT, true),
    };
    // An empty section may point anywhere, including nowhere: there is nothing
    // to read and a writer should not have to invent a placeholder offset.
    const outside = entry.offset < tableEnd || entry.offset + entry.length > bytes.byteLength;
    if (entry.length !== 0 && outside) {
      throw new BundleFormatError(
        `section ${sectionKindName(entry.kind)} at ${entry.offset}+${entry.length} lies outside the buffer`,
      );
    }
    if (sections.has(entry.kind)) {
      throw new BundleFormatError(`section ${sectionKindName(entry.kind)} appears twice`);
    }
    sections.set(entry.kind, entry);
  }
  return sections;
}

/** The slot count implied by the INDX section, validated once, at load. */
function indexSlots(indx: SectionEntry | undefined): number {
  if (indx === undefined) {
    return 0;
  }
  if (indx.length % INDEX_SLOT_BYTES !== 0) {
    throw new BundleFormatError(
      `the index is not a whole number of ${INDEX_SLOT_BYTES}-byte slots`,
    );
  }
  const slots = indx.length / INDEX_SLOT_BYTES;
  if (slots === 0 || (slots & (slots - 1)) !== 0) {
    throw new BundleFormatError(`the index slot count must be a power of two, got ${slots}`);
  }
  return slots;
}

/**
 * SHA-256 over everything after the header, truncated to 28 bytes.
 *
 * The comparison is constant-time out of habit rather than necessity: the digest
 * is unkeyed and public, so this detects truncation and corruption and is not an
 * authenticity control.
 */
async function verifyChecksum(bytes: Uint8Array): Promise<boolean> {
  const digest = await crypto.subtle.digest(CHECKSUM_ALGORITHM, unshared(bytes, HEADER_BYTES));
  const found = new Uint8Array(digest, 0, CHECKSUM_BYTES);
  const stored = bytes.subarray(HEADER_OFFSET.CHECKSUM, HEADER_OFFSET.CHECKSUM + CHECKSUM_BYTES);
  return timingSafeEqual(found, stored);
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/**
 * A malformed id is a miss, not a throw.
 *
 * The id arrives from a request. A shard must refuse it exactly the way it
 * refuses an id that simply is not here, or the shape of the failure becomes the
 * oracle the index was designed not to be.
 */
function tryParseConnectionId(
  connectionId: string,
): { shard: string; uuid: Uint8Array } | undefined {
  try {
    return parseConnectionId(connectionId);
  } catch {
    return undefined;
  }
}

/**
 * The bundle from `from` onwards, as a region Web Crypto will accept.
 *
 * Web Crypto refuses a `SharedArrayBuffer`, and so does this: the buffer is
 * mutated in place by every write-back, and a digest over bytes another thread
 * can change underneath it would mean nothing anyway.
 */
function unshared(bytes: Uint8Array, from: number): Uint8Array<ArrayBuffer> {
  const { buffer } = bytes;
  if (!(buffer instanceof ArrayBuffer)) {
    throw new BundleFormatError("a bundle cannot be read from a SharedArrayBuffer");
  }
  return new Uint8Array(buffer, bytes.byteOffset + from, bytes.byteLength - from);
}

/** Canonical 8-4-4-4-12. */
function formatUuid(uuid: Uint8Array): string {
  const hex = hexEncode(uuid);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
