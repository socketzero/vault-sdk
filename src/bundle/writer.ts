/**
 * The bundle writer. Used by the compiler, and by tests that need a bundle the
 * reader must agree with byte for byte.
 *
 * Emits, in order: the 64-byte header, the section table, INDX, CONN, GRUP with
 * its nested buckets, FILT, and the STRS arena holding every variable-length
 * value exactly once. The checksum is written last, over everything after the
 * header.
 */

import type { BundleInput } from "../types.js";

/**
 * Serialise a whole shard generation.
 *
 * @throws {BundleCapacityError} when a connection carries more sealed fields
 *   than `CONN_MAX_FIELDS`, when the connection count exceeds what the index
 *   can address, or when a section would overflow a uint32 offset.
 * @throws {RangeError} on a malformed input: a shard prefix that is not four
 *   lowercase letters, a connection naming a group that is not in `groups`, an
 *   envelope with the wrong algorithm, or a filter index out of range.
 */
export function writeBundle(input: BundleInput): Uint8Array {
  void input;
  throw new Error("not implemented");
}

/**
 * The exact byte length `writeBundle` will produce for an input.
 *
 * Separate from the write so a caller can size the pre-allocated ping-pong
 * buffers the shard reads into without serialising twice.
 */
export function measureBundle(input: BundleInput): number {
  void input;
  throw new Error("not implemented");
}

/**
 * Compute the 28-byte checksum over everything after the header.
 *
 * @param buffer the whole bundle, header included.
 */
export function computeChecksum(buffer: Uint8Array): Promise<Uint8Array> {
  void buffer;
  throw new Error("not implemented");
}

/**
 * Write a computed checksum into the header in place.
 *
 * Split from `writeBundle` because the digest is asynchronous under Web Crypto
 * while the serialisation is not.
 */
export function writeChecksum(buffer: Uint8Array, checksum: Uint8Array): void {
  void buffer;
  void checksum;
  throw new Error("not implemented");
}

/**
 * Serialise and stamp the checksum in one asynchronous call — what a compiler
 * actually wants.
 */
export function writeBundleWithChecksum(input: BundleInput): Promise<Uint8Array> {
  void input;
  throw new Error("not implemented");
}
