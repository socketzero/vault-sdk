/**
 * Byte/text conversions used by the key format and the bundle.
 *
 * No cryptography lives here. Base62 and CRC-32 are packaging: they make a key
 * survive a double-click and a paste, and they are what lets a mistyped key say
 * *mistyped* instead of *denied* (`datamodel/api-key`).
 */

/** `0-9A-Za-z`, in that order. Digits first, so the ordering is lexicographic. */
export const BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/** The IEEE polynomial, reflected — the one zlib uses. */
export const CRC32_POLYNOMIAL = 0xedb88320;

/**
 * Encode a fixed-width byte array as a big-endian base62 number, left-padded
 * with `"0"` to exactly `width` characters.
 *
 * Fixed width is the point: 32 bytes always produce 43 characters and a CRC-32
 * always produces 6, so the display form has one length and one shape.
 *
 * @throws {RangeError} if the value does not fit in `width` characters.
 */
export function base62Encode(bytes: Uint8Array, width: number): string {
  void bytes;
  void width;
  throw new Error("not implemented");
}

/**
 * Decode exactly `byteLength` bytes from a base62 string, big-endian.
 *
 * @throws {RangeError} on a character outside the alphabet, or on a value too
 *   large for `byteLength` bytes.
 */
export function base62Decode(text: string, byteLength: number): Uint8Array {
  void text;
  void byteLength;
  throw new Error("not implemented");
}

/** CRC-32 (IEEE, reflected, init/xor `0xffffffff`), returned as an unsigned 32-bit number. */
export function crc32(bytes: Uint8Array): number {
  void bytes;
  throw new Error("not implemented");
}

/** Lowercase hex, two characters per byte. */
export function hexEncode(bytes: Uint8Array): string {
  void bytes;
  throw new Error("not implemented");
}

/**
 * Decode lowercase or uppercase hex.
 *
 * @throws {RangeError} on an odd length or a non-hex character.
 */
export function hexDecode(text: string): Uint8Array {
  void text;
  throw new Error("not implemented");
}

/**
 * Constant-time byte comparison.
 *
 * Returns `false` for differing lengths without inspecting contents; for equal
 * lengths the running time depends only on the length, never on where the first
 * difference is.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  void a;
  void b;
  throw new Error("not implemented");
}

/** UTF-8 encode. Centralised so every AAD in the SDK is built the same way. */
export function utf8Encode(text: string): Uint8Array {
  void text;
  throw new Error("not implemented");
}

/** UTF-8 decode a view without copying it first. */
export function utf8Decode(bytes: Uint8Array): string {
  void bytes;
  throw new Error("not implemented");
}

/** Standard base64 (with padding), as the envelope's display form uses. */
export function base64Encode(bytes: Uint8Array): string {
  void bytes;
  throw new Error("not implemented");
}

/**
 * Decode standard base64.
 *
 * @throws {RangeError} on characters outside the alphabet or a bad length.
 */
export function base64Decode(text: string): Uint8Array {
  void text;
  throw new Error("not implemented");
}
