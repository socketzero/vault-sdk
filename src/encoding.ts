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

const BASE62_RADIX = 62n;

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const HEX_DIGITS = "0123456789abcdef";

/**
 * Character-code → digit-value tables. Built once from the alphabets above so
 * the decoders never disagree with the encoders about what is in the alphabet.
 * `-1` marks every code point that is not a digit.
 */
function buildDecodeTable(alphabet: string): Int8Array {
  const table = new Int8Array(128).fill(-1);
  for (let value = 0; value < alphabet.length; value += 1) {
    table[alphabet.charCodeAt(value)] = value;
  }
  return table;
}

const BASE62_VALUES = buildDecodeTable(BASE62_ALPHABET);
const BASE64_VALUES = buildDecodeTable(BASE64_ALPHABET);

/** `-1` for anything outside the table, including every code point above ASCII. */
function digitValue(table: Int8Array, code: number): number {
  return table[code] ?? -1;
}

function requirePositiveInteger(name: string, value: number): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive integer, got ${value}`);
  }
}

/**
 * The number of base62 characters that can hold any `byteLength`-byte value —
 * 43 for 32 bytes, 6 for a CRC-32.
 *
 * Computed rather than tabulated: `ceil(byteLength * 8 / log2(62))` is close
 * enough to an integer boundary that floating point cannot be trusted with it.
 */
export function base62Width(byteLength: number): number {
  requirePositiveInteger("byteLength", byteLength);
  const limit = 1n << BigInt(byteLength * 8);
  let width = 0;
  let capacity = 1n;
  while (capacity < limit) {
    capacity *= BASE62_RADIX;
    width += 1;
  }
  return width;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

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
  requirePositiveInteger("width", width);
  let value = bytesToBigInt(bytes);
  // Emitting exactly `width` digits low-to-high does the padding for free; a
  // non-zero remainder afterwards is precisely "does not fit".
  const digits: string[] = [];
  for (let position = 0; position < width; position += 1) {
    digits.push(BASE62_ALPHABET.charAt(Number(value % BASE62_RADIX)));
    value /= BASE62_RADIX;
  }
  if (value !== 0n) {
    throw new RangeError(`value does not fit in ${width} base62 characters`);
  }
  return digits.reverse().join("");
}

/**
 * Decode exactly `byteLength` bytes from a base62 string, big-endian.
 *
 * The string must be the canonical fixed width for `byteLength` — the encoder
 * never produces anything else, so a short or long one is a corrupted paste,
 * not a shorter number.
 *
 * @throws {RangeError} on a wrong length, a character outside the alphabet, or
 *   on a value too large for `byteLength` bytes.
 */
export function base62Decode(text: string, byteLength: number): Uint8Array<ArrayBuffer> {
  const width = base62Width(byteLength);
  if (text.length !== width) {
    throw new RangeError(`expected ${width} base62 characters, got ${text.length}`);
  }
  let value = 0n;
  for (let index = 0; index < text.length; index += 1) {
    const digit = digitValue(BASE62_VALUES, text.charCodeAt(index));
    if (digit < 0) {
      throw new RangeError(`non-base62 character at index ${index}`);
    }
    value = value * BASE62_RADIX + BigInt(digit);
  }
  if (value >= 1n << BigInt(byteLength * 8)) {
    throw new RangeError(`value does not fit in ${byteLength} bytes`);
  }
  const bytes = new Uint8Array(byteLength);
  for (let index = byteLength - 1; index >= 0; index -= 1) {
    bytes[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

/**
 * CRC-32 (IEEE, reflected, init/xor `0xffffffff`), returned as an unsigned 32-bit number.
 *
 * Bit-at-a-time rather than table-driven: the only inputs are 32-byte keys, so
 * the table would buy nothing and cost a branch that no input can exercise.
 */
export function crc32(bytes: Uint8Array): number {
  let remainder = 0xffffffff;
  for (const byte of bytes) {
    remainder ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      remainder = remainder & 1 ? (remainder >>> 1) ^ CRC32_POLYNOMIAL : remainder >>> 1;
    }
  }
  return (remainder ^ 0xffffffff) >>> 0;
}

/** Lowercase hex, two characters per byte. */
export function hexEncode(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) {
    text += HEX_DIGITS.charAt(byte >>> 4) + HEX_DIGITS.charAt(byte & 0x0f);
  }
  return text;
}

function hexValue(code: number): number {
  if (code >= 0x30 && code <= 0x39) {
    return code - 0x30;
  }
  if (code >= 0x61 && code <= 0x66) {
    return code - 0x61 + 10;
  }
  if (code >= 0x41 && code <= 0x46) {
    return code - 0x41 + 10;
  }
  return -1;
}

/**
 * Decode lowercase or uppercase hex.
 *
 * @throws {RangeError} on an odd length or a non-hex character.
 */
export function hexDecode(text: string): Uint8Array<ArrayBuffer> {
  if (text.length % 2 !== 0) {
    throw new RangeError(`hex string must have an even length, got ${text.length}`);
  }
  const bytes = new Uint8Array(text.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    const high = hexValue(text.charCodeAt(index * 2));
    const low = hexValue(text.charCodeAt(index * 2 + 1));
    if (high < 0 || low < 0) {
      throw new RangeError(`non-hex character at index ${index * 2}`);
    }
    bytes[index] = (high << 4) | low;
  }
  return bytes;
}

/**
 * Constant-time byte comparison.
 *
 * Returns `false` for differing lengths without inspecting contents; for equal
 * lengths the running time depends only on the length, never on where the first
 * difference is.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  // Read through DataViews: `a[i]` is `number | undefined` under
  // noUncheckedIndexedAccess, and a `?? 0` there would be a branch that no
  // input can take.
  const left = new DataView(a.buffer, a.byteOffset, a.byteLength);
  const right = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let difference = 0;
  for (let index = 0; index < a.byteLength; index += 1) {
    difference |= left.getUint8(index) ^ right.getUint8(index);
  }
  return difference === 0;
}

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

/** UTF-8 encode. Centralised so every AAD in the SDK is built the same way. */
export function utf8Encode(text: string): Uint8Array<ArrayBuffer> {
  return TEXT_ENCODER.encode(text);
}

/** UTF-8 decode a view without copying it first. */
export function utf8Decode(bytes: Uint8Array): string {
  return TEXT_DECODER.decode(bytes);
}

/** Standard base64 (with padding), as the envelope's display form uses. */
export function base64Encode(bytes: Uint8Array): string {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let text = "";
  for (let index = 0; index < bytes.byteLength; index += 3) {
    const hasSecond = index + 1 < bytes.byteLength;
    const hasThird = index + 2 < bytes.byteLength;
    const first = view.getUint8(index);
    const second = hasSecond ? view.getUint8(index + 1) : 0;
    const third = hasThird ? view.getUint8(index + 2) : 0;
    text += BASE64_ALPHABET.charAt(first >>> 2);
    text += BASE64_ALPHABET.charAt(((first & 0x03) << 4) | (second >>> 4));
    text += hasSecond ? BASE64_ALPHABET.charAt(((second & 0x0f) << 2) | (third >>> 6)) : "=";
    text += hasThird ? BASE64_ALPHABET.charAt(third & 0x3f) : "=";
  }
  return text;
}

/**
 * Decode standard base64.
 *
 * Strict on purpose: padded length, padding only at the end, and no non-zero
 * bits left over in the final group. An envelope that decodes two ways is an
 * envelope whose AAD binding can be re-encoded around.
 *
 * @throws {RangeError} on characters outside the alphabet or a bad length.
 */
export function base64Decode(text: string): Uint8Array<ArrayBuffer> {
  if (text.length % 4 !== 0) {
    throw new RangeError(`base64 length must be a multiple of 4, got ${text.length}`);
  }
  let padding = 0;
  if (text.endsWith("==")) {
    padding = 2;
  } else if (text.endsWith("=")) {
    padding = 1;
  }
  const bytes = new Uint8Array((text.length / 4) * 3 - padding);
  const digitCount = text.length - padding;
  let accumulator = 0;
  let bits = 0;
  let written = 0;
  for (let index = 0; index < digitCount; index += 1) {
    const digit = digitValue(BASE64_VALUES, text.charCodeAt(index));
    if (digit < 0) {
      throw new RangeError(`non-base64 character at index ${index}`);
    }
    // Masked to 16 bits: at most 12 are ever live, and an unmasked shift would
    // walk into the sign bit for no reason.
    accumulator = ((accumulator << 6) | digit) & 0xffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[written] = (accumulator >>> bits) & 0xff;
      written += 1;
    }
  }
  if ((accumulator & ((1 << bits) - 1)) !== 0) {
    throw new RangeError("base64 has non-zero padding bits");
  }
  return bytes;
}
