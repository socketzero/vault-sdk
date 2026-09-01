import { describe, expect, it } from "vitest";
import {
  BASE62_ALPHABET,
  base62Decode,
  base62Encode,
  base62Width,
  base64Decode,
  base64Encode,
  CRC32_POLYNOMIAL,
  crc32,
  hexDecode,
  hexEncode,
  timingSafeEqual,
  utf8Decode,
  utf8Encode,
} from "./encoding.js";

const bytes = (...values: number[]): Uint8Array => Uint8Array.from(values);

const repeat = (value: number, count: number): Uint8Array => new Uint8Array(count).fill(value);

describe("alphabet constants", () => {
  it("orders base62 digits before letters so the ordering is lexicographic", () => {
    expect(BASE62_ALPHABET).toHaveLength(62);
    expect(new Set(BASE62_ALPHABET).size).toBe(62);
    expect(BASE62_ALPHABET.slice(0, 10)).toBe("0123456789");
    expect([...BASE62_ALPHABET].toSorted().join("")).toBe(BASE62_ALPHABET);
  });

  it("uses the reflected IEEE polynomial", () => {
    expect(CRC32_POLYNOMIAL).toBe(0xedb88320);
  });
});

describe("base62Width", () => {
  it("gives 43 characters for a 32-byte key and 6 for a CRC-32", () => {
    expect(base62Width(32)).toBe(43);
    expect(base62Width(4)).toBe(6);
  });

  it("gives a width that holds the largest value of that size but no more", () => {
    for (const byteLength of [1, 2, 3, 4, 8, 16, 32]) {
      const width = base62Width(byteLength);
      const capacity = 62n ** BigInt(width);
      const limit = 1n << BigInt(byteLength * 8);
      expect(capacity).toBeGreaterThanOrEqual(limit);
      expect(62n ** BigInt(width - 1)).toBeLessThan(limit);
    }
  });

  it("rejects a non-integer or non-positive byte length", () => {
    expect(() => base62Width(1.5)).toThrow(RangeError);
    expect(() => base62Width(0)).toThrow(RangeError);
    expect(() => base62Width(-1)).toThrow(RangeError);
  });
});

describe("base62Encode", () => {
  it("encodes 32 bytes as exactly 43 characters", () => {
    expect(base62Encode(repeat(0xff, 32), 43)).toHaveLength(43);
    expect(base62Encode(repeat(0x00, 32), 43)).toBe("0".repeat(43));
  });

  it("left-pads a small value with zeroes to the full width", () => {
    expect(base62Encode(bytes(0, 0, 0, 1), 6)).toBe("000001");
    expect(base62Encode(bytes(61), 6)).toBe("00000z");
    expect(base62Encode(bytes(62), 6)).toBe("000010");
  });

  it("encodes big-endian", () => {
    expect(base62Encode(bytes(1, 0), 6)).toBe(base62Encode(bytes(0, 0, 1, 0), 6));
    expect(base62Encode(bytes(1, 0), 6)).not.toBe(base62Encode(bytes(0, 1), 6));
  });

  it("encodes an empty array as zero", () => {
    expect(base62Encode(new Uint8Array(0), 3)).toBe("000");
  });

  it("throws when the value does not fit in the requested width", () => {
    expect(() => base62Encode(repeat(0xff, 32), 42)).toThrow(RangeError);
    expect(() => base62Encode(bytes(0xff, 0xff), 2)).toThrow(/does not fit in 2 base62/);
  });

  it("rejects a non-positive or fractional width", () => {
    expect(() => base62Encode(bytes(1), 0)).toThrow(/width must be a positive integer/);
    expect(() => base62Encode(bytes(1), 2.5)).toThrow(RangeError);
  });
});

describe("base62Decode", () => {
  it("round-trips every byte value at key width", () => {
    for (const fill of [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]) {
      const original = repeat(fill, 32);
      expect(base62Decode(base62Encode(original, 43), 32)).toEqual(original);
    }
  });

  it("round-trips a mixed 32-byte value", () => {
    const original = Uint8Array.from({ length: 32 }, (_, index) => (index * 37 + 11) & 0xff);
    expect(base62Decode(base62Encode(original, 43), 32)).toEqual(original);
  });

  it("accepts every character of the alphabet", () => {
    for (const [value, char] of [...BASE62_ALPHABET].entries()) {
      const decoded = base62Decode(`00000${char}`, 4);
      expect(decoded).toEqual(bytes(0, 0, 0, value));
    }
  });

  it("rejects a string that is not the canonical width", () => {
    expect(() => base62Decode("00001", 4)).toThrow(/expected 6 base62 characters, got 5/);
    expect(() => base62Decode("0000001", 4)).toThrow(RangeError);
    expect(() => base62Decode("", 4)).toThrow(RangeError);
  });

  it("rejects characters outside the alphabet", () => {
    expect(() => base62Decode("00000_", 4)).toThrow(/non-base62 character at index 5/);
    expect(() => base62Decode("-00000", 4)).toThrow(/non-base62 character at index 0/);
  });

  it("rejects a non-ASCII character", () => {
    expect(() => base62Decode("0000€", 4)).toThrow(RangeError);
    expect(() => base62Decode("00000€", 4)).toThrow(/non-base62 character at index 5/);
  });

  it("rejects a value too large for the byte length", () => {
    // 62^6 - 1 needs more than four bytes.
    expect(() => base62Decode("zzzzzz", 4)).toThrow(/does not fit in 4 bytes/);
    expect(() => base62Decode("z".repeat(43), 32)).toThrow(RangeError);
  });

  it("accepts the largest value that does fit", () => {
    expect(base62Decode(base62Encode(repeat(0xff, 4), 6), 4)).toEqual(repeat(0xff, 4));
  });

  it("rejects a non-positive byte length", () => {
    expect(() => base62Decode("0", 0)).toThrow(/byteLength must be a positive integer/);
  });
});

describe("crc32", () => {
  it("matches the published check value", () => {
    expect(crc32(utf8Encode("123456789"))).toBe(0xcbf43926);
  });

  it("is zero for the empty input", () => {
    expect(crc32(new Uint8Array(0))).toBe(0);
  });

  it("matches known vectors", () => {
    expect(crc32(utf8Encode("a"))).toBe(0xe8b7be43);
    expect(crc32(utf8Encode("abc"))).toBe(0x352441c2);
    expect(crc32(bytes(0x00))).toBe(0xd202ef8d);
    expect(crc32(repeat(0xff, 4))).toBe(0xffffffff);
  });

  it("returns an unsigned 32-bit number", () => {
    const value = crc32(repeat(0xff, 4));
    expect(value).toBeGreaterThanOrEqual(0);
    expect(value).toBeLessThanOrEqual(0xffffffff);
    expect(Number.isInteger(value)).toBe(true);
  });

  it("detects a single-bit change", () => {
    expect(crc32(bytes(1, 2, 3))).not.toBe(crc32(bytes(1, 2, 2)));
  });
});

describe("hexEncode / hexDecode", () => {
  it("encodes two lowercase characters per byte", () => {
    expect(hexEncode(bytes(0x00, 0x0f, 0xa5, 0xff))).toBe("000fa5ff");
    expect(hexEncode(new Uint8Array(0))).toBe("");
  });

  it("round-trips", () => {
    const original = Uint8Array.from({ length: 16 }, (_, index) => index * 17);
    expect(hexDecode(hexEncode(original))).toEqual(original);
  });

  it("accepts uppercase and mixed case", () => {
    expect(hexDecode("AbCdEf")).toEqual(bytes(0xab, 0xcd, 0xef));
    expect(hexDecode("0123456789abcdefABCDEF")).toHaveLength(11);
  });

  it("rejects an odd length", () => {
    expect(() => hexDecode("abc")).toThrow(/even length, got 3/);
  });

  it("rejects a non-hex character in either nibble", () => {
    expect(() => hexDecode("g0")).toThrow(/non-hex character at index 0/);
    expect(() => hexDecode("0g")).toThrow(/non-hex character at index 0/);
    expect(() => hexDecode("00/0")).toThrow(/non-hex character at index 2/);
    expect(() => hexDecode("00:0")).toThrow(RangeError);
    expect(() => hexDecode("00G0")).toThrow(RangeError);
  });
});

describe("timingSafeEqual", () => {
  it("is true for equal contents", () => {
    expect(timingSafeEqual(bytes(1, 2, 3), bytes(1, 2, 3))).toBe(true);
    expect(timingSafeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });

  it("is false for differing contents at any position", () => {
    expect(timingSafeEqual(bytes(1, 2, 3), bytes(9, 2, 3))).toBe(false);
    expect(timingSafeEqual(bytes(1, 2, 3), bytes(1, 2, 9))).toBe(false);
  });

  it("is false for differing lengths", () => {
    expect(timingSafeEqual(bytes(1, 2), bytes(1, 2, 3))).toBe(false);
  });

  it("compares the view, not the underlying buffer", () => {
    const backing = Uint8Array.from([9, 1, 2, 3, 9]);
    const view = backing.subarray(1, 4);
    expect(timingSafeEqual(view, bytes(1, 2, 3))).toBe(true);
    expect(timingSafeEqual(view, bytes(9, 1, 2))).toBe(false);
  });
});

describe("utf8Encode / utf8Decode", () => {
  it("round-trips ASCII, accents, CJK and astral characters", () => {
    for (const text of ["", "connection-id", "naïve", "秘密", "🔐"]) {
      expect(utf8Decode(utf8Encode(text))).toBe(text);
    }
  });

  it("encodes multi-byte characters as UTF-8", () => {
    expect(utf8Encode("é")).toEqual(bytes(0xc3, 0xa9));
    expect([...utf8Encode("🔐")]).toHaveLength(4);
  });

  it("decodes a subarray view without needing a copy", () => {
    const backing = utf8Encode("xxhellyy");
    expect(utf8Decode(backing.subarray(2, 6))).toBe("hell");
  });
});

describe("base64Encode / base64Decode", () => {
  it("matches the RFC 4648 test vectors", () => {
    const vectors: ReadonlyArray<readonly [string, string]> = [
      ["", ""],
      ["f", "Zg=="],
      ["fo", "Zm8="],
      ["foo", "Zm9v"],
      ["foob", "Zm9vYg=="],
      ["fooba", "Zm9vYmE="],
      ["foobar", "Zm9vYmFy"],
    ];
    for (const [plain, encoded] of vectors) {
      expect(base64Encode(utf8Encode(plain))).toBe(encoded);
      expect(utf8Decode(base64Decode(encoded))).toBe(plain);
    }
  });

  it("encodes the high alphabet characters", () => {
    expect(base64Encode(bytes(0xfb, 0xff, 0xfe))).toBe("+//+");
    expect(base64Decode("+//+")).toEqual(bytes(0xfb, 0xff, 0xfe));
  });

  it("round-trips every byte value", () => {
    const original = Uint8Array.from({ length: 256 }, (_, index) => index);
    expect(base64Decode(base64Encode(original))).toEqual(original);
  });

  it("round-trips an envelope-sized payload", () => {
    const original = Uint8Array.from({ length: 32 + 12 + 16 + 7 }, (_, i) => (i * 91) & 0xff);
    expect(base64Decode(base64Encode(original))).toEqual(original);
  });

  it("encodes a subarray view, not its backing buffer", () => {
    const backing = Uint8Array.from([0xff, 0x66, 0x6f, 0x6f, 0xff]);
    expect(base64Encode(backing.subarray(1, 4))).toBe("Zm9v");
  });

  it("rejects a length that is not a multiple of four", () => {
    expect(() => base64Decode("Zm9")).toThrow(/multiple of 4, got 3/);
    expect(() => base64Decode("Zm9vY")).toThrow(RangeError);
  });

  it("rejects characters outside the alphabet, including padding in the middle", () => {
    expect(() => base64Decode("Zm9-")).toThrow(/non-base64 character at index 3/);
    expect(() => base64Decode("Z=9v")).toThrow(/non-base64 character at index 1/);
    expect(() => base64Decode("=m9v")).toThrow(/non-base64 character at index 0/);
    expect(() => base64Decode("====")).toThrow(RangeError);
  });

  it("rejects a non-ASCII character", () => {
    expect(() => base64Decode("A€==")).toThrow(/non-base64 character at index 1/);
  });

  it("rejects non-canonical trailing bits", () => {
    // "AB==" carries a 1 in bits the single decoded byte cannot hold.
    expect(() => base64Decode("AB==")).toThrow(/non-zero padding bits/);
    expect(() => base64Decode("AAB=")).toThrow(/non-zero padding bits/);
    expect(base64Decode("AQ==")).toEqual(bytes(0x01));
    expect(base64Decode("AAE=")).toEqual(bytes(0x00, 0x01));
  });
});

describe("api key display shape", () => {
  it("produces the 43 + 6 character body the key format specifies", () => {
    const key = Uint8Array.from({ length: 32 }, (_, index) => (index * 7 + 3) & 0xff);
    const body = base62Encode(key, 43);
    const checksum = base62Encode(base62Decode(base62Encode(bytes(0, 0, 0, 0), 6), 4), 6);
    expect(body).toHaveLength(43);
    expect(checksum).toHaveLength(6);

    const crcBytes = new Uint8Array(4);
    new DataView(crcBytes.buffer).setUint32(0, crc32(key), false);
    expect(base62Encode(crcBytes, 6)).toHaveLength(6);
    // The derivation input is the raw bytes: decoding the display body must
    // return exactly what was encoded.
    expect(base62Decode(body, 32)).toEqual(key);
  });
});
