import { hkdfSync } from "node:crypto";
import { describe, expect, test } from "vitest";
import {
  API_KEY_BODY_CHARS,
  API_KEY_BYTES,
  API_KEY_CHECKSUM_CHARS,
  API_KEY_DISPLAY_LENGTH,
  API_KEY_ENVIRONMENTS,
  deriveKeyId,
  deriveKeyIdHex,
  deriveWrapKey,
  formatApiKey,
  generateApiKey,
  HKDF_INFO_KEY_ID,
  HKDF_INFO_WRAP_KEY,
  KEY_ID_BYTES,
  parseApiKey,
  WRAP_KEY_BYTES,
} from "./api-key.js";
import { BASE62_ALPHABET, crc32, hexEncode, utf8Encode } from "./encoding.js";
import {
  type ApiKeyBytes,
  type ApiKeyEnvironment,
  type ApiKeyMaterial,
  type ApiKeyParseFailure,
  asApiKeyBytes,
  requireApiKey,
} from "./types.js";

/**
 * The worked example from `datamodel/api-key`, verbatim.
 *
 * Every fixture below is reached by *parsing*, never by formatting bytes:
 * `generateApiKey` is the only minting path in the module, so a test that wants
 * a fixed key has to start from a display string, exactly as a user does.
 */
const SAMPLE_DISPLAY = "sk0_live_bl5P5fbg8iT8NCjg1g3ZFujxc8wkEqsdBiazmNyib0N_0BKAzU";
const SAMPLE: ApiKeyMaterial = requireApiKey(parseApiKey(SAMPLE_DISPLAY));
const SAMPLE_BYTES = SAMPLE.bytes;

/** The same key in the other environment: the checksum covers bytes, not packaging. */
const SAMPLE_TEST_DISPLAY = `sk0_test${SAMPLE_DISPLAY.slice(8)}`;

const TENANT = "tenant_01HZY8Q7";
const OTHER_TENANT = "tenant_01HZY8Q8";

/** An untyped caller reaching a typed parameter. Never how the SDK calls itself. */
function untyped<T>(value: unknown): T {
  return value as T;
}

/** Big-endian base62 at a fixed width — written out here, not imported. */
function base62Of(value: bigint, width: number): string {
  let rest = value;
  let text = "";
  for (let index = 0; index < width; index += 1) {
    text = BASE62_ALPHABET.charAt(Number(rest % 62n)) + text;
    rest /= 62n;
  }
  return text;
}

function bigIntOf(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

/**
 * An independent rendering of the display form, used only to build fixtures the
 * SDK deliberately refuses to mint (an all-zero key, the largest legal key).
 * The module under test exports no such function on purpose.
 */
function oracleDisplay(bytes: Uint8Array, environment: string): string {
  const body = base62Of(bigIntOf(bytes), API_KEY_BODY_CHARS);
  const checksum = base62Of(BigInt(crc32(bytes)), API_KEY_CHECKSUM_CHARS);
  return `sk0_${environment}_${body}_${checksum}`;
}

function expectFailure(display: string, reason: ApiKeyParseFailure): void {
  const parsed = parseApiKey(display);
  expect(parsed.ok).toBe(false);
  if (parsed.ok) {
    return;
  }
  expect(parsed.reason).toBe(reason);
  expect(parsed.message.length).toBeGreaterThan(0);
  // A rejection must never be quotable back into key material.
  expect(parsed.message).not.toContain(SAMPLE_DISPLAY.slice(9, 20));
}

function parsedBytes(display: string): ApiKeyBytes {
  return requireApiKey(parseApiKey(display)).bytes;
}

/** Independent HKDF-SHA256 oracle: Node's, not the one under test. */
function referenceHkdf(key: Uint8Array, salt: string, info: string, length: number): Uint8Array {
  return new Uint8Array(hkdfSync("sha256", key, utf8Encode(salt), utf8Encode(info), length));
}

describe("the packaging pinned by `datamodel/api-key`", () => {
  test("base62 is 0-9A-Za-z, in that order", () => {
    expect(BASE62_ALPHABET).toBe("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
  });

  test("the checksum is the reflected IEEE CRC-32 the catalog names", () => {
    // The canonical check value of CRC-32/ISO-HDLC — polynomial 0xEDB88320
    // reflected, 0xFFFFFFFF init and final XOR, the one zlib computes.
    expect(crc32(utf8Encode("123456789"))).toBe(0xcbf43926);
  });

  test("the catalog's worked example parses, checksum and all", () => {
    expect(SAMPLE.environment).toBe("live");
    expect(SAMPLE_BYTES).toHaveLength(API_KEY_BYTES);
    expect(SAMPLE.display).toBe(SAMPLE_DISPLAY);
    expect(SAMPLE_DISPLAY).toHaveLength(API_KEY_DISPLAY_LENGTH);
  });

  test("the four segments are fixed width", () => {
    const segments = SAMPLE_DISPLAY.split("_");
    expect(segments).toHaveLength(4);
    expect(segments[0]).toBe("sk0");
    expect(segments[1]).toBe("live");
    expect(segments[2]).toHaveLength(API_KEY_BODY_CHARS);
    expect(segments[3]).toHaveLength(API_KEY_CHECKSUM_CHARS);
  });

  test("the checksum covers the bytes, not the packaging", () => {
    const other = requireApiKey(parseApiKey(SAMPLE_TEST_DISPLAY));
    expect(other.environment).toBe("test");
    expect(other.bytes).toStrictEqual(SAMPLE_BYTES);
  });
});

describe("generateApiKey", () => {
  test.each<ApiKeyEnvironment>(["live", "test"])("mints a parseable %s key", (environment) => {
    const minted = generateApiKey(environment);
    expect(minted.bytes).toHaveLength(API_KEY_BYTES);
    expect(minted.environment).toBe(environment);
    expect(minted.display.startsWith(`sk0_${environment}_`)).toBe(true);
    expect(minted.display).toHaveLength(API_KEY_DISPLAY_LENGTH);
    // The display is the bytes: parsing it back is the check that matters.
    expect(parsedBytes(minted.display)).toStrictEqual(minted.bytes);
    expect(minted.display).toBe(oracleDisplay(minted.bytes, environment));
  });

  test("is not reproducible", () => {
    const first = generateApiKey("live");
    const second = generateApiKey("live");
    expect(first.display).not.toBe(second.display);
  });

  test("is the only public path to key material", () => {
    // `requirement/api-key-entropy`: "no code path accepts a caller-supplied
    // key, seed or passphrase". The one exported formatter takes material that
    // already exists and re-renders it; nothing exported turns bytes into a key.
    expect(formatApiKey(SAMPLE)).toBe(SAMPLE_DISPLAY);
    expect(API_KEY_ENVIRONMENTS).toStrictEqual(["live", "test"]);
  });

  test("refuses an environment outside the format", () => {
    // A JS caller passing "prod" would otherwise mint `sk0_prod_…`, which no
    // parser accepts — a key discovered dead only at first use.
    expect(() => generateApiKey(untyped<ApiKeyEnvironment>("prod"))).toThrow(RangeError);
    expect(() => generateApiKey(untyped<ApiKeyEnvironment>("prod"))).toThrow(/live, test/);
    expect(() => generateApiKey(untyped<ApiKeyEnvironment>(""))).toThrow(RangeError);
  });
});

describe("formatApiKey", () => {
  test("re-renders material that already exists", () => {
    expect(formatApiKey(SAMPLE)).toBe(SAMPLE_DISPLAY);
    expect(formatApiKey(requireApiKey(parseApiKey(SAMPLE_TEST_DISPLAY)))).toBe(SAMPLE_TEST_DISPLAY);
  });

  test("catches material whose display was edited apart from its bytes", () => {
    const tampered: ApiKeyMaterial = { ...SAMPLE, display: `${SAMPLE_DISPLAY.slice(0, 58)}0` };
    expect(() => formatApiKey(tampered)).toThrow(RangeError);
    let reported = "";
    try {
      formatApiKey(tampered);
    } catch (error) {
      reported = String(error);
    }
    expect(reported).toMatch(/disagree/);
    // The complaint must not quote the key it is complaining about.
    expect(reported).not.toContain(SAMPLE_DISPLAY.slice(9, 20));
  });

  test("catches material whose environment is not one of the two", () => {
    const wrong: ApiKeyMaterial = { ...SAMPLE, environment: untyped<ApiKeyEnvironment>("prod") };
    expect(() => formatApiKey(wrong)).toThrow(RangeError);
  });

  test("catches material whose bytes are not 32", () => {
    const short: ApiKeyMaterial = { ...SAMPLE, bytes: untyped<ApiKeyBytes>(new Uint8Array(31)) };
    expect(() => formatApiKey(short)).toThrow(RangeError);
  });

  test("left-pads a small value to the full body width", () => {
    const zeroBytes = new Uint8Array(API_KEY_BYTES);
    const zero: ApiKeyMaterial = {
      environment: "live",
      bytes: asApiKeyBytes(zeroBytes),
      display: oracleDisplay(zeroBytes, "live"),
    };
    const display = formatApiKey(zero);
    expect(display.split("_")[2]).toBe("0".repeat(API_KEY_BODY_CHARS));
    expect(display).toHaveLength(API_KEY_DISPLAY_LENGTH);
    expect(parsedBytes(display)).toStrictEqual(zeroBytes);
  });
});

describe("parseApiKey", () => {
  test("round-trips the display form back to the raw bytes", () => {
    expect(parseApiKey(SAMPLE_DISPLAY)).toStrictEqual({
      ok: true,
      environment: "live",
      bytes: SAMPLE_BYTES,
      display: SAMPLE_DISPLAY,
    });
  });

  test("reads the environment out of the display form", () => {
    const parsed = parseApiKey(SAMPLE_TEST_DISPLAY);
    expect(parsed.ok && parsed.environment).toBe("test");
  });

  test.each([
    ["an empty string", "", "empty" as const],
    ["a pasted file", `${SAMPLE_DISPLAY}x`, "bad-length" as const],
    ["too few segments", "sk0_live_short", "bad-segment-count" as const],
    ["too many segments", `sk0_live_${"0".repeat(36)}_0000_000000`, "bad-segment-count" as const],
    ["a foreign issuer", `sk1${SAMPLE_DISPLAY.slice(3)}`, "bad-issuer-prefix" as const],
    [
      "an unknown environment",
      `sk0_prod${SAMPLE_DISPLAY.slice(8)}`,
      "unknown-environment" as const,
    ],
    ["a short body", `sk0_live_${"0".repeat(42)}_000000`, "bad-body-length" as const],
    ["a long body", `sk0_live_${"0".repeat(44)}_00000`, "bad-body-length" as const],
    ["a short checksum", `sk0_live_${"0".repeat(43)}_00000`, "bad-checksum-length" as const],
    ["a non-base62 body", `sk0_live_${"-".repeat(43)}_000000`, "non-base62-character" as const],
    ["a non-base62 checksum", `sk0_live_${"0".repeat(43)}_-00000`, "non-base62-character" as const],
    ["a body above 2^256", `sk0_live_${"z".repeat(43)}_000000`, "body-out-of-range" as const],
    ["a checksum above 2^32", `sk0_live_${"0".repeat(43)}_zzzzzz`, "checksum-mismatch" as const],
    ["a wrong checksum", `${SAMPLE_DISPLAY.slice(0, 53)}000000`, "checksum-mismatch" as const],
  ])("rejects %s", (_name, display, reason) => {
    expectFailure(display, reason);
  });

  test("enforces the 2^256 bound exactly, rejecting rather than truncating", () => {
    // 43 base62 characters reach past 2^256 and the display regex cannot say
    // so, which is why `datamodel/api-key` puts the bound on the parser.
    const maximum = 2n ** 256n - 1n;
    expectFailure(
      `sk0_live_${base62Of(maximum + 1n, API_KEY_BODY_CHARS)}_000000`,
      "body-out-of-range",
    );

    const allOnes = new Uint8Array(API_KEY_BYTES).fill(0xff);
    expect(base62Of(maximum, API_KEY_BODY_CHARS)).toBe(
      oracleDisplay(allOnes, "live").split("_")[2],
    );
    expect(parsedBytes(oracleDisplay(allOnes, "live"))).toStrictEqual(allOnes);
  });

  test("reports rather than throws, so a typo can be told from a denial", () => {
    expect(() => parseApiKey("nonsense")).not.toThrow();
  });

  test("rejects a substitution at every single position", () => {
    for (let index = 0; index < SAMPLE_DISPLAY.length; index += 1) {
      const original = SAMPLE_DISPLAY[index];
      for (const replacement of ["0", "x", "Z", "_"]) {
        if (replacement === original) {
          continue;
        }
        const typo = SAMPLE_DISPLAY.slice(0, index) + replacement + SAMPLE_DISPLAY.slice(index + 1);
        expect(`${index}:${replacement}:${parseApiKey(typo).ok}`).toBe(
          `${index}:${replacement}:false`,
        );
      }
    }
  });

  test("rejects a dropped character at every single position", () => {
    for (let index = 0; index < SAMPLE_DISPLAY.length; index += 1) {
      const typo = SAMPLE_DISPLAY.slice(0, index) + SAMPLE_DISPLAY.slice(index + 1);
      expect(`${index}:${parseApiKey(typo).ok}`).toBe(`${index}:false`);
    }
  });

  test("rejects a doubled character at every single position", () => {
    for (let index = 0; index < SAMPLE_DISPLAY.length; index += 1) {
      const typo = SAMPLE_DISPLAY.slice(0, index + 1) + SAMPLE_DISPLAY.slice(index);
      expect(`${index}:${parseApiKey(typo).ok}`).toBe(`${index}:false`);
    }
  });

  test("rejects two adjacent body characters transposed", () => {
    const body = SAMPLE_DISPLAY.slice(9, 52);
    for (let index = 0; index + 1 < body.length; index += 1) {
      const first = body[index];
      const second = body[index + 1];
      if (first === second) {
        continue;
      }
      const swapped = body.slice(0, index) + second + first + body.slice(index + 2);
      expect(parseApiKey(`sk0_live_${swapped}_${SAMPLE_DISPLAY.slice(53)}`).ok).toBe(false);
    }
  });
});

describe("derivations", () => {
  test("key id is 16 bytes and matches an independent HKDF-SHA256", async () => {
    const keyId = await deriveKeyId(SAMPLE_BYTES, TENANT);
    expect(keyId).toHaveLength(KEY_ID_BYTES);
    expect(keyId).toStrictEqual(
      referenceHkdf(SAMPLE_BYTES, TENANT, HKDF_INFO_KEY_ID, KEY_ID_BYTES),
    );
  });

  test("wrap key is 32 bytes and matches an independent HKDF-SHA256", async () => {
    const wrapKey = await deriveWrapKey(SAMPLE_BYTES, TENANT);
    expect(wrapKey).toHaveLength(WRAP_KEY_BYTES);
    expect(wrapKey).toStrictEqual(
      referenceHkdf(SAMPLE_BYTES, TENANT, HKDF_INFO_WRAP_KEY, WRAP_KEY_BYTES),
    );
  });

  test("the two info strings keep the public identifier independent of the wrap key", async () => {
    const keyId = await deriveKeyId(SAMPLE_BYTES, TENANT);
    const wrapKey = await deriveWrapKey(SAMPLE_BYTES, TENANT);
    // The identifier is stored in the clear in every bundle; it must not be a
    // prefix of, or otherwise reveal, the key that opens the group.
    expect(hexEncode(wrapKey).startsWith(hexEncode(keyId))).toBe(false);
  });

  test("the salt is the tenant id, so the same key derives differently per tenant", async () => {
    const here = await deriveKeyId(SAMPLE_BYTES, TENANT);
    const there = await deriveKeyId(SAMPLE_BYTES, OTHER_TENANT);
    expect(here).not.toStrictEqual(there);
    expect(await deriveWrapKey(SAMPLE_BYTES, TENANT)).not.toStrictEqual(
      await deriveWrapKey(SAMPLE_BYTES, OTHER_TENANT),
    );
  });

  test("the salt is the tenant id's exact UTF-8 bytes, uncanonicalised", async () => {
    // Case, surrounding space and hyphenation are all load-bearing: a tenant id
    // spelled differently derives a key id that finds nothing, silently.
    const canonical = hexEncode(await deriveKeyId(SAMPLE_BYTES, TENANT));
    for (const spelling of [TENANT.toUpperCase(), ` ${TENANT}`, TENANT.replace("_", "-")]) {
      expect(hexEncode(await deriveKeyId(SAMPLE_BYTES, spelling))).not.toBe(canonical);
    }
    // And a non-ASCII id is salted with its UTF-8 bytes, not its code units.
    const unicode = "tenant_ünïcode";
    expect(await deriveKeyId(SAMPLE_BYTES, unicode)).toStrictEqual(
      referenceHkdf(SAMPLE_BYTES, unicode, HKDF_INFO_KEY_ID, KEY_ID_BYTES),
    );
  });

  test("is deterministic for one key and tenant", async () => {
    expect(await deriveKeyId(SAMPLE_BYTES, TENANT)).toStrictEqual(
      await deriveKeyId(SAMPLE_BYTES, TENANT),
    );
  });

  test("different keys derive different identifiers", async () => {
    const other = asApiKeyBytes(Uint8Array.from(SAMPLE_BYTES));
    other[0] = (other[0] ?? 0) ^ 0x01;
    expect(await deriveKeyId(other, TENANT)).not.toStrictEqual(
      await deriveKeyId(SAMPLE_BYTES, TENANT),
    );
  });

  test("the hex form is what a bucket stores", async () => {
    const hex = await deriveKeyIdHex(SAMPLE_BYTES, TENANT);
    expect(hex).toMatch(/^[0-9a-f]{32}$/);
    expect(hex).toBe(hexEncode(await deriveKeyId(SAMPLE_BYTES, TENANT)));
  });

  test("refuses anything but the raw 32 bytes — notably the display string", async () => {
    // Unreachable with a branded input; reachable from JS, where handing over
    // the display string is the commonest mistake there is.
    await expect(
      deriveKeyId(untyped<ApiKeyBytes>(utf8Encode(SAMPLE_DISPLAY)), TENANT),
    ).rejects.toThrow(RangeError);
    await expect(deriveWrapKey(untyped<ApiKeyBytes>(new Uint8Array(31)), TENANT)).rejects.toThrow(
      RangeError,
    );
  });
});
