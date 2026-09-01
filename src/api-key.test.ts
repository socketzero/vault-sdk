import { hkdfSync } from "node:crypto";
import { describe, expect, test } from "vitest";
import {
  API_KEY_BODY_CHARS,
  API_KEY_BYTES,
  API_KEY_CHECKSUM_CHARS,
  API_KEY_DISPLAY_LENGTH,
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
import { hexEncode, utf8Encode } from "./encoding.js";
import type { ApiKeyEnvironment, ApiKeyParseFailure } from "./types.js";

/** A fixed key, so every "one typo" case below is deterministic. */
const SAMPLE_BYTES = new Uint8Array(API_KEY_BYTES).map((_, index) => index * 7 + 1);
const SAMPLE_DISPLAY = formatApiKey(SAMPLE_BYTES, "live");

const TENANT = "tenant_01HZY8Q7";
const OTHER_TENANT = "tenant_01HZY8Q8";

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

function parsedBytes(display: string): Uint8Array {
  const parsed = parseApiKey(display);
  if (!parsed.ok) {
    throw new Error(`expected a valid key, got ${parsed.reason}`);
  }
  return parsed.bytes;
}

/** Independent HKDF-SHA256 oracle: Node's, not the one under test. */
function referenceHkdf(key: Uint8Array, salt: string, info: string, length: number): Uint8Array {
  return new Uint8Array(hkdfSync("sha256", key, utf8Encode(salt), utf8Encode(info), length));
}

describe("formatApiKey", () => {
  test("renders the four fixed-width segments", () => {
    const segments = SAMPLE_DISPLAY.split("_");
    expect(segments).toHaveLength(4);
    expect(segments[0]).toBe("sk0");
    expect(segments[1]).toBe("live");
    expect(segments[2]).toHaveLength(API_KEY_BODY_CHARS);
    expect(segments[3]).toHaveLength(API_KEY_CHECKSUM_CHARS);
    expect(SAMPLE_DISPLAY).toHaveLength(API_KEY_DISPLAY_LENGTH);
  });

  test("is stable for a given input", () => {
    expect(formatApiKey(SAMPLE_BYTES, "live")).toBe(SAMPLE_DISPLAY);
  });

  test("distinguishes the environments at a glance", () => {
    const test_ = formatApiKey(SAMPLE_BYTES, "test");
    expect(test_.startsWith("sk0_test_")).toBe(true);
    // Only the environment segment differs: the checksum covers the bytes, not the packaging.
    expect(test_.slice(9)).toBe(SAMPLE_DISPLAY.slice(9));
  });

  test("left-pads a small value to the full body width", () => {
    const display = formatApiKey(new Uint8Array(API_KEY_BYTES), "live");
    expect(display.split("_")[2]).toBe("0".repeat(API_KEY_BODY_CHARS));
    expect(parseApiKey(display).ok).toBe(true);
  });

  test("accepts only 32 bytes", () => {
    expect(() => formatApiKey(new Uint8Array(31), "live")).toThrow(RangeError);
    expect(() => formatApiKey(new Uint8Array(33), "live")).toThrow(RangeError);
  });
});

describe("generateApiKey", () => {
  test.each<ApiKeyEnvironment>(["live", "test"])("mints a parseable %s key", (environment) => {
    const minted = generateApiKey(environment);
    expect(minted.bytes).toHaveLength(API_KEY_BYTES);
    expect(minted.environment).toBe(environment);
    expect(minted.display).toBe(formatApiKey(minted.bytes, environment));
    expect(parsedBytes(minted.display)).toStrictEqual(minted.bytes);
  });

  test("is not reproducible", () => {
    const first = generateApiKey("live");
    const second = generateApiKey("live");
    expect(first.display).not.toBe(second.display);
  });
});

describe("parseApiKey", () => {
  test("round-trips the display form back to the raw bytes", () => {
    const parsed = parseApiKey(SAMPLE_DISPLAY);
    expect(parsed).toStrictEqual({
      ok: true,
      environment: "live",
      bytes: SAMPLE_BYTES,
      display: SAMPLE_DISPLAY,
    });
  });

  test("accepts the worked example from `datamodel/api-key` verbatim", () => {
    // A cross-check on the packaging conventions themselves — big-endian
    // base62 over the digits-first alphabet, CRC-32 over the raw bytes.
    const fromCatalog = "sk0_live_bl5P5fbg8iT8NCjg1g3ZFujxc8wkEqsdBiazmNyib0N_0BKAzU";
    expect(formatApiKey(parsedBytes(fromCatalog), "live")).toBe(fromCatalog);
  });

  test("reads the environment out of the display form", () => {
    const parsed = parseApiKey(formatApiKey(SAMPLE_BYTES, "test"));
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
  test("key id is 16 bytes and matches an independent HKDF", async () => {
    const keyId = await deriveKeyId(SAMPLE_BYTES, TENANT);
    expect(keyId).toHaveLength(KEY_ID_BYTES);
    expect(keyId).toStrictEqual(
      referenceHkdf(SAMPLE_BYTES, TENANT, HKDF_INFO_KEY_ID, KEY_ID_BYTES),
    );
  });

  test("wrap key is 32 bytes and matches an independent HKDF", async () => {
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

  test("is deterministic for one key and tenant", async () => {
    expect(await deriveKeyId(SAMPLE_BYTES, TENANT)).toStrictEqual(
      await deriveKeyId(SAMPLE_BYTES, TENANT),
    );
  });

  test("different keys derive different identifiers", async () => {
    const other = new Uint8Array(SAMPLE_BYTES);
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
    await expect(deriveKeyId(utf8Encode(SAMPLE_DISPLAY), TENANT)).rejects.toThrow(RangeError);
    await expect(deriveWrapKey(new Uint8Array(31), TENANT)).rejects.toThrow(RangeError);
  });
});
