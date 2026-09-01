/**
 * The API key format and its two derivations (`datamodel/api-key`).
 *
 *     sk0_live_bl5P5fbg8iT8NCjg1g3ZFujxc8wkEqsdBiazmNyib0N_0BKAzU
 *     |__| |__| |_________________________________________| |____|
 *      3    4                     43                          6
 *
 *     key      = base62_decode(body)                                 32 bytes
 *     verify   = crc32(key) == base62_decode(checksum)
 *     key_id   = HKDF-SHA256(key, salt=utf8(tenant_id), "socket0/v1/key-id",   16)
 *     wrap_key = HKDF-SHA256(key, salt=utf8(tenant_id), "socket0/v1/tmk-wrap", 32)
 *
 * Two different info strings over one secret, so the identifier stored in the
 * clear in every bundle is independent of the key that opens the group. The
 * salt is the **exact UTF-8 bytes of the tenant id** — never canonicalised,
 * never the group's public half, which rotates while `key_id` must not.
 *
 * Base62 is `0-9A-Za-z` in that order and the checksum is CRC-32 with the
 * reflected IEEE polynomial `0xEDB88320` (`encoding.ts` pins both). The
 * derivation input is the raw 32 bytes: the prefix and the checksum are
 * packaging, and changing them must not invalidate a key that already exists.
 *
 * **Minting.** `generateApiKey` is the only way to make a key, and it takes
 * nothing but an environment. `requirement/api-key-entropy` is explicit that
 * "no code path accepts a caller-supplied key, seed or passphrase", so the
 * `bytes → display` formatter is module-internal; the exported `formatApiKey`
 * re-renders a key that already exists and cannot mint one.
 */

import {
  BASE62_ALPHABET,
  base62Decode,
  base62Encode,
  crc32,
  hexEncode,
  utf8Encode,
} from "./encoding.js";
import {
  API_KEY_MATERIAL_BYTES,
  type ApiKeyBytes,
  type ApiKeyEnvironment,
  type ApiKeyMaterial,
  type ApiKeyParseFailure,
  asApiKeyBytes,
  type ParsedApiKey,
} from "./types.js";

/** Fixed issuer prefix. */
export const API_KEY_ISSUER_PREFIX = "sk0";
/** The secret is 32 random bytes, and only ever 32 random bytes. */
export const API_KEY_BYTES = API_KEY_MATERIAL_BYTES;
/** 32 bytes in base62, fixed width. */
export const API_KEY_BODY_CHARS = 43;
/** A CRC-32 in base62, fixed width. */
export const API_KEY_CHECKSUM_CHARS = 6;
/** `3 + 1 + 4 + 1 + 43 + 1 + 6`. */
export const API_KEY_DISPLAY_LENGTH = 59;
/** The separator between the four segments. Unambiguous because the body is alphanumeric. */
export const API_KEY_SEPARATOR = "_";
/** The environments that may appear in the second segment, in display order. */
export const API_KEY_ENVIRONMENTS: readonly ApiKeyEnvironment[] = ["live", "test"];

/** Info string for the identifier stored in the clear in every bundle. */
export const HKDF_INFO_KEY_ID = "socket0/v1/key-id";
/** Info string for the key that opens K1. */
export const HKDF_INFO_WRAP_KEY = "socket0/v1/tmk-wrap";
/** `key_id` is 16 bytes, displayed as 32 hex characters. */
export const KEY_ID_BYTES = 16;
/** `wrap_key` is a 32-byte AES-256 key. */
export const WRAP_KEY_BYTES = 32;

/** A CRC-32 is four bytes wide before it is rendered in base62. */
const CHECKSUM_BYTES = 4;
/** Issuer, environment, body, checksum. */
const SEGMENT_COUNT = 4;

/** The four segments, once their number is known. */
type KeySegments = readonly [string, string, string, string];

/**
 * Mint a new key: 32 bytes from `crypto.getRandomValues`, formatted for display.
 *
 * The **only** way to obtain key material. There is deliberately no overload
 * taking bytes: never derived from a password, never influenced by a user,
 * never regenerated from anything reproducible (`requirement/api-key-entropy`).
 *
 * @throws {RangeError} if `environment` is not one of `API_KEY_ENVIRONMENTS` —
 *   an untyped caller passing `"prod"` would otherwise mint `sk0_prod_…`, which
 *   the published display format has no room for.
 */
export function generateApiKey(environment: ApiKeyEnvironment): ApiKeyMaterial {
  const checked = requireEnvironment(environment);
  const bytes = asApiKeyBytes(globalThis.crypto.getRandomValues(new Uint8Array(API_KEY_BYTES)));
  return { environment: checked, bytes, display: formatDisplay(bytes, checked) };
}

/**
 * Re-render the display form of a key that already exists, and check it against
 * the display carried alongside it.
 *
 * Not a minting function: it accepts no loose bytes, only material that
 * `generateApiKey` or `parseApiKey` produced. It is the check for material that
 * has been round-tripped through storage — a JSON copy keeps the display but
 * loses nothing else, so a display edited apart from its bytes is caught here
 * rather than at a relay that answers every bad key identically.
 *
 * @throws {RangeError} if the environment is unknown, the bytes are not 32, or
 *   the recomputed display disagrees with `material.display`. No message quotes
 *   the key.
 */
export function formatApiKey(material: ApiKeyMaterial): string {
  const display = formatDisplay(
    asApiKeyBytes(material.bytes),
    requireEnvironment(material.environment),
  );
  if (display !== material.display) {
    throw new RangeError("the API key material and its display form disagree");
  }
  return display;
}

/**
 * Validate shape **and** checksum locally, before anything is attempted with
 * the key, and return the raw bytes on success.
 *
 * Never throws: the failure variant carries a machine reason, because a wrong
 * key and a mistyped key are otherwise the same event to everybody involved —
 * the relay answers both with an authentication-tag failure on purpose.
 *
 * The failure messages never quote the input, so a rejected key cannot be
 * reconstructed from a log line.
 */
export function parseApiKey(display: string): ParsedApiKey {
  if (display.length === 0) {
    return failure("empty", "an API key was expected, but the string is empty");
  }
  // Nothing longer than a well-formed key can be one. Rejecting on length here
  // (rather than after splitting) keeps an accidental paste of a whole file
  // from being scanned, and still leaves every shorter shape a precise reason.
  if (display.length > API_KEY_DISPLAY_LENGTH) {
    return failure(
      "bad-length",
      `an API key is ${API_KEY_DISPLAY_LENGTH} characters, got ${display.length}`,
    );
  }

  const segments = display.split(API_KEY_SEPARATOR);
  if (!hasAllSegments(segments)) {
    return failure(
      "bad-segment-count",
      `an API key has ${SEGMENT_COUNT} '${API_KEY_SEPARATOR}'-separated segments, got ${segments.length}`,
    );
  }
  const [prefix, environment, body, checksum] = segments;

  if (prefix !== API_KEY_ISSUER_PREFIX) {
    return failure("bad-issuer-prefix", `an API key starts with '${API_KEY_ISSUER_PREFIX}'`);
  }
  if (!isEnvironment(environment)) {
    return failure(
      "unknown-environment",
      `the environment segment must be one of: ${API_KEY_ENVIRONMENTS.join(", ")}`,
    );
  }
  if (body.length !== API_KEY_BODY_CHARS) {
    return failure(
      "bad-body-length",
      `the key body is ${API_KEY_BODY_CHARS} characters, got ${body.length}`,
    );
  }
  if (checksum.length !== API_KEY_CHECKSUM_CHARS) {
    return failure(
      "bad-checksum-length",
      `the checksum is ${API_KEY_CHECKSUM_CHARS} characters, got ${checksum.length}`,
    );
  }
  if (!isBase62(body) || !isBase62(checksum)) {
    return failure(
      "non-base62-character",
      "the body and checksum use base62 characters (0-9, A-Z, a-z) only",
    );
  }

  // 62^43 is a shade over 2^256, so a well-shaped body can still name a number
  // too large to be 32 bytes. The display regex cannot express that bound, so
  // the parser has to: reject, never truncate (`datamodel/api-key`).
  const bytes = tryBase62Decode(body, API_KEY_BYTES);
  if (bytes === undefined) {
    return failure("body-out-of-range", `the key body does not name a ${API_KEY_BYTES}-byte value`);
  }

  // Likewise 62^6 > 2^32: an over-range checksum decodes to nothing, and is
  // therefore not the CRC of this key — which is exactly a checksum mismatch.
  if (tryBase62Decode(checksum, CHECKSUM_BYTES) === undefined) {
    return mistyped();
  }
  if (checksum !== base62Encode(checksumBytes(bytes), API_KEY_CHECKSUM_CHARS)) {
    return mistyped();
  }

  return { ok: true, environment, bytes: asApiKeyBytes(bytes), display };
}

/**
 * `HKDF-SHA256(apiKey, salt=utf8(tenantId), info="socket0/v1/key-id", 16)`.
 *
 * @param apiKey the RAW 32 bytes, never the display string.
 * @param tenantId the tenant id, whose exact UTF-8 bytes are the HKDF salt.
 * @returns 16 bytes.
 */
export function deriveKeyId(apiKey: ApiKeyBytes, tenantId: string): Promise<Uint8Array> {
  return hkdf(apiKey, tenantId, HKDF_INFO_KEY_ID, KEY_ID_BYTES);
}

/** `deriveKeyId` rendered as the 32 lowercase hex characters a bucket stores. */
export async function deriveKeyIdHex(apiKey: ApiKeyBytes, tenantId: string): Promise<string> {
  return hexEncode(await deriveKeyId(apiKey, tenantId));
}

/**
 * `HKDF-SHA256(apiKey, salt=utf8(tenantId), info="socket0/v1/tmk-wrap", 32)`.
 *
 * @param apiKey the RAW 32 bytes, never the display string.
 * @returns 32 bytes, the AES-256-GCM key that opens a bucket entry.
 */
export function deriveWrapKey(apiKey: ApiKeyBytes, tenantId: string): Promise<Uint8Array> {
  return hkdf(apiKey, tenantId, HKDF_INFO_WRAP_KEY, WRAP_KEY_BYTES);
}

/**
 * Render 32 raw bytes as the display form, appending the base62 CRC-32 of those
 * same bytes.
 *
 * Module-internal: exporting it would be a public path from caller-supplied
 * bytes to a key that parses, which `requirement/api-key-entropy` forbids.
 */
function formatDisplay(bytes: ApiKeyBytes, environment: ApiKeyEnvironment): string {
  const body = base62Encode(bytes, API_KEY_BODY_CHARS);
  const checksum = base62Encode(checksumBytes(bytes), API_KEY_CHECKSUM_CHARS);
  return [API_KEY_ISSUER_PREFIX, environment, body, checksum].join(API_KEY_SEPARATOR);
}

/**
 * The environment, checked at runtime.
 *
 * The type says `"live" | "test"`, but the type is not there at runtime and the
 * display format has exactly four characters for this segment: an unchecked
 * `"prod"` mints a string no parser will ever accept.
 *
 * @throws {RangeError} on anything else.
 */
function requireEnvironment(environment: ApiKeyEnvironment): ApiKeyEnvironment {
  if (!isEnvironment(environment)) {
    throw new RangeError(
      `the environment must be one of: ${API_KEY_ENVIRONMENTS.join(", ")}, got '${String(environment)}'`,
    );
  }
  return environment;
}

/**
 * One HKDF-SHA256 expansion over the raw key material.
 *
 * The two callers differ only in `info` and output length, which is the whole
 * of the separation the format relies on: `key_id` travels in the clear in
 * every bundle, `wrap_key` opens the group, and neither can be computed from
 * the other. The salt is the tenant id's exact UTF-8 bytes — uncanonicalised,
 * and stable across rotation.
 */
async function hkdf(
  apiKey: ApiKeyBytes,
  tenantId: string,
  info: string,
  byteLength: number,
): Promise<Uint8Array> {
  if (apiKey.length !== API_KEY_BYTES) {
    // Unreachable through `asApiKeyBytes`, which is the only sanctioned way to
    // brand these bytes. It stays for the untyped caller, whose commonest way
    // to get this wrong is to hand over the display string.
    throw new RangeError(`HKDF input is the raw ${API_KEY_BYTES} key bytes, got ${apiKey.length}`);
  }
  const material = await globalThis.crypto.subtle.importKey(
    "raw",
    unshared(apiKey),
    "HKDF",
    false,
    ["deriveBits"],
  );
  const bits = await globalThis.crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: unshared(utf8Encode(tenantId)),
      info: unshared(utf8Encode(info)),
    },
    material,
    byteLength * 8,
  );
  return new Uint8Array(bits);
}

/**
 * Copy a view onto a buffer known not to be shared.
 *
 * Web Crypto refuses a `SharedArrayBuffer`, and a plain `Uint8Array` cannot
 * prove it is not backed by one. The inputs here are at most a few dozen bytes,
 * so a copy costs nothing and keeps the public signatures free of a cast.
 */
function unshared(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(bytes);
}

/** The CRC-32 of the raw key, big-endian, ready for base62. */
function checksumBytes(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(CHECKSUM_BYTES);
  new DataView(out.buffer).setUint32(0, crc32(bytes), false);
  return out;
}

/** `undefined` when the text names a number wider than `byteLength`. */
function tryBase62Decode(text: string, byteLength: number): Uint8Array | undefined {
  try {
    return base62Decode(text, byteLength);
  } catch {
    return undefined;
  }
}

function hasAllSegments(segments: readonly string[]): segments is KeySegments {
  return segments.length === SEGMENT_COUNT;
}

function isEnvironment(value: string): value is ApiKeyEnvironment {
  return (API_KEY_ENVIRONMENTS as readonly string[]).includes(value);
}

function isBase62(text: string): boolean {
  for (const character of text) {
    if (!BASE62_ALPHABET.includes(character)) {
      return false;
    }
  }
  return true;
}

function mistyped(): ParsedApiKey {
  return failure("checksum-mismatch", "the checksum does not match the key — it looks mistyped");
}

function failure(reason: ApiKeyParseFailure, message: string): ParsedApiKey {
  return { ok: false, reason, message };
}
