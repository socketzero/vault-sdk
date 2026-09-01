/**
 * The API key format and its two derivations (`datamodel/api-key`).
 *
 *     sk0_live_bl5P5fbg8iT8NCjg1g3ZFujxc8wkEqsdBiazmNyib0N_0BKAzU
 *     |__| |__| |_________________________________________| |____|
 *      3    4                     43                          6
 *
 *     key      = base62_decode(body)                              32 bytes
 *     key_id   = HKDF-SHA256(key, salt=tenant_id, "socket0/v1/key-id",   16)
 *     wrap_key = HKDF-SHA256(key, salt=tenant_id, "socket0/v1/tmk-wrap", 32)
 *
 * Two different info strings over one secret, so the identifier stored in the
 * clear in every bundle is independent of the key that opens the group. The
 * salt is the **tenant id** — never the group's public half, which rotates
 * while `key_id` must not.
 *
 * The derivation input is the raw 32 bytes. The prefix and the checksum are
 * packaging; changing them must not invalidate a key that already exists.
 */

import type { ApiKeyEnvironment, ApiKeyMaterial, ParsedApiKey } from "./types.js";

/** Fixed issuer prefix. */
export const API_KEY_ISSUER_PREFIX = "sk0";
/** The secret is 32 random bytes, and only ever 32 random bytes. */
export const API_KEY_BYTES = 32;
/** 32 bytes in base62, fixed width. */
export const API_KEY_BODY_CHARS = 43;
/** A CRC-32 in base62, fixed width. */
export const API_KEY_CHECKSUM_CHARS = 6;
/** `3 + 1 + 4 + 1 + 43 + 1 + 6`. */
export const API_KEY_DISPLAY_LENGTH = 59;
/** The separator between the four segments. Unambiguous because the body is alphanumeric. */
export const API_KEY_SEPARATOR = "_";

/** Info string for the identifier stored in the clear in every bundle. */
export const HKDF_INFO_KEY_ID = "socket0/v1/key-id";
/** Info string for the key that opens K1. */
export const HKDF_INFO_WRAP_KEY = "socket0/v1/tmk-wrap";
/** `key_id` is 16 bytes, displayed as 32 hex characters. */
export const KEY_ID_BYTES = 16;
/** `wrap_key` is a 32-byte AES-256 key. */
export const WRAP_KEY_BYTES = 32;

/**
 * Mint a new key: 32 bytes from `crypto.getRandomValues`, formatted for display.
 *
 * Never derived from a password, never influenced by a user, never regenerated
 * from anything reproducible (`requirement/api-key-entropy`).
 */
export function generateApiKey(environment: ApiKeyEnvironment): ApiKeyMaterial {
  void environment;
  throw new Error("not implemented");
}

/**
 * Render 32 raw bytes as the display form, appending the base62 CRC-32 of those
 * same bytes.
 *
 * @throws {RangeError} if `bytes.length !== API_KEY_BYTES`.
 */
export function formatApiKey(bytes: Uint8Array, environment: ApiKeyEnvironment): string {
  void bytes;
  void environment;
  throw new Error("not implemented");
}

/**
 * Validate shape **and** checksum locally, before anything is attempted with
 * the key, and return the raw bytes on success.
 *
 * Never throws: the failure variant carries a machine reason, because a typo
 * and an attack are otherwise the same event to everybody involved.
 */
export function parseApiKey(display: string): ParsedApiKey {
  void display;
  throw new Error("not implemented");
}

/**
 * `HKDF-SHA256(apiKey, salt=tenantId, info="socket0/v1/key-id", 16)`.
 *
 * @param apiKey the RAW 32 bytes, never the display string.
 * @param tenantId the tenant id, used verbatim as the HKDF salt.
 * @returns 16 bytes.
 */
export function deriveKeyId(apiKey: Uint8Array, tenantId: string): Promise<Uint8Array> {
  void apiKey;
  void tenantId;
  throw new Error("not implemented");
}

/** `deriveKeyId` rendered as the 32 lowercase hex characters a bucket stores. */
export function deriveKeyIdHex(apiKey: Uint8Array, tenantId: string): Promise<string> {
  void apiKey;
  void tenantId;
  throw new Error("not implemented");
}

/**
 * `HKDF-SHA256(apiKey, salt=tenantId, info="socket0/v1/tmk-wrap", 32)`.
 *
 * @param apiKey the RAW 32 bytes, never the display string.
 * @returns 32 bytes, the AES-256-GCM key that opens a bucket entry.
 */
export function deriveWrapKey(apiKey: Uint8Array, tenantId: string): Promise<Uint8Array> {
  void apiKey;
  void tenantId;
  throw new Error("not implemented");
}
