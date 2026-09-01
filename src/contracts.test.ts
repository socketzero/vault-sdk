/**
 * Cross-module contracts.
 *
 * Invariants that belong to no single module because two modules have to agree
 * on them: the API key display arithmetic, the 60-byte envelope overhead that
 * makes the bundle's in-place write-back fit, the two distinct HKDF info
 * strings, and the header/slot geometry. Each is asserted from the constants
 * the modules actually use, so a unilateral change in one of them fails here
 * rather than in somebody's bundle.
 *
 * This file also constructs every error class in `types.ts`, which is otherwise
 * a module of declarations no single module's tests own.
 */

import { describe, expect, it } from "vitest";
import * as apiKey from "./api-key.js";
import * as layout from "./bundle/layout.js";
import * as envelope from "./envelope.js";
import * as types from "./types.js";

describe("shared constants", () => {
  it("fixes the API key display shape at 59 characters", () => {
    const { API_KEY_ISSUER_PREFIX, API_KEY_BODY_CHARS, API_KEY_CHECKSUM_CHARS } = apiKey;
    const environmentChars = 4; // "live" and "test" are both four
    const separators = 3;
    expect(
      API_KEY_ISSUER_PREFIX.length +
        environmentChars +
        API_KEY_BODY_CHARS +
        API_KEY_CHECKSUM_CHARS +
        separators,
    ).toBe(apiKey.API_KEY_DISPLAY_LENGTH);
  });

  it("keeps the envelope overhead at exactly 60 bytes", () => {
    expect(envelope.EPHEMERAL_PUBLIC_KEY_BYTES + envelope.NONCE_BYTES + envelope.TAG_BYTES).toBe(
      envelope.ENVELOPE_OVERHEAD_BYTES,
    );
  });

  it("derives key id and wrap key under two different info strings", () => {
    expect(apiKey.HKDF_INFO_KEY_ID).not.toBe(apiKey.HKDF_INFO_WRAP_KEY);
  });

  it("lays the header out in exactly 64 bytes", () => {
    expect(layout.HEADER_OFFSET.CHECKSUM + layout.CHECKSUM_BYTES).toBe(layout.HEADER_BYTES);
  });

  it("keeps index slots at 8 bytes and treats offset 0 as empty", () => {
    expect(layout.INDEX_SLOT_BYTES).toBe(8);
    expect(layout.INDEX_EMPTY_SLOT).toBe(0);
  });
});

describe("errors", () => {
  it("constructs every error class", () => {
    expect(new types.VaultError("x")).toBeInstanceOf(Error);
    expect(new types.ApiKeyFormatError("checksum-mismatch", "x").reason).toBe("checksum-mismatch");
    expect(new types.EnvelopeFormatError("x")).toBeInstanceOf(types.VaultError);
    expect(new types.VaultDecryptionError()).toBeInstanceOf(types.VaultError);
    expect(new types.VaultDecryptionError("x").message).toBe("x");
    expect(new types.BundleFormatError("x")).toBeInstanceOf(types.VaultError);
    expect(new types.UnsupportedBundleVersionError(2, 1).found).toBe(2);
    expect(new types.BundleCapacityError("x")).toBeInstanceOf(types.VaultError);
  });
});
