import { describe, expect, test } from "vitest";
import {
  API_KEY_MATERIAL_BYTES,
  type ApiKeyBytes,
  ApiKeyFormatError,
  type ApiKeyMaterial,
  asApiKeyBytes,
  asPrivateKey,
  asPublicKey,
  BundleCapacityError,
  BundleFormatError,
  EnvelopeFormatError,
  FieldState,
  type GroupRotation,
  type ParsedApiKey,
  type PrivateKey,
  type PublicKey,
  requireApiKey,
  SEAL_ALGORITHM,
  UnsupportedBundleVersionError,
  VaultDecryptionError,
  VaultError,
  X25519_PRIVATE_KEY_BYTES,
  X25519_PUBLIC_KEY_BYTES,
} from "./types.js";

/**
 * A compile-time assertion, spelled as a value so it is both checked by `tsc`
 * and reachable from a test. `assertTrue<false>(...)` does not compile.
 */
const assertTrue = <T extends true>(value: T): T => value;
/** True only when `T` is assignable to `U`. */
type Assignable<T, U> = [T] extends [U] ? true : false;
/** True only when `T` is NOT assignable to `U` — the shape most of these want. */
type NotAssignable<T, U> = Assignable<T, U> extends false ? true : false;

describe("the brands are nominal", () => {
  // These are the substitutions that produce an envelope nobody can ever open.
  // If either half ever becomes assignable to the other, this file stops
  // compiling — which is the whole reason the brands exist.
  test("no key role is assignable to another, and none is forgeable", () => {
    expect(assertTrue<NotAssignable<PrivateKey, PublicKey>>(true)).toBe(true);
    expect(assertTrue<NotAssignable<PublicKey, PrivateKey>>(true)).toBe(true);
    expect(assertTrue<NotAssignable<ApiKeyBytes, PrivateKey>>(true)).toBe(true);
    expect(assertTrue<NotAssignable<PrivateKey, ApiKeyBytes>>(true)).toBe(true);
    // A plain array cannot be branded by structural typing, only by a constructor.
    expect(assertTrue<NotAssignable<Uint8Array, PublicKey>>(true)).toBe(true);
  });

  test("a brand narrows without stopping a key reaching Web Crypto", () => {
    expect(assertTrue<Assignable<PublicKey, Uint8Array>>(true)).toBe(true);
    expect(assertTrue<Assignable<PrivateKey, Uint8Array>>(true)).toBe(true);
    // The parse result carries branded material, so `parsed.bytes` needs no cast.
    expect(assertTrue<Assignable<ApiKeyMaterial["bytes"], ApiKeyBytes>>(true)).toBe(true);
  });

  test("rotation lands as one object: no member of the result is optional", () => {
    expect(
      assertTrue<
        Assignable<
          GroupRotation,
          Required<Pick<GroupRotation, "publicKey" | "privateKey" | "fields" | "bucket">>
        >
      >(true),
    ).toBe(true);
  });
});

describe("key brands", () => {
  test("a correctly sized array brands as any of the three roles", () => {
    const bytes = new Uint8Array(32);

    expect(asPublicKey(bytes)).toBe(bytes);
    expect(asPrivateKey(bytes)).toBe(bytes);
    expect(asApiKeyBytes(bytes)).toBe(bytes);
  });

  test("branding does not copy, because a bundle view must not be copied", () => {
    const buffer = new Uint8Array(64);
    const view = buffer.subarray(8, 40);

    const key = asPublicKey(view);
    key[0] = 7;

    expect(buffer[8]).toBe(7);
  });

  test.each([
    ["asPublicKey", asPublicKey, X25519_PUBLIC_KEY_BYTES],
    ["asPrivateKey", asPrivateKey, X25519_PRIVATE_KEY_BYTES],
    ["asApiKeyBytes", asApiKeyBytes, API_KEY_MATERIAL_BYTES],
  ] as const)("%s refuses the wrong length", (_name, brand, expected) => {
    expect(() => brand(new Uint8Array(expected - 1))).toThrow(RangeError);
    expect(() => brand(new Uint8Array(expected + 1))).toThrow(
      new RegExp(`${expected} bytes, got ${expected + 1}`),
    );
    expect(() => brand(new Uint8Array(0))).toThrow(RangeError);
  });
});

describe("requireApiKey", () => {
  const material: ApiKeyMaterial = {
    environment: "live",
    bytes: asApiKeyBytes(new Uint8Array(API_KEY_MATERIAL_BYTES)),
    display: "sk0_live_body_check",
  };

  test("returns the material of a successful parse", () => {
    const parsed: ParsedApiKey = { ok: true, ...material };

    expect(requireApiKey(parsed)).toEqual({ ok: true, ...material });
  });

  test("throws the format error a failed parse describes", () => {
    const parsed: ParsedApiKey = {
      ok: false,
      reason: "checksum-mismatch",
      message: "checksum does not match",
    };

    expect(() => requireApiKey(parsed)).toThrow(ApiKeyFormatError);
    try {
      requireApiKey(parsed);
      expect.unreachable("requireApiKey must throw on a failed parse");
    } catch (error) {
      expect(error).toBeInstanceOf(ApiKeyFormatError);
      const formatError = error as ApiKeyFormatError;
      expect(formatError.reason).toBe("checksum-mismatch");
      expect(formatError.message).toBe("checksum does not match");
      expect(formatError.name).toBe("ApiKeyFormatError");
    }
  });
});

describe("constants", () => {
  test("the algorithm label and the field states are the catalog's", () => {
    expect(SEAL_ALGORITHM).toBe("x25519-hkdf-aesgcm");
    expect(FieldState.Sealed).toBe(0);
    expect(FieldState.Open).toBe(1);
    expect(X25519_PUBLIC_KEY_BYTES).toBe(32);
    expect(X25519_PRIVATE_KEY_BYTES).toBe(32);
    expect(API_KEY_MATERIAL_BYTES).toBe(32);
  });
});

describe("errors", () => {
  test("every error is a VaultError and names itself", () => {
    const cases = [
      [new VaultError("base"), "VaultError", "base"],
      [new ApiKeyFormatError("empty", "empty"), "ApiKeyFormatError", "empty"],
      [new EnvelopeFormatError("bad base64"), "EnvelopeFormatError", "bad base64"],
      [new BundleFormatError("truncated"), "BundleFormatError", "truncated"],
      [new BundleCapacityError("too many"), "BundleCapacityError", "too many"],
    ] as const;

    for (const [error, name, message] of cases) {
      expect(error).toBeInstanceOf(VaultError);
      expect(error).toBeInstanceOf(Error);
      expect(error.name).toBe(name);
      expect(error.message).toBe(message);
    }
  });

  test("a cause survives the base constructor", () => {
    const cause = new Error("underlying");

    expect(new VaultError("wrapped", { cause }).cause).toBe(cause);
    expect(new VaultError("bare").cause).toBeUndefined();
  });

  test("decryption failure says nothing a caller could enumerate with", () => {
    expect(new VaultDecryptionError().message).toBe("decryption failed");
    expect(new VaultDecryptionError("still nothing").message).toBe("still nothing");
    expect(new VaultDecryptionError().name).toBe("VaultDecryptionError");
  });

  test("an unsupported version reports both numbers", () => {
    const error = new UnsupportedBundleVersionError(4, 1);

    expect(error.found).toBe(4);
    expect(error.supported).toBe(1);
    expect(error.message).toBe("bundle version 4 is newer than the supported version 1");
    expect(error.name).toBe("UnsupportedBundleVersionError");
  });
});
