import { describe, expect, it } from "vitest";
import { base64Decode, base64Encode } from "./encoding.js";
import {
  AAD_LENGTH_PREFIX_BYTES,
  bucketAssociatedData,
  derivePublicKey,
  ENVELOPE_OVERHEAD_BYTES,
  EPHEMERAL_PUBLIC_KEY_BYTES,
  fieldAssociatedData,
  formatEnvelope,
  generateX25519KeyPair,
  HKDF_INFO_ENVELOPE,
  NONCE_BYTES,
  open,
  parseEnvelope,
  parseEnvelopeBytes,
  seal,
  TAG_BYTES,
  X25519_BASE_POINT_BYTES,
} from "./envelope.js";
import type { PrivateKey, PublicKey } from "./types.js";
import {
  asPrivateKey,
  EnvelopeFormatError,
  SEAL_ALGORITHM,
  VaultDecryptionError,
  VaultError,
} from "./types.js";

/**
 * The brands are compile-time only, and the package ships to JavaScript
 * consumers who have no compiler at all. Casting here is how a test reaches the
 * runtime guards that exist for exactly those callers.
 */
function unchecked<T>(bytes: Uint8Array): T {
  return bytes as unknown as T;
}

const utf8 = new TextEncoder();

const CONNECTION_A = "shrd_018f2a3b-0000-7000-8000-000000000001";
const CONNECTION_B = "shrd_018f2a3b-0000-7000-8000-000000000002";

/** A payload of the minimum legal size, with no cryptographic meaning. */
function fakePayload(extra = 0): Uint8Array {
  return Uint8Array.from({ length: ENVELOPE_OVERHEAD_BYTES + extra }, (_unused, i) => i & 0xff);
}

describe("constants", () => {
  it("states the overhead as the sum of its three fixed parts", () => {
    expect(EPHEMERAL_PUBLIC_KEY_BYTES + NONCE_BYTES + TAG_BYTES).toBe(ENVELOPE_OVERHEAD_BYTES);
    expect(ENVELOPE_OVERHEAD_BYTES).toBe(60);
    expect(HKDF_INFO_ENVELOPE).toBe("socket0/v1");
    expect(X25519_BASE_POINT_BYTES).toBe(32);
  });
});

describe("generateX25519KeyPair / derivePublicKey", () => {
  it("produces 32-byte halves that are not each other", async () => {
    const pair = await generateX25519KeyPair();
    expect(pair.privateKey).toHaveLength(32);
    expect(pair.publicKey).toHaveLength(32);
    expect(pair.publicKey).not.toEqual(pair.privateKey);
  });

  it("produces a distinct keypair each call", async () => {
    const [first, second] = await Promise.all([generateX25519KeyPair(), generateX25519KeyPair()]);
    expect(first.privateKey).not.toEqual(second.privateKey);
    expect(first.publicKey).not.toEqual(second.publicKey);
  });

  it("recovers the same public half from the private half, deterministically", async () => {
    const pair = await generateX25519KeyPair();
    expect(await derivePublicKey(pair.privateKey)).toEqual(pair.publicKey);
    expect(await derivePublicKey(pair.privateKey)).toEqual(pair.publicKey);
  });

  it("matches the RFC 7748 test vector for the base point", async () => {
    // RFC 7748 §6.1: Alice's private key and the public key it must produce.
    const alicePrivate = Uint8Array.from(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a".match(/../g) ?? [],
      (byte) => Number.parseInt(byte, 16),
    );
    const alicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const derived = Array.from(await derivePublicKey(asPrivateKey(alicePrivate)), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    expect(derived).toBe(alicePublic);
  });

  it("rejects a private key that is not 32 bytes", async () => {
    const wrong = unchecked<PrivateKey>(new Uint8Array(31));
    await expect(derivePublicKey(wrong)).rejects.toBeInstanceOf(VaultError);
    await expect(derivePublicKey(wrong)).rejects.toThrow(/private key must be 32/);
  });
});

/** `u32be(len(utf8(a))) || utf8(a) || ...`, written out independently. */
function expectedAad(...components: readonly string[]): Uint8Array {
  const parts = components.map((component) => utf8.encode(component));
  const bytes: number[] = [];
  for (const part of parts) {
    const length = part.length;
    bytes.push(
      (length >>> 24) & 0xff,
      (length >>> 16) & 0xff,
      (length >>> 8) & 0xff,
      length & 0xff,
    );
    bytes.push(...part);
  }
  return Uint8Array.from(bytes);
}

describe("associated data", () => {
  it("states the length prefix as a big-endian u32", () => {
    expect(AAD_LENGTH_PREFIX_BYTES).toBe(4);
  });

  it("binds a field as AAD(connection_id, field_name)", () => {
    expect(fieldAssociatedData("conn", "password")).toEqual(expectedAad("conn", "password"));
    expect(Array.from(fieldAssociatedData("conn", "password").subarray(0, 4))).toEqual([
      0, 0, 0, 4,
    ]);
  });

  it("binds a bucket entry as AAD(group_id, key_id)", () => {
    expect(bucketAssociatedData("grp", "0a1b")).toEqual(expectedAad("grp", "0a1b"));
  });

  it("is one length prefix plus one body per component", () => {
    const aad = fieldAssociatedData(CONNECTION_A, "password");
    expect(aad).toHaveLength(2 * AAD_LENGTH_PREFIX_BYTES + CONNECTION_A.length + "password".length);
  });

  it("distinguishes two field names under one connection", () => {
    expect(fieldAssociatedData(CONNECTION_A, "password")).not.toEqual(
      fieldAssociatedData(CONNECTION_A, "api_key"),
    );
  });

  it("prefixes the UTF-8 byte length, not the code-unit count", () => {
    // "é" is one character and two UTF-8 bytes; "ß" likewise.
    expect(fieldAssociatedData("é", "ß")).toEqual(expectedAad("é", "ß"));
    expect(Array.from(fieldAssociatedData("é", "ß"))).toEqual([
      0, 0, 0, 2, 0xc3, 0xa9, 0, 0, 0, 2, 0xc3, 0x9f,
    ]);
  });

  it("accepts an empty component and still prefixes it", () => {
    expect(fieldAssociatedData("", "")).toEqual(Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0]));
  });

  it("does not canonicalise, trim or lower-case a component", () => {
    expect(fieldAssociatedData("Conn", " password ")).toEqual(expectedAad("Conn", " password "));
    expect(fieldAssociatedData("Conn", "password")).not.toEqual(
      fieldAssociatedData("conn", "password"),
    );
  });

  it("separates the shift that plain concatenation collided", () => {
    // The whole reason the prefix exists: `("conn","1password")` and
    // `("conn1","password")` concatenate to the same bytes.
    expect(utf8.encode("conn1password")).toEqual(utf8.encode("conn1password"));
    expect(fieldAssociatedData("conn", "1password")).not.toEqual(
      fieldAssociatedData("conn1", "password"),
    );
    expect(bucketAssociatedData("grp", "10a1b")).not.toEqual(bucketAssociatedData("grp1", "0a1b"));
  });
});

describe("seal / open round trip", () => {
  it("returns the plaintext under the matching key and AAD", async () => {
    const group = await generateX25519KeyPair();
    const aad = fieldAssociatedData(CONNECTION_A, "password");
    const secret = utf8.encode("hunter2");

    const envelope = await seal(secret, group.publicKey, aad);
    expect(await open(envelope, group.privateKey, aad)).toEqual(secret);
  });

  it("accepts the public half explicitly, skipping the base-point derivation", async () => {
    const group = await generateX25519KeyPair();
    const aad = fieldAssociatedData(CONNECTION_A, "token");
    const envelope = await seal(utf8.encode("value"), group.publicKey, aad);

    expect(await open(envelope, group.privateKey, aad, group.publicKey)).toEqual(
      utf8.encode("value"),
    );
  });

  it("opens raw payload bytes, the form a bundle stores", async () => {
    const group = await generateX25519KeyPair();
    const aad = fieldAssociatedData(CONNECTION_A, "password");
    const envelope = await seal(utf8.encode("from-bundle"), group.publicKey, aad);
    const payload = base64Decode(envelope.slice(SEAL_ALGORITHM.length + 1));

    expect(await open(payload, group.privateKey, aad)).toEqual(utf8.encode("from-bundle"));
  });

  it("emits the declared algorithm prefix and a decodable payload", async () => {
    const group = await generateX25519KeyPair();
    const envelope = await seal(new Uint8Array(0), group.publicKey, new Uint8Array(0));

    expect(envelope.startsWith(`${SEAL_ALGORITHM}:`)).toBe(true);
    expect(parseEnvelope(envelope).algorithm).toBe(SEAL_ALGORITHM);
  });

  it("never repeats an ephemeral key or a nonce across seals of one value", async () => {
    const group = await generateX25519KeyPair();
    const aad = fieldAssociatedData(CONNECTION_A, "password");
    const secret = utf8.encode("same input every time");

    const envelopes = await Promise.all(
      Array.from({ length: 16 }, () => seal(secret, group.publicKey, aad)),
    );
    const parts = envelopes.map(parseEnvelope);
    const ephemerals = new Set(parts.map((p) => base64Encode(p.ephemeralPublicKey)));
    const nonces = new Set(parts.map((p) => base64Encode(p.nonce)));

    expect(ephemerals.size).toBe(16);
    expect(nonces.size).toBe(16);
    expect(new Set(envelopes).size).toBe(16);
  });

  it("round-trips a plaintext backed by a SharedArrayBuffer", async () => {
    // Web Crypto refuses shared views outright, so the module must copy them
    // rather than hand `subtle` something it will reject with a DataError.
    const group = await generateX25519KeyPair();
    const aad = fieldAssociatedData(CONNECTION_A, "password");
    const shared = new Uint8Array(new SharedArrayBuffer(11));
    shared.set(utf8.encode("shared-mem "));

    const envelope = await seal(shared, group.publicKey, aad);
    expect(await open(envelope, group.privateKey, aad)).toEqual(Uint8Array.from(shared));
  });

  it("round-trips binary plaintext containing every byte value", async () => {
    const group = await generateX25519KeyPair();
    const aad = bucketAssociatedData("grp_1", "0123456789abcdef0123456789abcdef");
    const secret = Uint8Array.from({ length: 256 }, (_unused, i) => i);

    const envelope = await seal(secret, group.publicKey, aad);
    expect(await open(envelope, group.privateKey, aad)).toEqual(secret);
  });
});

describe("the 60-byte size relation", () => {
  const lengths = [0, 1, 2, 15, 16, 17, 31, 32, 33, 60, 64, 255, 256, 1000, 4096, 65_536];

  it.each(lengths)("holds for a %i-byte plaintext", async (length) => {
    const group = await generateX25519KeyPair();
    const aad = fieldAssociatedData(CONNECTION_A, "password");
    const secret = Uint8Array.from({ length }, (_unused, i) => i & 0xff);

    const envelope = await seal(secret, group.publicKey, aad);
    const payload = base64Decode(envelope.slice(SEAL_ALGORITHM.length + 1));

    // The invariant the bundle's in-place write-back cache depends on.
    expect(payload.length).toBe(length + ENVELOPE_OVERHEAD_BYTES);

    const parts = parseEnvelopeBytes(payload);
    expect(parts.ephemeralPublicKey).toHaveLength(EPHEMERAL_PUBLIC_KEY_BYTES);
    expect(parts.nonce).toHaveLength(NONCE_BYTES);
    expect(parts.ciphertextAndTag).toHaveLength(length + TAG_BYTES);
    expect(await open(payload, group.privateKey, aad)).toEqual(secret);
  });
});

describe("open rejects everything that is not the exact original", () => {
  it("fails on a different AAD field name", async () => {
    const group = await generateX25519KeyPair();
    const envelope = await seal(
      utf8.encode("low value"),
      group.publicKey,
      fieldAssociatedData(CONNECTION_A, "note"),
    );

    await expect(
      open(envelope, group.privateKey, fieldAssociatedData(CONNECTION_A, "api_key")),
    ).rejects.toBeInstanceOf(VaultDecryptionError);
  });

  it("fails when the envelope is moved to another connection", async () => {
    const group = await generateX25519KeyPair();
    const envelope = await seal(
      utf8.encode("secret"),
      group.publicKey,
      fieldAssociatedData(CONNECTION_A, "password"),
    );

    await expect(
      open(envelope, group.privateKey, fieldAssociatedData(CONNECTION_B, "password")),
    ).rejects.toBeInstanceOf(VaultDecryptionError);
  });

  it("fails under a different key group", async () => {
    const [group, other] = await Promise.all([generateX25519KeyPair(), generateX25519KeyPair()]);
    const aad = fieldAssociatedData(CONNECTION_A, "password");
    const envelope = await seal(utf8.encode("secret"), group.publicKey, aad);

    await expect(open(envelope, other.privateKey, aad)).rejects.toBeInstanceOf(
      VaultDecryptionError,
    );
  });

  it("fails when the caller supplies a wrong public half for the salt", async () => {
    // The accelerator argument is trusted, not verified — verifying it would
    // cost the derivation it exists to skip — so a mismatch is a tag failure.
    const [group, other] = await Promise.all([generateX25519KeyPair(), generateX25519KeyPair()]);
    const aad = fieldAssociatedData(CONNECTION_A, "password");
    const envelope = await seal(utf8.encode("secret"), group.publicKey, aad);

    await expect(open(envelope, group.privateKey, aad, other.publicKey)).rejects.toBeInstanceOf(
      VaultDecryptionError,
    );
  });

  it.each([
    ["ephemeral public key", 0],
    ["nonce", EPHEMERAL_PUBLIC_KEY_BYTES],
    ["ciphertext", EPHEMERAL_PUBLIC_KEY_BYTES + NONCE_BYTES],
    ["tag", ENVELOPE_OVERHEAD_BYTES + 7],
  ])("fails on a single flipped bit in the %s", async (_name, index) => {
    const group = await generateX25519KeyPair();
    const aad = fieldAssociatedData(CONNECTION_A, "password");
    const envelope = await seal(utf8.encode("eight-byte payload"), group.publicKey, aad);
    const payload = base64Decode(envelope.slice(SEAL_ALGORITHM.length + 1));

    const byte = payload[index];
    expect(byte).toBeDefined();
    payload[index] = (byte ?? 0) ^ 0x01;

    await expect(open(payload, group.privateKey, aad)).rejects.toBeInstanceOf(VaultDecryptionError);
  });

  it("reports one indistinguishable error and no cause for every failure", async () => {
    const group = await generateX25519KeyPair();
    const aad = fieldAssociatedData(CONNECTION_A, "password");
    const envelope = await seal(utf8.encode("secret"), group.publicKey, aad);

    const error = await open(envelope, group.privateKey, new Uint8Array(0)).catch(
      (thrown: unknown) => thrown,
    );
    expect(error).toBeInstanceOf(VaultDecryptionError);
    expect(error).toBeInstanceOf(VaultError);
    expect((error as VaultDecryptionError).message).toBe("decryption failed");
    expect((error as VaultDecryptionError).cause).toBeUndefined();
  });

  it("rejects a private key of the wrong length before touching the envelope", async () => {
    const group = await generateX25519KeyPair();
    const aad = fieldAssociatedData(CONNECTION_A, "password");
    const envelope = await seal(utf8.encode("secret"), group.publicKey, aad);

    await expect(open(envelope, unchecked<PrivateKey>(new Uint8Array(16)), aad)).rejects.toThrow(
      /private key must be 32 raw bytes, received 16/,
    );
  });

  it("rejects a supplied public key of the wrong length", async () => {
    const group = await generateX25519KeyPair();
    const aad = fieldAssociatedData(CONNECTION_A, "password");
    const envelope = await seal(utf8.encode("secret"), group.publicKey, aad);

    await expect(
      open(envelope, group.privateKey, aad, unchecked<PublicKey>(new Uint8Array(33))),
    ).rejects.toThrow(/public key must be 32 raw bytes, received 33/);
  });
});

describe("seal input validation", () => {
  it("rejects a recipient public key that is not 32 bytes", async () => {
    const wrong = unchecked<PublicKey>(new Uint8Array(31));
    await expect(seal(new Uint8Array(1), wrong, new Uint8Array(0))).rejects.toThrow(
      /public key must be 32 raw bytes, received 31/,
    );
    await expect(seal(new Uint8Array(1), wrong, new Uint8Array(0))).rejects.toBeInstanceOf(
      VaultError,
    );
  });
});

describe("parseEnvelope", () => {
  it("splits a well-formed envelope into views over one payload", async () => {
    const group = await generateX25519KeyPair();
    const envelope = await seal(utf8.encode("abc"), group.publicKey, new Uint8Array(0));
    const parts = parseEnvelope(envelope);

    expect(parts.algorithm).toBe(SEAL_ALGORITHM);
    expect(parts.ephemeralPublicKey.buffer).toBe(parts.nonce.buffer);
    expect(parts.nonce.buffer).toBe(parts.ciphertextAndTag.buffer);
    expect(parts.ciphertextAndTag).toHaveLength(3 + TAG_BYTES);
  });

  it("rejects a string with no separator", () => {
    expect(() => parseEnvelope("no-separator-here")).toThrow(EnvelopeFormatError);
    expect(() => parseEnvelope("no-separator-here")).toThrow(/"<alg>:<base64>"/);
  });

  it("rejects an unknown algorithm tag", () => {
    expect(() => parseEnvelope(`rsa-oaep:${base64Encode(fakePayload())}`)).toThrow(
      /unsupported envelope algorithm "rsa-oaep"/,
    );
  });

  it("rejects an empty algorithm tag", () => {
    expect(() => parseEnvelope(`:${base64Encode(fakePayload())}`)).toThrow(
      /unsupported envelope algorithm ""/,
    );
  });

  it("truncates a hostile algorithm tag in the message", () => {
    const tag = "z".repeat(500);
    const thrown = (() => {
      try {
        parseEnvelope(`${tag}:AAAA`);
        return undefined;
      } catch (error: unknown) {
        return error;
      }
    })();
    expect(thrown).toBeInstanceOf(EnvelopeFormatError);
    expect((thrown as EnvelopeFormatError).message).toBe(
      `unsupported envelope algorithm "${"z".repeat(32)}"`,
    );
  });

  it.each([
    ["a non-alphabet character", "AAA!"],
    ["base64url instead of base64", "AA-_"],
    ["a length that is not a multiple of four", "AAAAA"],
    ["padding in the middle", "AA==AAAA"],
    ["whitespace", "AAAA AAAA"],
  ])("rejects %s", (_name, encoded) => {
    expect(() => parseEnvelope(`${SEAL_ALGORITHM}:${encoded}`)).toThrow(
      /payload is not standard base64/,
    );
  });

  it("rejects non-zero base64 padding bits as a format error, not a RangeError", () => {
    // "AB==" is shape-legal base64 whose final character carries bits the
    // padding says are not there. The decoder throws a RangeError; nothing
    // outside this module's taxonomy may escape.
    const thrown = (() => {
      try {
        parseEnvelope(`${SEAL_ALGORITHM}:AB==`);
        return undefined;
      } catch (error: unknown) {
        return error;
      }
    })();
    expect(thrown).toBeInstanceOf(EnvelopeFormatError);
    expect(thrown).not.toBeInstanceOf(RangeError);
    expect((thrown as EnvelopeFormatError).message).toBe("envelope payload is not standard base64");
  });

  it("rejects non-zero padding bits on a full-length payload too", () => {
    // 61 bytes -> 84 characters ending in "==", so the same defect survives a
    // payload that would otherwise pass the length check.
    const encoded = base64Encode(fakePayload(1));
    const corrupted = `${encoded.slice(0, encoded.length - 3)}B==`;
    expect(() => parseEnvelope(`${SEAL_ALGORITHM}:${corrupted}`)).toThrow(EnvelopeFormatError);
    expect(() => parseEnvelope(`${SEAL_ALGORITHM}:${corrupted}`)).toThrow(
      /payload is not standard base64/,
    );
  });

  it("rejects a valid base64 payload below the overhead", () => {
    const short = base64Encode(fakePayload().subarray(0, ENVELOPE_OVERHEAD_BYTES - 1));
    expect(() => parseEnvelope(`${SEAL_ALGORITHM}:${short}`)).toThrow(
      /is 59 bytes, below the 60-byte overhead/,
    );
  });

  it("accepts an empty payload only to report it as too short", () => {
    expect(() => parseEnvelope(`${SEAL_ALGORITHM}:`)).toThrow(/is 0 bytes, below the 60-byte/);
  });

  it("splits on the first colon, so a colon inside the tag is part of the tag", () => {
    expect(() => parseEnvelope("x25519:hkdf-aesgcm:AAAA")).toThrow(
      /unsupported envelope algorithm "x25519"/,
    );
  });
});

describe("parseEnvelopeBytes", () => {
  it("accepts exactly the overhead, which is an empty plaintext", () => {
    const parts = parseEnvelopeBytes(fakePayload());
    expect(parts.ciphertextAndTag).toHaveLength(TAG_BYTES);
  });

  it("rejects one byte below the overhead", () => {
    expect(() => parseEnvelopeBytes(new Uint8Array(ENVELOPE_OVERHEAD_BYTES - 1))).toThrow(
      EnvelopeFormatError,
    );
  });

  it("returns views, not copies", () => {
    const payload = fakePayload(4);
    const parts = parseEnvelopeBytes(payload);
    expect(parts.nonce.buffer).toBe(payload.buffer);
    expect(parts.ephemeralPublicKey.byteOffset).toBe(payload.byteOffset);
  });
});

describe("formatEnvelope", () => {
  it("round-trips a payload through the display form", () => {
    const payload = fakePayload(9);
    const parts = parseEnvelope(formatEnvelope(payload));
    expect(parts.ephemeralPublicKey).toEqual(payload.subarray(0, EPHEMERAL_PUBLIC_KEY_BYTES));
    expect(parts.ciphertextAndTag).toEqual(
      payload.subarray(EPHEMERAL_PUBLIC_KEY_BYTES + NONCE_BYTES),
    );
  });

  it("rejects a payload below the overhead", () => {
    expect(() => formatEnvelope(new Uint8Array(59))).toThrow(EnvelopeFormatError);
    expect(() => formatEnvelope(new Uint8Array(0))).toThrow(/is 0 bytes, below the 60-byte/);
  });
});

describe("open contains the whole derive path in the failure taxonomy", () => {
  /**
   * An attacker controls the ephemeral half carried in an envelope. A low-order
   * or otherwise invalid X25519 point makes the ephemeral import or the shared-
   * secret derivation throw a raw `OperationError` DOMException — which, before
   * the fix, escaped `open` as an unhandled rejection rather than the uniform
   * `VaultDecryptionError`. On the relay's refusal path that is a distinguishable
   * outcome: a different status and a different timing envelope, i.e. an oracle.
   */
  const LOW_ORDER_POINTS: readonly Uint8Array[] = [
    new Uint8Array(32), // all zero — the identity/small-order point
    Uint8Array.from({ length: 32 }, (_v, i) => (i === 0 ? 1 : 0)), // order-1 point
    Uint8Array.from({ length: 32 }, (_v, i) => (i === 31 ? 0x80 : 0)), // high-bit-only
  ];

  it.each(LOW_ORDER_POINTS.map((point, i) => [i, point] as const))(
    "maps a bad ephemeral point (#%i) to VaultDecryptionError, not a DOMException",
    async (_i, point) => {
      const pair = await generateX25519KeyPair();
      const aad = fieldAssociatedData("conn", "field");
      const genuine = await seal(new Uint8Array([1, 2, 3]), pair.publicKey, aad);

      // Splice the attacker's point over the genuine ephemeral half.
      const payload = base64Decode(genuine.slice(SEAL_ALGORITHM.length + 1));
      payload.set(point, 0);
      const forged = `${SEAL_ALGORITHM}:${base64Encode(payload)}`;

      await expect(open(forged, pair.privateKey, aad)).rejects.toBeInstanceOf(VaultDecryptionError);
    },
  );

  it("still reports a malformed recipient private half as a caller bug", async () => {
    const pair = await generateX25519KeyPair();
    const aad = fieldAssociatedData("conn", "field");
    const genuine = await seal(new Uint8Array([1, 2, 3]), pair.publicKey, aad);

    // A wrong-sized private half is the caller's mistake, not an authentication
    // failure, and must stay loud rather than be masked as a decryption error.
    const shortKey = unchecked<PrivateKey>(new Uint8Array(31));
    await expect(open(genuine, shortKey, aad)).rejects.toBeInstanceOf(VaultError);
    await expect(open(genuine, shortKey, aad)).rejects.not.toBeInstanceOf(VaultDecryptionError);
  });
});
