/**
 * Scaffold baseline.
 *
 * Every module in this package is currently a stub whose body is
 * `throw new Error('not implemented')`. This file asserts exactly that, which
 * does two useful things at the scaffold stage:
 *
 *   1. it proves every declared signature is reachable and compiles, so the
 *      modules being written in parallel are building against a real contract;
 *   2. it keeps the 100% coverage gate honest instead of vacuous — the gate is
 *      on from the first commit, not switched on later once it is inconvenient.
 *
 * DELETE THE STUB ASSERTIONS FOR A MODULE AS YOU IMPLEMENT IT, and replace them
 * with real tests. This file is scaffolding, not a specification.
 */

import { describe, expect, it } from "vitest";
import * as apiKey from "./api-key.js";
import * as layout from "./bundle/layout.js";
import * as reader from "./bundle/reader.js";
import * as writer from "./bundle/writer.js";
import * as encoding from "./encoding.js";
import * as envelope from "./envelope.js";
import * as group from "./group.js";
import * as types from "./types.js";

const NOT_IMPLEMENTED = /not implemented/;

const bytes = (length: number): Uint8Array => new Uint8Array(length);

/** Every stub, as a zero-argument thunk that calls it with plausible arguments. */
const stubs: ReadonlyArray<readonly [string, () => unknown]> = [
  ["encoding.base62Encode", () => encoding.base62Encode(bytes(32), 43)],
  ["encoding.base62Decode", () => encoding.base62Decode("0", 32)],
  ["encoding.crc32", () => encoding.crc32(bytes(4))],
  ["encoding.hexEncode", () => encoding.hexEncode(bytes(4))],
  ["encoding.hexDecode", () => encoding.hexDecode("00")],
  ["encoding.timingSafeEqual", () => encoding.timingSafeEqual(bytes(4), bytes(4))],
  ["encoding.utf8Encode", () => encoding.utf8Encode("x")],
  ["encoding.utf8Decode", () => encoding.utf8Decode(bytes(1))],
  ["encoding.base64Encode", () => encoding.base64Encode(bytes(4))],
  ["encoding.base64Decode", () => encoding.base64Decode("AAAA")],

  ["api-key.generateApiKey", () => apiKey.generateApiKey("live")],
  ["api-key.formatApiKey", () => apiKey.formatApiKey(bytes(32), "test")],
  ["api-key.parseApiKey", () => apiKey.parseApiKey("sk0_live_x_y")],
  ["api-key.deriveKeyId", () => apiKey.deriveKeyId(bytes(32), "tenant")],
  ["api-key.deriveKeyIdHex", () => apiKey.deriveKeyIdHex(bytes(32), "tenant")],
  ["api-key.deriveWrapKey", () => apiKey.deriveWrapKey(bytes(32), "tenant")],

  ["envelope.generateX25519KeyPair", () => envelope.generateX25519KeyPair()],
  ["envelope.derivePublicKey", () => envelope.derivePublicKey(bytes(32))],
  ["envelope.fieldAssociatedData", () => envelope.fieldAssociatedData("conn", "api_key")],
  ["envelope.bucketAssociatedData", () => envelope.bucketAssociatedData("group", "keyid")],
  ["envelope.seal", () => envelope.seal(bytes(8), bytes(32), bytes(16))],
  ["envelope.open", () => envelope.open("x25519-hkdf-aesgcm:AA", bytes(32), bytes(16))],
  ["envelope.parseEnvelope", () => envelope.parseEnvelope("x25519-hkdf-aesgcm:AA")],
  ["envelope.parseEnvelopeBytes", () => envelope.parseEnvelopeBytes(bytes(60))],
  ["envelope.formatEnvelope", () => envelope.formatEnvelope(bytes(60))],

  ["group.generateGroup", () => group.generateGroup()],
  ["group.wrap", () => group.wrap(bytes(32), bytes(32), "tenant", "group")],
  [
    "group.unwrap",
    () => group.unwrap({ keyId: "00", wrapped: bytes(60) }, bytes(32), "tenant", "group"),
  ],
  [
    "group.findBucketEntry",
    () =>
      group.findBucketEntry(
        { groupId: "g", publicKey: bytes(32), bucket: [] },
        bytes(32),
        "tenant",
      ),
  ],
  ["group.buildBucket", () => group.buildBucket(bytes(32), [bytes(32)], "tenant", "group")],

  ["layout.indexSlotCount", () => layout.indexSlotCount(1)],
  ["layout.bucketOf", () => layout.bucketOf(0, 8)],
  ["layout.uuidLow32", () => layout.uuidLow32(bytes(16))],
  ["layout.uuidHigh32", () => layout.uuidHigh32(bytes(16))],
  ["layout.indexSlotOffset", () => layout.indexSlotOffset(0, 0)],
  ["layout.sectionEntryOffset", () => layout.sectionEntryOffset(0)],
  ["layout.connRecordOffset", () => layout.connRecordOffset(0, 0)],
  ["layout.fieldDescriptorOffset", () => layout.fieldDescriptorOffset(0, 0)],
  ["layout.grupRecordOffset", () => layout.grupRecordOffset(0, 0)],
  ["layout.bucketEntryOffset", () => layout.bucketEntryOffset(0, 0)],
  ["layout.filtEntryOffset", () => layout.filtEntryOffset(0, 0)],
  ["layout.parseConnectionId", () => layout.parseConnectionId("abcd_uuid")],
  ["layout.sectionKindName", () => layout.sectionKindName(layout.SECTION_KIND.INDX)],

  ["writer.writeBundle", () => writer.writeBundle(emptyInput())],
  ["writer.measureBundle", () => writer.measureBundle(emptyInput())],
  ["writer.computeChecksum", () => writer.computeChecksum(bytes(64))],
  ["writer.writeChecksum", () => writer.writeChecksum(bytes(64), bytes(28))],
  ["writer.writeBundleWithChecksum", () => writer.writeBundleWithChecksum(emptyInput())],

  ["reader.readBundle", () => reader.readBundle(bytes(64))],
  ["reader.writeBackPlaintext", () => reader.writeBackPlaintext(bytes(64), descriptor(), bytes(1))],
  ["reader.readFieldDescriptor", () => reader.readFieldDescriptor(bytes(64), 0)],
  ["reader.zeroTail", () => reader.zeroTail(bytes(64), 0)],
  ["reader.decoyUnwrap", () => reader.decoyUnwrap()],
];

function emptyInput(): types.BundleInput {
  return {
    header: { version: 1, generation: 0n, shard: "aaaa", builtAt: 0n },
    groups: [],
    connections: [],
    filters: [],
  };
}

function descriptor(): types.FieldDescriptor {
  return {
    descriptorOffset: 0,
    strsOffset: 0,
    sealedLen: 61,
    plainLen: 0,
    state: types.FieldState.Sealed,
  };
}

describe("scaffold", () => {
  it.each(stubs)("%s is declared and not yet implemented", (_name, call) => {
    expect(call).toThrow(NOT_IMPLEMENTED);
  });
});

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
