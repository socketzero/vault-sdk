/**
 * End-to-end integration.
 *
 * Every other test file proves one module against the catalog. This one proves
 * the modules against *each other*, which is the failure the catalog calls the
 * quietest in the system: a bundle one party writes and another cannot read.
 *
 * Nothing here is a fixture or a stub. Real X25519 groups, real API keys, real
 * HKDF derivations, a real bundle emitted by `writeBundle` and read back by
 * `readBundle` — the two are independent implementations of one document, and
 * until this file existed nothing made them meet.
 */

import { describe, expect, it, vi } from "vitest";
import { generateApiKey, parseApiKey } from "./api-key.js";
import { FIELD_DESCRIPTOR_OFFSET, HEADER_OFFSET, parseUuid } from "./bundle/layout.js";
import { readBundle } from "./bundle/reader.js";
import {
  computeChecksum,
  writeBundle,
  writeBundleWithChecksum,
  writeChecksum,
} from "./bundle/writer.js";
import { utf8Decode, utf8Encode } from "./encoding.js";
import {
  bucketAssociatedData,
  fieldAssociatedData,
  formatEnvelope,
  open,
  seal,
} from "./envelope.js";
import { buildBucket, findBucketEntry, generateGroup, rotateGroup, unwrap } from "./group.js";
import {
  type ApiKeyBytes,
  type BucketEntry,
  BundleFormatError,
  type BundleInput,
  type ConnectionInput,
  FieldState,
  type KeyGroup,
  type PrivateKey,
  type PublicKey,
  type SealedEnvelope,
  type SealedField,
  VaultDecryptionError,
} from "./types.js";

const TENANT = "tnt_01j9x4m2q8";
const OTHER_TENANT = "tnt_01j9x4m2q9";

/** `high32` then eight zero bytes then `low32`, formatted 8-4-4-4-12. */
function makeUuid(high32: number, low32: number): string {
  const hex = `${(high32 >>> 0).toString(16).padStart(8, "0")}0000000000000000${(low32 >>> 0)
    .toString(16)
    .padStart(8, "0")}`;
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

const GROUP_ONE = makeUuid(0xa1a1a1a1, 0x00000001);
const GROUP_TWO = makeUuid(0xb2b2b2b2, 0x00000002);

// ---------------------------------------------------------------------------
// The bucket: one group, two API keys, both of which open it
// ---------------------------------------------------------------------------

describe("a key group wrapped under two API keys", () => {
  it("gives each key its own entry and returns the identical private half to both", async () => {
    const group = await generateGroup();
    const keyA = generateApiKey("live");
    const keyB = generateApiKey("test");

    const bucket = await buildBucket(group.privateKey, [keyA.bytes, keyB.bytes], TENANT, GROUP_ONE);

    expect(bucket).toHaveLength(2);
    const [entryA, entryB] = bucket;
    if (entryA === undefined || entryB === undefined) {
      throw new Error("buildBucket returned fewer entries than keys");
    }

    // Two info strings over one secret: the id stored in the clear is
    // independent of the key that opens the group, and independent per key.
    expect(entryA.keyId).not.toBe(entryB.keyId);
    expect(entryA.keyId).toMatch(/^[0-9a-f]{32}$/);
    // Distinct nonces, so two wraps of one private half are not one ciphertext.
    expect(entryA.wrapped).not.toEqual(entryB.wrapped);

    await expect(unwrap(entryA, keyA.bytes, TENANT, GROUP_ONE)).resolves.toEqual(group.privateKey);
    await expect(unwrap(entryB, keyB.bytes, TENANT, GROUP_ONE)).resolves.toEqual(group.privateKey);
  });

  it("finds each key its own entry in the bucket", async () => {
    const group = await generateGroup();
    const keyA = generateApiKey("live");
    const keyB = generateApiKey("live");
    const stranger = generateApiKey("live");
    const bucket = await buildBucket(group.privateKey, [keyA.bytes, keyB.bytes], TENANT, GROUP_ONE);
    const keyGroup: KeyGroup = {
      groupId: GROUP_ONE,
      publicKey: group.publicKey,
      generation: 0,
      bucket,
    };

    const foundA = await findBucketEntry(keyGroup, keyA.bytes, TENANT);
    const foundB = await findBucketEntry(keyGroup, keyB.bytes, TENANT);
    expect(foundA?.keyId).toBe(bucket[0]?.keyId);
    expect(foundB?.keyId).toBe(bucket[1]?.keyId);
    expect(await findBucketEntry(keyGroup, stranger.bytes, TENANT)).toBeUndefined();
  });

  it("refuses the other key's entry, another group and another tenant alike", async () => {
    const group = await generateGroup();
    const keyA = generateApiKey("live");
    const keyB = generateApiKey("live");
    const bucket = await buildBucket(group.privateKey, [keyA.bytes, keyB.bytes], TENANT, GROUP_ONE);
    const [entryA] = bucket;
    if (entryA === undefined) {
      throw new Error("buildBucket returned no entries");
    }

    await expect(unwrap(entryA, keyB.bytes, TENANT, GROUP_ONE)).rejects.toBeInstanceOf(
      VaultDecryptionError,
    );
    await expect(unwrap(entryA, keyA.bytes, TENANT, GROUP_TWO)).rejects.toBeInstanceOf(
      VaultDecryptionError,
    );
    await expect(unwrap(entryA, keyA.bytes, OTHER_TENANT, GROUP_ONE)).rejects.toBeInstanceOf(
      VaultDecryptionError,
    );
  });

  it("wraps under the key recovered from its display string, not the string itself", async () => {
    const group = await generateGroup();
    const key = generateApiKey("live");
    const parsed = parseApiKey(key.display);
    if (!parsed.ok) {
      throw new Error(`a generated key did not parse: ${parsed.reason}`);
    }
    expect(parsed.bytes).toEqual(key.bytes);

    const bucket = await buildBucket(group.privateKey, [key.bytes], TENANT, GROUP_ONE);
    const [entry] = bucket;
    if (entry === undefined) {
      throw new Error("buildBucket returned no entries");
    }
    // The derivation input is the raw bytes; a key that survived a paste opens
    // the same entry the generator wrapped.
    await expect(unwrap(entry, parsed.bytes, TENANT, GROUP_ONE)).resolves.toEqual(group.privateKey);
  });
});

// ---------------------------------------------------------------------------
// The envelope: sealed with a public half only, opened with the unwrapped one
// ---------------------------------------------------------------------------

describe("a credential sealed to a group and opened with the unwrapped private half", () => {
  const CONNECTION = makeUuid(0x11111111, 0x00000010);
  const SECRET = "hunter2-éè-🔑";

  it("round-trips through wrap, unwrap, seal and open", async () => {
    const group = await generateGroup();
    const key = generateApiKey("live");
    const bucket = await buildBucket(group.privateKey, [key.bytes], TENANT, GROUP_ONE);
    const [entry] = bucket;
    if (entry === undefined) {
      throw new Error("buildBucket returned no entries");
    }

    // The sealer holds only the public half. Nothing in this block has a secret.
    const aad = fieldAssociatedData(parseUuid(CONNECTION), "password");
    const envelope = await seal(utf8Encode(SECRET), group.publicKey, aad);
    expect(envelope.startsWith("x25519-hkdf-aesgcm:")).toBe(true);

    // The opener presents an API key and gets the private half from the bucket.
    const privateKey = await unwrap(entry, key.bytes, TENANT, GROUP_ONE);
    const opened = await open(envelope, privateKey, aad, group.publicKey);
    expect(utf8Decode(opened)).toBe(SECRET);

    // ...and opens identically without being handed the public half, which it
    // then recovers from the private one.
    expect(utf8Decode(await open(envelope, privateKey, aad))).toBe(SECRET);
  });

  it("keeps the envelope exactly 60 bytes larger than the secret", async () => {
    const group = await generateGroup();
    const aad = fieldAssociatedData(parseUuid(CONNECTION), "password");
    for (const length of [0, 1, 15, 16, 17, 4096]) {
      const envelope = await seal(new Uint8Array(length), group.publicKey, aad);
      const payload = envelope.slice(envelope.indexOf(":") + 1);
      // Recover the payload length from the base64 without decoding it: this is
      // the property the bundle's in-place write-back depends on.
      const decoded = await open(envelope, group.privateKey, aad, group.publicKey);
      expect(decoded.byteLength).toBe(length);
      expect(Buffer.from(payload, "base64").byteLength).toBe(length + 60);
    }
  });

  it("refuses a field moved to another name, another connection or another group", async () => {
    const group = await generateGroup();
    const other = await generateGroup();
    const aad = fieldAssociatedData(parseUuid(CONNECTION), "password");
    const envelope = await seal(utf8Encode(SECRET), group.publicKey, aad);

    const moved = fieldAssociatedData(parseUuid(CONNECTION), "api_key");
    await expect(open(envelope, group.privateKey, moved, group.publicKey)).rejects.toBeInstanceOf(
      VaultDecryptionError,
    );

    const elsewhere = fieldAssociatedData(parseUuid(makeUuid(0x22222222, 0x11)), "password");
    await expect(
      open(envelope, group.privateKey, elsewhere, group.publicKey),
    ).rejects.toBeInstanceOf(VaultDecryptionError);

    await expect(open(envelope, other.privateKey, aad, other.publicKey)).rejects.toBeInstanceOf(
      VaultDecryptionError,
    );
  });
});

// ---------------------------------------------------------------------------
// The bundle: written by the writer, read in place by the reader
// ---------------------------------------------------------------------------

interface Fixture {
  readonly input: BundleInput;
  readonly groups: ReadonlyArray<{
    readonly groupId: string;
    readonly publicKey: PublicKey;
    readonly privateKey: PrivateKey;
    readonly apiKey: ApiKeyBytes;
    readonly entry: BucketEntry;
  }>;
  readonly secrets: ReadonlyMap<string, string>;
}

const CONNECTIONS = [
  { uuid: makeUuid(0x0a0a0a0a, 0x00000101), group: 0, target: "https://api.stripe.com" },
  { uuid: makeUuid(0x0b0b0b0b, 0x00000102), group: 0, target: "https://api.github.com" },
  { uuid: makeUuid(0x0c0c0c0c, 0x00000103), group: 1, target: "https://slack.com/api" },
  // Shares its low 32 bits with the first connection, so the index has to
  // resolve a genuine bucket collision by probing.
  { uuid: makeUuid(0x0d0d0d0d, 0x00000101), group: 1, target: "https://api.twilio.com" },
] as const;

/** Build a real bundle: real groups, real buckets, real envelopes. */
async function buildFixture(): Promise<Fixture> {
  const groupIds = [GROUP_ONE, GROUP_TWO];
  const groups = await Promise.all(
    groupIds.map(async (groupId) => {
      const pair = await generateGroup();
      const apiKey = generateApiKey("live");
      const bucket = await buildBucket(pair.privateKey, [apiKey.bytes], TENANT, groupId);
      const [entry] = bucket;
      if (entry === undefined) {
        throw new Error("buildBucket returned no entries");
      }
      return { groupId, ...pair, apiKey: apiKey.bytes, entry, bucket };
    }),
  );

  const secrets = new Map<string, string>();
  const connections: ConnectionInput[] = [];
  for (const spec of CONNECTIONS) {
    const connectionId = spec.uuid;
    const group = groups[spec.group];
    if (group === undefined) {
      throw new Error("fixture names a group that was not built");
    }
    const sealed: Record<string, SealedEnvelope> = {};
    for (const fieldName of ["password", "api_key"]) {
      const secret = `${fieldName}@${spec.target}`;
      secrets.set(`${connectionId}/${fieldName}`, secret);
      sealed[fieldName] = await seal(
        utf8Encode(secret),
        group.publicKey,
        fieldAssociatedData(parseUuid(connectionId), fieldName),
      );
    }
    connections.push({
      connectionId,
      groupId: group.groupId,
      target: spec.target,
      visible: { region: "eu", timeoutMs: 2500, streaming: true },
      sealed,
      filters: [0],
      expiresAt: null,
    });
  }

  return {
    input: {
      header: { version: 1, generation: 42n, builtAt: 1_725_000_000_000n },
      groups: groups.map((group) => ({
        groupId: group.groupId,
        publicKey: group.publicKey,
        generation: 0,
        bucket: group.bucket,
      })),
      connections,
      filters: [{ kind: 1, args: utf8Encode("rate-limit:100") }],
    },
    groups,
    secrets,
  };
}

describe("a bundle written by the writer and read in place by the reader", () => {
  it("verifies its own checksum and reports what the writer put in the header", async () => {
    const fixture = await buildFixture();
    const bytes = await writeBundleWithChecksum(fixture.input);
    const bundle = readBundle(bytes);

    expect(bundle.header.magic).toBe("S0BUNDLE");
    expect(bundle.header.generation).toBe(42n);
    expect(bundle.connectionCount).toBe(CONNECTIONS.length);
    expect(bundle.groupCount).toBe(2);
    await expect(bundle.verifyChecksum()).resolves.toBe(true);
  });

  it("finds every connection by its id, including the one that collides", async () => {
    const fixture = await buildFixture();
    const bundle = readBundle(writeBundle(fixture.input));

    for (const spec of CONNECTIONS) {
      const record = bundle.lookup(spec.uuid);
      expect(record?.target()).toBe(spec.target);
      expect(record?.groupIndex).toBe(spec.group);
      expect(record?.visible("region")).toBe("eu");
      expect(record?.visible("timeoutMs")).toBe(2500);
      expect(record?.visible("streaming")).toBe(true);
      expect(record?.expiresAt()).toBeNull();
      expect([...(record?.filterIndices() ?? [])]).toEqual([0]);
      expect(record?.fieldNames()).toEqual(["password", "api_key"]);
    }

    // The two colliding ids resolved to different records, not to one another.
    const first = bundle.lookup(CONNECTIONS[0].uuid);
    const collider = bundle.lookup(CONNECTIONS[3].uuid);
    expect(first?.recordOffset).not.toBe(collider?.recordOffset);
  });

  it("hands back the filter arguments and the groups by id, exactly as written", async () => {
    const fixture = await buildFixture();
    const bundle = readBundle(writeBundle(fixture.input));

    const filter = bundle.filter(0);
    expect(filter?.kind).toBe(1);
    expect(utf8Decode(filter?.args() ?? new Uint8Array())).toBe("rate-limit:100");

    for (const [index, group] of fixture.groups.entries()) {
      const byId = bundle.groupById(group.groupId);
      expect(byId?.groupIndex).toBe(index);
      expect(byId?.publicKey()).toEqual(group.publicKey);
      expect(byId?.bucketSize).toBe(1);
      expect(byId?.bucketEntry(0)?.keyIdHex()).toBe(group.entry.keyId);
      expect(byId?.bucketEntry(0)?.wrapped()).toEqual(group.entry.wrapped);
    }
  });

  it("round-trips an expiry the shard reads to see its renewal margin", async () => {
    const fixture = await buildFixture();
    const [first, ...rest] = fixture.input.connections;
    if (first === undefined) {
      throw new Error("the fixture has no connections");
    }
    const bundle = readBundle(
      writeBundle({
        ...fixture.input,
        connections: [{ ...first, expiresAt: 1_800_000_000_123 }, ...rest],
      }),
    );
    expect(bundle.lookup(first.connectionId)?.expiresAt()).toBe(1_800_000_000_123);
  });

  it("opens a sealed field with a key presented at read time, group unwrapped from the bundle", async () => {
    const fixture = await buildFixture();
    const bundle = readBundle(writeBundle(fixture.input));

    for (const spec of CONNECTIONS) {
      const connectionId = spec.uuid;
      const record = bundle.lookup(connectionId);
      if (record === undefined) {
        throw new Error(`${connectionId} was not in the bundle`);
      }
      const presented = fixture.groups[spec.group];
      if (presented === undefined) {
        throw new Error("fixture names a group that was not built");
      }

      // Everything the opener needs comes out of the buffer: the group's public
      // half, its bucket entry keyed by the id this API key derives, and the
      // field's own bytes.
      const groupView = bundle.group(record.groupIndex);
      expect(groupView?.groupId()).toBe(presented.groupId);
      const entryView = groupView?.findBucketEntry(presented.entry.keyId);
      if (groupView === undefined || entryView === undefined) {
        throw new Error("the presented key's entry was not in the bundle's bucket");
      }
      const privateKey = await unwrap(
        { keyId: entryView.keyIdHex(), wrapped: entryView.wrapped() },
        presented.apiKey,
        TENANT,
        presented.groupId,
      );
      expect(privateKey).toEqual(presented.privateKey);
      expect(groupView.publicKey()).toEqual(presented.publicKey);

      for (const fieldName of ["password", "api_key"]) {
        const descriptor = record.field(fieldName);
        if (descriptor === undefined) {
          throw new Error(`${connectionId} has no field ${fieldName}`);
        }
        expect(descriptor.state).toBe(FieldState.Sealed);
        const opened = await open(
          record.fieldBytes(descriptor),
          privateKey,
          fieldAssociatedData(parseUuid(connectionId), fieldName),
          groupView.publicKey(),
        );
        expect(utf8Decode(opened)).toBe(fixture.secrets.get(`${connectionId}/${fieldName}`));
        // The slot the ciphertext occupied is exactly 60 bytes wider than the
        // secret, which is why the write-back below cannot fail to fit.
        expect(descriptor.sealedLen - opened.byteLength).toBe(60);
      }
    }
  });

  it("re-forms the stored payload into the envelope string the writer was given", async () => {
    const fixture = await buildFixture();
    const bundle = readBundle(writeBundle(fixture.input));
    const spec = CONNECTIONS[0];
    const connectionId = spec.uuid;
    const record = bundle.lookup(connectionId);
    const written = fixture.input.connections[0];
    if (record === undefined || written === undefined) {
      throw new Error("the fixture's first connection is not in the bundle");
    }

    // The algorithm prefix is not stored; a bundle speaks one algorithm. What
    // comes back out has to be byte-identical to what went in, for every field.
    for (const [fieldName, envelope] of Object.entries(written.sealed)) {
      const descriptor = record.field(fieldName);
      if (descriptor === undefined) {
        throw new Error(`${connectionId} lost its ${fieldName} field`);
      }
      expect(formatEnvelope(record.fieldBytes(descriptor))).toBe(envelope);
    }
  });

  it("returns the plaintext from the buffer on the second read, with no cryptography at all", async () => {
    const fixture = await buildFixture();
    const buffer = writeBundle(fixture.input);
    const bundle = readBundle(buffer);
    const spec = CONNECTIONS[0];
    const connectionId = spec.uuid;
    const expected = fixture.secrets.get(`${connectionId}/password`);

    const record = bundle.lookup(connectionId);
    const sealedDescriptor = record?.field("password");
    const group = fixture.groups[spec.group];
    if (record === undefined || sealedDescriptor === undefined || group === undefined) {
      throw new Error("the fixture's first connection is not readable");
    }

    const opened = await open(
      record.fieldBytes(sealedDescriptor),
      group.privateKey,
      fieldAssociatedData(parseUuid(connectionId), "password"),
      group.publicKey,
    );

    // Write-back: bytes, then plain_len, then the flag — into the buffer the
    // read started from.
    const written = bundle.writeBack(sealedDescriptor, opened);
    expect(written.state).toBe(FieldState.Open);
    expect(written.plainLen).toBe(opened.byteLength);
    // The plaintext went into the slot its own ciphertext occupied.
    expect(written.strsOffset).toBe(sealedDescriptor.strsOffset);
    expect(buffer.subarray(written.strsOffset, written.strsOffset + written.plainLen)).toEqual(
      opened,
    );

    // A second reader, resolving the field from scratch, sees the live flag.
    const again = bundle.lookup(connectionId)?.field("password");
    expect(again?.state).toBe(FieldState.Open);
    expect(again?.plainLen).toBe(opened.byteLength);

    // ...and gets the secret back with no call into Web Crypto whatsoever.
    const subtle = vi.spyOn(globalThis.crypto.subtle, "decrypt");
    const deriveBits = vi.spyOn(globalThis.crypto.subtle, "deriveBits");
    const importKey = vi.spyOn(globalThis.crypto.subtle, "importKey");
    try {
      const second = bundle.lookup(connectionId);
      const live = second?.field("password");
      if (second === undefined || live === undefined) {
        throw new Error("the opened field disappeared");
      }
      expect(utf8Decode(second.fieldBytes(live))).toBe(expected);
      expect(subtle).not.toHaveBeenCalled();
      expect(deriveBits).not.toHaveBeenCalled();
      expect(importKey).not.toHaveBeenCalled();
    } finally {
      subtle.mockRestore();
      deriveBits.mockRestore();
      importKey.mockRestore();
    }
  });

  it("caches a group's private half in its own slot the same way a field is cached", async () => {
    const fixture = await buildFixture();
    const buffer = writeBundle(fixture.input);
    const bundle = readBundle(buffer);
    const group = fixture.groups[0];
    const groupView = bundle.group(0);
    if (group === undefined || groupView === undefined) {
      throw new Error("the fixture's first group is not readable");
    }

    const descriptor = groupView.privateKeyDescriptor();
    expect(descriptor.state).toBe(FieldState.Sealed);

    const entry = groupView.findBucketEntry(group.entry.keyId);
    if (entry === undefined) {
      throw new Error("the group's own key id is not in its bucket");
    }
    const privateKey = await unwrap(
      { keyId: entry.keyIdHex(), wrapped: entry.wrapped() },
      group.apiKey,
      TENANT,
      group.groupId,
    );

    const written = bundle.writeBack(descriptor, privateKey);
    expect(written.state).toBe(FieldState.Open);
    expect(written.plainLen).toBe(32);
    expect(buffer.subarray(written.strsOffset, written.strsOffset + 32)).toEqual(privateKey);
    // Re-read from the live descriptor, so the second isolate request skips the
    // unwrap entirely.
    expect(bundle.group(0)?.privateKeyDescriptor().state).toBe(FieldState.Open);
  });
});

// ---------------------------------------------------------------------------
// A miss is refused, and costs nothing
// ---------------------------------------------------------------------------

/**
 * Record every offset the reader touches, through both routes it has: the
 * shared `DataView` and the `subarray` views it hands out.
 */
function recordReads<T>(buffer: Uint8Array, body: () => T): { result: T; offsets: number[] } {
  const offsets: number[] = [];
  const getters = [
    "getUint8",
    "getUint16",
    "getUint32",
    "getBigUint64",
    "getFloat64",
  ] as const satisfies ReadonlyArray<keyof DataView>;

  const spies = getters.map((name) => {
    const original = DataView.prototype[name];
    return vi.spyOn(DataView.prototype, name).mockImplementation(function (
      this: DataView,
      ...args: [number, boolean?]
    ) {
      offsets.push(this.byteOffset + args[0]);
      return Reflect.apply(original, this, args);
    });
  });
  const originalSubarray = Uint8Array.prototype.subarray;
  const subarraySpy = vi.spyOn(Uint8Array.prototype, "subarray").mockImplementation(function (
    this: Uint8Array,
    ...args: [number?, number?]
  ) {
    if (this.buffer === buffer.buffer) {
      offsets.push(this.byteOffset + (args[0] ?? 0));
    }
    return Reflect.apply(originalSubarray, this, args);
  });

  try {
    return { result: body(), offsets };
  } finally {
    subarraySpy.mockRestore();
    for (const spy of spies) {
      spy.mockRestore();
    }
  }
}

describe("a lookup that misses", () => {
  it("is refused without reading the CONN section, while a hit does read it", async () => {
    const fixture = await buildFixture();
    const buffer = writeBundle(fixture.input);
    const bundle = readBundle(buffer);
    const conn = bundle.section("CONN");
    if (conn === undefined) {
      throw new Error("the bundle has no CONN section");
    }
    const inConn = (offset: number): boolean =>
      offset >= conn.offset && offset < conn.offset + conn.length;

    // Same bucket as the first connection — the low 32 bits are identical — so
    // the slot is occupied and only the fingerprint can refuse it. Anything
    // less deliberate would land on an empty slot and prove nothing.
    const absent = makeUuid(0xdeadbeef, 0x00000101);
    const miss = recordReads(buffer, () => bundle.lookup(absent));
    expect(miss.result).toBeUndefined();
    expect(miss.offsets.length).toBeGreaterThan(0);
    expect(miss.offsets.filter(inConn)).toEqual([]);

    // The positive control: without it the assertion above could pass simply by
    // never reading anything.
    const hit = recordReads(buffer, () => bundle.lookup(CONNECTIONS[0].uuid));
    expect(hit.result).toBeDefined();
    expect(hit.offsets.filter(inConn).length).toBeGreaterThan(0);
  });

  it("refuses an id belonging to another shard, and a malformed one", async () => {
    const fixture = await buildFixture();
    const bundle = readBundle(writeBundle(fixture.input));
    expect(bundle.lookup(`usea_${CONNECTIONS[0].uuid}`)).toBeUndefined();
    expect(bundle.lookup("not-a-connection-id")).toBeUndefined();
  });

  it("does not hand out a group, an entry or a field that is not there", async () => {
    const fixture = await buildFixture();
    const bundle = readBundle(writeBundle(fixture.input));
    expect(bundle.groupById(makeUuid(0xffffffff, 0xffffffff))).toBeUndefined();
    expect(bundle.group(0)?.findBucketEntry("0".repeat(32))).toBeUndefined();
    expect(bundle.lookup(CONNECTIONS[0].uuid)?.field("client_secret")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// A forged bundle: the checksum is unkeyed, so sealing has to be checked
// ---------------------------------------------------------------------------

/**
 * Re-stamp the header checksum so the forgery below is not caught by accident.
 *
 * This is the whole point of the two tests that use it: anyone who can write to
 * the store can also compute a valid checksum, because it is unkeyed. The
 * checksum detects truncation and corruption; it is not an authenticity
 * control, and `readBundle` may not lean on it for one.
 */
async function restamp(buffer: Uint8Array): Promise<Uint8Array> {
  writeChecksum(buffer, await computeChecksum(buffer));
  return buffer;
}

/** True when the header's stored checksum matches the bytes that follow it. */
async function checksumIsValid(buffer: Uint8Array): Promise<boolean> {
  const stored = buffer.subarray(HEADER_OFFSET.CHECKSUM, HEADER_OFFSET.CHECKSUM + 28);
  return utf8Decode(await computeChecksum(buffer)) === utf8Decode(stored);
}

describe("a bundle forged in the store", () => {
  it("refuses one whose field arrives already open, credential injection and all", async () => {
    const fixture = await buildFixture();
    const buffer = await writeBundleWithChecksum(fixture.input);
    const connectionId = CONNECTIONS[0].uuid;

    // Read the pristine bundle once, purely to learn where the slot is.
    const descriptor = readBundle(buffer).lookup(connectionId)?.field("api_key");
    if (descriptor === undefined) {
      throw new Error("the fixture's first connection has no api_key field");
    }

    // The attack, end to end: overwrite the arena slot with a credential of the
    // attacker's choosing, declare its length, flip the flag, re-stamp.
    const injected = utf8Encode("sk-live-attacker-controlled");
    buffer.set(injected, descriptor.strsOffset);
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    view.setUint32(
      descriptor.descriptorOffset + FIELD_DESCRIPTOR_OFFSET.PLAIN_LEN,
      injected.byteLength,
      true,
    );
    view.setUint8(descriptor.descriptorOffset + FIELD_DESCRIPTOR_OFFSET.STATE, FieldState.Open);
    await restamp(buffer);

    // The checksum is no obstacle whatsoever — it verifies over the forgery.
    await expect(checksumIsValid(buffer)).resolves.toBe(true);
    // Refused at load, before any view of it exists to be asked for the field.
    expect(() => readBundle(buffer)).toThrow(BundleFormatError);
    expect(() => readBundle(buffer)).toThrow(/arrives open/);
  });

  it("refuses one whose field claims more plaintext than its slot holds", async () => {
    const fixture = await buildFixture();
    const buffer = await writeBundleWithChecksum(fixture.input);
    const connectionId = CONNECTIONS[0].uuid;
    const descriptor = readBundle(buffer).lookup(connectionId)?.field("password");
    if (descriptor === undefined) {
      throw new Error("the fixture's first connection has no password field");
    }

    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    view.setUint32(
      descriptor.descriptorOffset + FIELD_DESCRIPTOR_OFFSET.PLAIN_LEN,
      descriptor.sealedLen + 1,
      true,
    );
    await restamp(buffer);

    await expect(checksumIsValid(buffer)).resolves.toBe(true);
    expect(() => readBundle(buffer)).toThrow(BundleFormatError);
    expect(() => readBundle(buffer)).toThrow(/cannot live in its/);
  });

  it("does not let a plain_len forged after load read the next slot's bytes", async () => {
    // The same defect, forged past the load-time check: a resident buffer is
    // mutated by every open, so the descriptor is re-read on every access and
    // the bound has to hold there too, not only at load.
    const fixture = await buildFixture();
    const buffer = writeBundle(fixture.input);
    const bundle = readBundle(buffer);
    const connectionId = CONNECTIONS[0].uuid;
    const record = bundle.lookup(connectionId);
    const sealed = record?.field("password");
    const group = fixture.groups[CONNECTIONS[0].group];
    if (record === undefined || sealed === undefined || group === undefined) {
      throw new Error("the fixture's first connection is not readable");
    }

    const plaintext = await open(
      record.fieldBytes(sealed),
      group.privateKey,
      fieldAssociatedData(parseUuid(connectionId), "password"),
      group.publicKey,
    );
    const live = bundle.writeBack(sealed, plaintext);
    expect(utf8Decode(record.fieldBytes(live))).toBe(
      fixture.secrets.get(`${connectionId}/password`),
    );

    // Now claim the field runs to the end of the section that follows it.
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    view.setUint32(
      live.descriptorOffset + FIELD_DESCRIPTOR_OFFSET.PLAIN_LEN,
      live.sealedLen + 64,
      true,
    );

    expect(() => record.fieldBytes(live)).toThrow(BundleFormatError);
    expect(() => bundle.lookup(connectionId)?.field("password")).toThrow(/cannot live in its/);
  });
});

// ---------------------------------------------------------------------------
// Rotation: one operation, and the old private half is finished
// ---------------------------------------------------------------------------

describe("rotating a key group after a key is removed", () => {
  const CONNECTION_A = makeUuid(0x31313131, 0x00000301);
  const CONNECTION_B = makeUuid(0x32323232, 0x00000302);
  const PLAINTEXTS: ReadonlyArray<readonly [string, string, string]> = [
    [CONNECTION_A, "password", "hunter2-éè-🔑"],
    [CONNECTION_A, "api_key", "sk-a-0123456789"],
    [CONNECTION_B, "password", ""],
    [CONNECTION_B, "refresh_token", "rt-b-abcdefghijklmnop"],
  ];

  it("reseals every field to a new K1 that both surviving keys open, and no other", async () => {
    const old = await generateGroup();
    const keyA = generateApiKey("live");
    const keyB = generateApiKey("test");
    const staying = [keyA, keyB];
    const removed = generateApiKey("live");
    const before = await buildBucket(
      old.privateKey,
      [keyA.bytes, keyB.bytes, removed.bytes],
      TENANT,
      GROUP_ONE,
    );
    expect(before).toHaveLength(3);

    const fields: SealedField[] = await Promise.all(
      PLAINTEXTS.map(async ([connectionId, fieldName, secret]): Promise<SealedField> => {
        const identity = { connectionUuid: parseUuid(connectionId), fieldName };
        return {
          identity,
          envelope: await seal(
            utf8Encode(secret),
            old.publicKey,
            fieldAssociatedData(parseUuid(connectionId), fieldName),
          ),
        };
      }),
    );

    const rotated = await rotateGroup(
      old.privateKey,
      fields,
      [keyA.bytes, keyB.bytes],
      TENANT,
      GROUP_ONE,
    );

    // One result or none: a new pair, every field, one entry per surviving key.
    expect(rotated.publicKey).not.toEqual(old.publicKey);
    expect(rotated.privateKey).not.toEqual(old.privateKey);
    expect(rotated.fields).toHaveLength(PLAINTEXTS.length);
    expect(rotated.bucket).toHaveLength(2);

    const group: KeyGroup = {
      groupId: GROUP_ONE,
      publicKey: rotated.publicKey,
      generation: 1,
      bucket: rotated.bucket,
    };

    // BOTH surviving keys open EVERY resealed field.
    for (const key of staying) {
      const entry = await findBucketEntry(group, key.bytes, TENANT);
      if (entry === undefined) {
        throw new Error("a surviving key has no entry in the rebuilt bucket");
      }
      const privateKey = await unwrap(entry, key.bytes, TENANT, GROUP_ONE);
      expect(privateKey).toEqual(rotated.privateKey);

      for (const [index, field] of rotated.fields.entries()) {
        const expected = PLAINTEXTS[index];
        if (expected === undefined) {
          throw new Error("rotation returned more fields than it was given");
        }
        // The identity is carried through unchanged: rotation changes the
        // recipient, never what the envelope is bound to.
        expect(field.identity.connectionUuid).toEqual(parseUuid(expected[0]));
        expect(field.identity.fieldName).toBe(expected[1]);
        const opened = await open(
          field.envelope,
          privateKey,
          fieldAssociatedData(parseUuid(expected[0]), expected[1]),
          rotated.publicKey,
        );
        expect(utf8Decode(opened)).toBe(expected[2]);
      }
    }

    // The removed key finds nothing in the rebuilt bucket.
    expect(await findBucketEntry(group, removed.bytes, TENANT)).toBeUndefined();
  });

  it("leaves the old private half able to open none of the resealed fields", async () => {
    const old = await generateGroup();
    const key = generateApiKey("live");
    const fields: SealedField[] = await Promise.all(
      PLAINTEXTS.map(async ([connectionId, fieldName, secret]): Promise<SealedField> => {
        return {
          identity: { connectionUuid: parseUuid(connectionId), fieldName },
          envelope: await seal(
            utf8Encode(secret),
            old.publicKey,
            fieldAssociatedData(parseUuid(connectionId), fieldName),
          ),
        };
      }),
    );

    const rotated = await rotateGroup(old.privateKey, fields, [key.bytes], TENANT, GROUP_ONE);

    for (const field of rotated.fields) {
      const aad = fieldAssociatedData(field.identity.connectionUuid, field.identity.fieldName);
      // Both with and without the stale public half handed in: the salt is
      // wrong either way and the tag simply fails.
      await expect(open(field.envelope, old.privateKey, aad, old.publicKey)).rejects.toBeInstanceOf(
        VaultDecryptionError,
      );
      await expect(open(field.envelope, old.privateKey, aad)).rejects.toBeInstanceOf(
        VaultDecryptionError,
      );
    }

    // ...while the same envelopes open under the new half, so the assertion
    // above is about the key and not about a broken envelope.
    for (const [index, field] of rotated.fields.entries()) {
      const expected = PLAINTEXTS[index];
      if (expected === undefined) {
        throw new Error("rotation returned more fields than it was given");
      }
      const opened = await open(
        field.envelope,
        rotated.privateKey,
        fieldAssociatedData(parseUuid(expected[0]), expected[1]),
        rotated.publicKey,
      );
      expect(utf8Decode(opened)).toBe(expected[2]);
    }
  });

  it("refuses to rotate into a bucket no key would survive in", async () => {
    const old = await generateGroup();
    await expect(rotateGroup(old.privateKey, [], [], TENANT, GROUP_ONE)).rejects.toBeInstanceOf(
      RangeError,
    );
  });

  it("fails whole when a field cannot be opened, rather than returning part of a rotation", async () => {
    const old = await generateGroup();
    const stranger = await generateGroup();
    const key = generateApiKey("live");
    const identity = { connectionUuid: parseUuid(CONNECTION_A), fieldName: "password" };
    const fields: SealedField[] = [
      {
        identity,
        envelope: await seal(
          utf8Encode("openable"),
          old.publicKey,
          fieldAssociatedData(identity.connectionUuid, identity.fieldName),
        ),
      },
      {
        // Sealed to somebody else's group: the old private half cannot open it.
        identity: { connectionUuid: parseUuid(CONNECTION_B), fieldName: "password" },
        envelope: await seal(
          utf8Encode("not openable"),
          stranger.publicKey,
          fieldAssociatedData(parseUuid(CONNECTION_B), "password"),
        ),
      },
    ];

    await expect(
      rotateGroup(old.privateKey, fields, [key.bytes], TENANT, GROUP_ONE),
    ).rejects.toBeInstanceOf(VaultDecryptionError);
  });
});

// ---------------------------------------------------------------------------
// The AAD collision the length prefix exists to close
// ---------------------------------------------------------------------------

describe("associated data that plain concatenation would have collided", () => {
  it('refuses ("grp", "10a1b") opened as ("grp1", "0a1b")', async () => {
    // Plain concatenation is the defect the length prefix exists to close: both
    // pairs produce the identical byte string "grp10a1b". The field AAD can no
    // longer express this collision at all — its first component is a fixed
    // sixteen bytes — so the property is stated where two rendered identifiers
    // still meet: the bucket entry.
    const concatenated = (a: string, b: string): Uint8Array => utf8Encode(a + b);
    expect(concatenated("grp", "10a1b")).toEqual(concatenated("grp1", "0a1b"));
    expect(bucketAssociatedData("grp", "10a1b")).not.toEqual(bucketAssociatedData("grp1", "0a1b"));
  });

  it('refuses a bucket entry sealed for ("grp", "10a1b") opened as ("grp1", "0a1b")', async () => {
    const group = await generateGroup();
    const sealedFor = bucketAssociatedData("grp", "10a1b");
    const shifted = bucketAssociatedData("grp1", "0a1b");
    expect(sealedFor).not.toEqual(shifted);

    const envelope = await seal(group.privateKey, group.publicKey, sealedFor);
    await expect(open(envelope, group.privateKey, shifted, group.publicKey)).rejects.toBeInstanceOf(
      VaultDecryptionError,
    );
  });

  it("binds the exact bytes: a group id differing only in case opens nothing", async () => {
    const group = await generateGroup();
    const key = generateApiKey("live");
    const [entry] = await buildBucket(group.privateKey, [key.bytes], TENANT, GROUP_ONE);
    if (entry === undefined) {
      throw new Error("buildBucket returned no entries");
    }
    // Components are never canonicalised, trimmed or lower-cased.
    await expect(unwrap(entry, key.bytes, TENANT, GROUP_ONE.toUpperCase())).rejects.toBeInstanceOf(
      VaultDecryptionError,
    );
    await expect(unwrap(entry, key.bytes, ` ${TENANT}`, GROUP_ONE)).rejects.toBeInstanceOf(
      VaultDecryptionError,
    );
  });
});
