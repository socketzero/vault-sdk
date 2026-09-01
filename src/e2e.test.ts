/**
 * One tenant, from bootstrap to rotation, through every party that touches a
 * credential.
 *
 * Every other test file proves a module, and `integration.test.ts` proves two
 * modules against each other. This file proves the *system claim* the catalog
 * makes and nothing else checks: that a credential sealed by a control plane
 * which holds no private key is opened at the edge by a shard which holds no
 * key either, using only the API key that arrived in a request header — and
 * that removing that API key actually takes the access away.
 *
 * It is written as one story per `describe`, in the order the operations really
 * happen, because the failures worth catching here are ordering failures: a
 * rotation that leaves the old key working, a bundle that opens under the wrong
 * tenant, a write-back that survives a republish it should not survive.
 */

import { describe, expect, it, vi } from "vitest";
import { generateApiKey } from "./api-key.js";
import { readBundle } from "./bundle/reader.js";
import { writeBundleWithChecksum } from "./bundle/writer.js";
import { revealDump } from "./cli/reveal.js";
import { utf8Decode, utf8Encode } from "./encoding.js";
import { fieldAssociatedData, open, seal } from "./envelope.js";
import { buildBucket, findBucketEntry, generateGroup, rotateGroup, unwrap } from "./group.js";
import { bundleFromJSON, inspectBundle, verifyBundle } from "./inspect.js";
import {
  connectionId,
  makeConnection,
  makeGroup,
  makeUuid,
  SHARD,
  TENANT,
} from "./lifecycle.fixture.js";
import {
  type ApiKeyBytes,
  type BundleInput,
  FieldState,
  type KeyGroup,
  type SealedField,
  VaultDecryptionError,
} from "./types.js";

const GROUP = makeUuid(0xa1a1a1a1, 0x00000001);
const STRIPE = connectionId(0x00000001);
const PASSWORD = "sk_live_51HxxxxxxxxxxxxxxxxxxxxxxQ";

/**
 * The read a shard actually performs: find the connection, find the bucket
 * entry for the key on the request, unwrap K1, open the field, cache it back.
 *
 * Written out longhand rather than hidden in a helper the library provides,
 * because whether these six steps compose is the question this file exists to
 * answer.
 */
async function shardOpens(
  bundle: Uint8Array,
  id: string,
  fieldName: string,
  apiKey: ApiKeyBytes,
  tenantId = TENANT,
): Promise<string> {
  // A fresh copy per call: each invocation models an isolate loading the
  // generation for itself. Sharing one buffer would leak the previous call's
  // write-back into the next, which `readBundle` rejects outright — and that
  // rejection is the reader doing its job, not a failure of the scenario.
  const view = readBundle(bundle.slice());
  const record = view.lookup(id);
  if (record === undefined) throw new Error(`shard: no connection ${id}`);

  const group = view.group(record.groupIndex);
  if (group === undefined) throw new Error("shard: connection names a group that is not here");

  const keyGroup: KeyGroup = {
    groupId: group.groupId(),
    publicKey: group.publicKey(),
    generation: group.generation(),
    bucket: Array.from({ length: group.bucketSize }, (_, i) => {
      const entry = group.bucketEntry(i);
      if (entry === undefined) throw new Error("shard: bucket entry missing");
      return { keyId: entry.keyIdHex(), wrapped: entry.wrapped() };
    }),
  };

  const entry = await findBucketEntry(keyGroup, apiKey, tenantId);
  if (entry === undefined) throw new VaultDecryptionError();
  const privateKey = await unwrap(entry, apiKey, tenantId, keyGroup.groupId);

  const descriptor = record.field(fieldName);
  if (descriptor === undefined) throw new Error(`shard: no field ${fieldName}`);
  const plaintext = await open(
    record.fieldBytes(descriptor),
    privateKey,
    fieldAssociatedData(id, fieldName),
  );
  view.writeBack(descriptor, plaintext);
  return utf8Decode(plaintext);
}

// ---------------------------------------------------------------------------

describe("bootstrapping a tenant", () => {
  it("creates a group whose private half exists once, in the bucket, wrapped", async () => {
    const key = generateApiKey("live");
    const pair = await generateGroup();
    const bucket = await buildBucket(pair.privateKey, [key.bytes], TENANT, GROUP);

    expect(bucket).toHaveLength(1);
    // The claim the whole design rests on: what is stored is a ciphertext, and
    // the plaintext private half appears nowhere in it.
    const entry = bucket[0];
    if (entry === undefined) throw new Error("buildBucket returned no entries");
    expect(Array.from(entry.wrapped)).not.toEqual(Array.from(pair.privateKey));

    // And the key that made the bucket is the key that opens it.
    await expect(unwrap(entry, key.bytes, TENANT, GROUP)).resolves.toEqual(pair.privateKey);
  });

  it("refuses to create a group nobody can ever open", async () => {
    const pair = await generateGroup();
    await expect(buildBucket(pair.privateKey, [], TENANT, GROUP)).rejects.toThrow(RangeError);
  });
});

describe("the control plane authoring a connection", () => {
  it("seals a credential holding only the public half — it cannot read what it stored", async () => {
    const group = await makeGroup({ groupId: GROUP, keys: ["live"] });
    const envelope = await seal(
      utf8Encode(PASSWORD),
      group.pair.publicKey,
      fieldAssociatedData(STRIPE, "password"),
    );

    expect(envelope.startsWith("x25519-hkdf-aesgcm:")).toBe(true);
    // Nothing in this scope can undo that. Opening needs the private half, and
    // the private half was never handed to the party that did the sealing.
    await expect(
      open(envelope, group.pair.privateKey, fieldAssociatedData(STRIPE, "password")),
    ).resolves.toEqual(utf8Encode(PASSWORD));
  });

  it("publishes a bundle that verifies structurally, not just by checksum", async () => {
    const group = await makeGroup({ groupId: GROUP, keys: ["live"] });
    const input: BundleInput = {
      header: { version: 1, generation: 1n, shard: SHARD, builtAt: 1_726_000_000_000n },
      groups: [group.keyGroup],
      connections: [
        await makeConnection({
          connectionId: STRIPE,
          group,
          target: "https://api.stripe.com",
          visible: { limit: 100 },
          secrets: { password: PASSWORD },
        }),
      ],
      filters: [],
    };

    const report = await verifyBundle(readBundle(await writeBundleWithChecksum(input)));
    expect(report.ok).toBe(true);
    expect(report.indexResolved).toBe(1);
  });
});

// ---------------------------------------------------------------------------

describe("the shard serving a request", () => {
  async function published(keys: readonly ("live" | "test")[] = ["live"]) {
    const group = await makeGroup({ groupId: GROUP, keys });
    const input: BundleInput = {
      header: { version: 1, generation: 1n, shard: SHARD, builtAt: 1_726_000_000_000n },
      groups: [group.keyGroup],
      connections: [
        await makeConnection({
          connectionId: STRIPE,
          group,
          target: "https://api.stripe.com",
          visible: { limit: 100 },
          secrets: { password: PASSWORD, username: "acct_1QZ" },
        }),
      ],
      filters: [],
    };
    return { group, bytes: await writeBundleWithChecksum(input) };
  }

  it("opens the credential with nothing but the API key from the request header", async () => {
    const { group, bytes } = await published();
    const key = group.keys[0];
    if (key === undefined) throw new Error("no key");

    // No private key, no shared secret, no fleet key: the header is the input.
    await expect(shardOpens(bytes, STRIPE, "password", key.bytes)).resolves.toBe(PASSWORD);
  });

  it("reads the visible configuration with no key at all", async () => {
    const { bytes } = await published();
    const record = readBundle(bytes).lookup(STRIPE);
    expect(record?.visible("limit")).toBe(100);
    expect(record?.target()).toBe("https://api.stripe.com");
  });

  it("does no cryptography at all on the second read of the same field", async () => {
    const { group, bytes } = await published();
    const key = group.keys[0];
    if (key === undefined) throw new Error("no key");

    // One long-lived view, the way an isolate holds one buffer across requests.
    const view = readBundle(bytes);
    const record = view.lookup(STRIPE);
    const descriptor = record?.field("password");
    if (record === undefined || descriptor === undefined) throw new Error("no field");

    const grup = view.group(record.groupIndex);
    if (grup === undefined) throw new Error("no group");
    const entry = grup.bucketEntry(0);
    if (entry === undefined) throw new Error("no entry");
    const privateKey = await unwrap(
      { keyId: entry.keyIdHex(), wrapped: entry.wrapped() },
      key.bytes,
      TENANT,
      GROUP,
    );
    const first = await open(
      record.fieldBytes(descriptor),
      privateKey,
      fieldAssociatedData(STRIPE, "password"),
    );
    const cached = view.writeBack(descriptor, first);

    const decrypt = vi.spyOn(globalThis.crypto.subtle, "decrypt");
    const second = record.fieldBytes(cached);
    decrypt.mockRestore();

    expect(cached.state).toBe(FieldState.Open);
    expect(utf8Decode(second)).toBe(PASSWORD);
    // The whole point of the write-back cache: the hot path is a memory read.
    expect(decrypt).not.toHaveBeenCalled();
  });

  it("refuses a key from another tenant, and one that is simply not in the bucket", async () => {
    const { group, bytes } = await published();
    const key = group.keys[0];
    const stranger = generateApiKey("live");
    if (key === undefined) throw new Error("no key");

    await expect(shardOpens(bytes, STRIPE, "password", stranger.bytes)).rejects.toThrow(
      VaultDecryptionError,
    );
    // The same key, the same bundle, a different tenant: the salt is the tenant,
    // so the key id does not even match and the bucket lookup misses.
    await expect(shardOpens(bytes, STRIPE, "password", key.bytes, "tnt_other")).rejects.toThrow(
      VaultDecryptionError,
    );
  });

  it("gives two API keys in one bucket the identical credential", async () => {
    const { group, bytes } = await published(["live", "test"]);
    const [a, b] = group.keys;
    if (a === undefined || b === undefined) throw new Error("expected two keys");

    await expect(shardOpens(bytes, STRIPE, "password", a.bytes)).resolves.toBe(PASSWORD);
    await expect(shardOpens(bytes, STRIPE, "password", b.bytes)).resolves.toBe(PASSWORD);
  });

  it("does not resolve a connection that belongs to another shard", async () => {
    const { bytes } = await published();
    const elsewhere = connectionId(0x00000001, "usea");
    expect(readBundle(bytes).lookup(elsewhere)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------

describe("rotating a key group after an API key is revoked", () => {
  it("takes the revoked key's access away and keeps the survivor's", async () => {
    // Two keys share a group. One is revoked, which forces a new K1: the
    // revoked key could otherwise still unwrap the old private half from any
    // bundle generation it ever saw.
    const group = await makeGroup({ groupId: GROUP, keys: ["live", "test"] });
    const [revoked, survivor] = group.keys;
    if (revoked === undefined || survivor === undefined) throw new Error("expected two keys");

    const envelope = await seal(
      utf8Encode(PASSWORD),
      group.pair.publicKey,
      fieldAssociatedData(STRIPE, "password"),
    );
    const fields: SealedField[] = [
      { identity: { connectionId: STRIPE, fieldName: "password" }, envelope },
    ];

    const rotation = await rotateGroup(
      group.pair.privateKey,
      fields,
      [survivor.bytes],
      TENANT,
      GROUP,
    );
    const resealed = rotation.fields[0];
    if (resealed === undefined) throw new Error("rotation returned no fields");

    const republished = await writeBundleWithChecksum({
      header: { version: 1, generation: 2n, shard: SHARD, builtAt: 1_726_000_100_000n },
      groups: [
        { groupId: GROUP, publicKey: rotation.publicKey, generation: 1, bucket: rotation.bucket },
      ],
      connections: [
        {
          connectionId: STRIPE,
          groupId: GROUP,
          target: "https://api.stripe.com",
          visible: { limit: 100 },
          sealed: { password: resealed.envelope },
          filters: [],
          expiresAt: null,
        },
      ],
      filters: [],
    });

    await expect(shardOpens(republished, STRIPE, "password", survivor.bytes)).resolves.toBe(
      PASSWORD,
    );
    // The revoked key is not in the new bucket, so it never reaches a private
    // half — and the private half it could have kept opens nothing here either,
    // because every field was resealed to a new K1.
    await expect(shardOpens(republished, STRIPE, "password", revoked.bytes)).rejects.toThrow(
      VaultDecryptionError,
    );
    await expect(
      open(resealed.envelope, group.pair.privateKey, fieldAssociatedData(STRIPE, "password")),
    ).rejects.toThrow(VaultDecryptionError);
  });

  it("keeps every surviving key's identifier across the rotation", async () => {
    const group = await makeGroup({ groupId: GROUP, keys: ["live", "test"] });
    const [, survivor] = group.keys;
    if (survivor === undefined) throw new Error("expected two keys");

    const before = await findBucketEntry(group.keyGroup, survivor.bytes, TENANT);
    const rotation = await rotateGroup(group.pair.privateKey, [], [survivor.bytes], TENANT, GROUP);

    // `key_id` is derived from the API key and the tenant, never from K1, which
    // is why a rotation does not invalidate the identifier a bucket stores.
    expect(rotation.bucket[0]?.keyId).toBe(before?.keyId);
  });

  it("leaves the old generation openable by the old key, which is why rotation must republish", async () => {
    const group = await makeGroup({ groupId: GROUP, keys: ["live"] });
    const key = group.keys[0];
    if (key === undefined) throw new Error("no key");

    const old = await writeBundleWithChecksum({
      header: { version: 1, generation: 1n, shard: SHARD, builtAt: 1n },
      groups: [group.keyGroup],
      connections: [
        await makeConnection({
          connectionId: STRIPE,
          group,
          target: "https://api.stripe.com",
          secrets: { password: PASSWORD },
        }),
      ],
      filters: [],
    });

    // Stated as a fact, not a defect: a bundle already at the edge keeps working
    // until the next generation lands. Revocation is a publish, not an event.
    await expect(shardOpens(old, STRIPE, "password", key.bytes)).resolves.toBe(PASSWORD);
  });
});

// ---------------------------------------------------------------------------

describe("the debugging tools, against the artifact the shard actually reads", () => {
  async function published() {
    const group = await makeGroup({ groupId: GROUP, keys: ["test"] });
    const bytes = await writeBundleWithChecksum({
      header: { version: 1, generation: 9n, shard: SHARD, builtAt: 1_726_000_000_000n },
      groups: [group.keyGroup],
      connections: [
        await makeConnection({
          connectionId: STRIPE,
          group,
          target: "https://api.stripe.com",
          visible: { limit: 100 },
          secrets: { password: PASSWORD },
        }),
      ],
      filters: [],
    });
    return { group, bytes };
  }

  it("verifies, dumps, rebuilds byte-identically, and the rebuild still opens", async () => {
    const { group, bytes } = await published();
    const key = group.keys[0];
    if (key === undefined) throw new Error("no key");

    expect((await verifyBundle(readBundle(bytes))).ok).toBe(true);

    const dump = JSON.parse(JSON.stringify(inspectBundle(readBundle(bytes))));
    const rebuilt = await writeBundleWithChecksum(bundleFromJSON(dump));
    expect(rebuilt).toEqual(bytes);

    // The rebuild is not merely well-formed: a real API key still opens it.
    await expect(shardOpens(rebuilt, STRIPE, "password", key.bytes)).resolves.toBe(PASSWORD);
  });

  it("shows the operator nothing secret until they hand in a key", async () => {
    const { group, bytes } = await published();
    const key = group.keys[0];
    if (key === undefined) throw new Error("no key");

    const closed = JSON.stringify(inspectBundle(readBundle(bytes)));
    expect(closed).not.toContain(PASSWORD);

    const view = readBundle(bytes);
    const result = await revealDump(inspectBundle(view), key.bytes, TENANT);
    const opened = JSON.stringify(inspectBundle(view, { revealed: result.revealed }));

    expect(result.groupsOpened).toBe(1);
    expect(opened).toContain(PASSWORD);
    // And it is labelled as such wherever it appears.
    expect(opened).toContain('"revealed":true');
  });
});
