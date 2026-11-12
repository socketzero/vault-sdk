/**
 * remove-key end to end (`protocol/tenant-management`, `workflows/remove-key.yaml`):
 * `removeKey` through the stock `httpKeyGroupRotator` against socket0-api's
 * fetch-group and commit-rotation routes, played by `rotation-api.fixture.ts`.
 *
 * Every claim is checked by opening what the fake API stored afterwards, with
 * real keys: the removed key opens nothing, each surviving key opens every
 * field, the old K1 opens none of the new envelopes, and K0 still recovers the
 * group.
 */

import { describe, expect, it } from "vitest";
import { deriveKeyIdHex, generateApiKey } from "./api-key.js";
import { KeyGroupRegistrarError } from "./bootstrap.js";
import { parseUuid } from "./bundle/layout.js";
import { base64Decode, base64Encode, utf8Decode, utf8Encode } from "./encoding.js";
import { bucketAssociatedData, fieldAssociatedData, open, seal } from "./envelope.js";
import { buildBucket, findBucketEntry, generateGroup, unwrap } from "./group.js";
import { openRecovery, sealRecovery } from "./recovery.js";
import { httpKeyGroupRotator } from "./registrar-http.js";
import {
  type KeyGroupRotator,
  KeyRemovalOutcomeUnknownError,
  KeyRemovalRefusedError,
  removeKey,
  rotationProof,
} from "./remove-key.js";
import {
  FAKE_BASE_URL,
  FAKE_TOKEN,
  type FakeGroup,
  type FakeRotationApi,
  fakeRotationApi,
} from "./rotation-api.fixture.js";
import {
  type ApiKeyBytes,
  type ApiKeyMaterial,
  asPublicKey,
  type GroupKeyPair,
  type KeyGroup,
  type PublicKey,
  type SealedEnvelope,
  VaultDecryptionError,
} from "./types.js";

const TENANT = "0192f1a0-0000-7000-8000-000000000001";
const GROUP_ID = "0192f1a0-1111-7abc-8def-0123456789ab";
const OTHER_GROUP_ID = "0192f1a0-2222-7abc-8def-0123456789ab";
const CONN_PREFIXED = "aaab-0192a7c1-0000-7000-8000-000000000001";
const CONN_BARE = "0192a7c1-0000-7000-8000-000000000002";
const APP = "0192a7c1-0000-7000-8000-0000000000aa";

/** The UUID bytes a connection's fields bind: the id without its shard tag. */
function uuidOf(id: string): Uint8Array {
  return parseUuid(id.length === 41 ? id.slice(5) : id);
}

async function sealTo(publicKey: PublicKey, owner: string, field: string, value: string) {
  return seal(utf8Encode(value), publicKey, fieldAssociatedData(uuidOf(owner), field));
}

interface World {
  readonly api: FakeRotationApi;
  readonly k1: GroupKeyPair;
  readonly k0: GroupKeyPair | undefined;
  readonly keys: readonly ApiKeyMaterial[];
  readonly keyIds: readonly string[];
  readonly group: FakeGroup;
}

/** One tenant: the group under test with `keyCount` keys, plus an untouched second group. */
async function world(keyCount: number, recovery: boolean): Promise<World> {
  const k1 = await generateGroup();
  const k0 = recovery ? await generateGroup() : undefined;
  const keys = Array.from({ length: keyCount }, () => generateApiKey("test"));
  const bucket = await buildBucket(
    k1.privateKey,
    keys.map((k) => k.bytes),
    TENANT,
    GROUP_ID,
  );
  const keyIds = await Promise.all(keys.map((k) => deriveKeyIdHex(k.bytes, TENANT)));
  const group: FakeGroup = {
    id: GROUP_ID,
    tenantId: TENANT,
    name: "default",
    generation: 4,
    publicKey: base64Encode(k1.publicKey),
    recoveryPublicKey: k0 === undefined ? null : base64Encode(k0.publicKey),
    recoveryEntry:
      k0 === undefined ? null : await sealRecovery(k1.privateKey, k0.publicKey, GROUP_ID),
    keys: bucket.map((entry, i) => ({
      key_id: entry.keyId,
      wrapped: base64Encode(entry.wrapped),
      label: i === 0 ? "laptop" : null,
      created_at: 100 + i,
    })),
  };
  const other = await generateGroup();
  const otherKey = generateApiKey("test");
  const [otherEntry] = await buildBucket(
    other.privateKey,
    [otherKey.bytes],
    TENANT,
    OTHER_GROUP_ID,
  );
  const api = fakeRotationApi({
    tenantId: TENANT,
    groups: [
      group,
      {
        id: OTHER_GROUP_ID,
        tenantId: TENANT,
        name: "other",
        generation: 0,
        publicKey: base64Encode(other.publicKey),
        recoveryPublicKey: null,
        recoveryEntry: null,
        keys: [
          {
            key_id: otherEntry?.keyId as string,
            wrapped: base64Encode(otherEntry?.wrapped as Uint8Array),
            label: null,
            created_at: 1,
          },
        ],
      },
    ],
    connections: [
      {
        id: CONN_PREFIXED,
        groupId: GROUP_ID,
        version: 3,
        config: {
          "access-token": await sealTo(k1.publicKey, CONN_PREFIXED, "access-token", "at-1"),
          "refresh-token": await sealTo(k1.publicKey, CONN_PREFIXED, "refresh-token", "rt-1"),
          region: "eu",
        },
      },
      {
        id: CONN_BARE,
        groupId: GROUP_ID,
        version: 1,
        config: { password: await sealTo(k1.publicKey, CONN_BARE, "password", "hunter2") },
      },
      { id: "0192a7c1-0000-7000-8000-000000000003", groupId: GROUP_ID, version: 1, config: {} },
      {
        id: "0192a7c1-0000-7000-8000-000000000009",
        groupId: OTHER_GROUP_ID,
        version: 7,
        config: { password: await sealTo(other.publicKey, CONN_BARE, "password", "x") },
      },
    ],
    apps: [
      {
        id: APP,
        copies: new Map([
          [GROUP_ID, await sealTo(k1.publicKey, APP, "client-secret", "cs-1")],
          [OTHER_GROUP_ID, await sealTo(other.publicKey, APP, "client-secret", "cs-1")],
        ]),
      },
    ],
  });
  return { api, k1, k0, keys, keyIds, group };
}

type Committed = Awaited<ReturnType<KeyGroupRotator["commitRotation"]>>;

function rotator(api: FakeRotationApi) {
  return httpKeyGroupRotator({ baseUrl: FAKE_BASE_URL, accessToken: FAKE_TOKEN, fetch: api.fetch });
}

function asKeyGroup(group: FakeGroup): KeyGroup {
  return {
    groupId: group.id,
    publicKey: asPublicKey(base64Decode(group.publicKey)),
    generation: group.generation,
    bucket: group.keys.map((k) => ({ keyId: k.key_id, wrapped: base64Decode(k.wrapped) })),
  };
}

/** What a holder of `apiKey` reads back from the stored group, or the error it gets. */
async function readAll(w: World, apiKey: ApiKeyBytes) {
  const stored = asKeyGroup(w.group);
  const entry = await findBucketEntry(stored, apiKey, TENANT);
  if (entry === undefined) return "not in bucket";
  const k1 = await unwrap(entry, apiKey, TENANT, GROUP_ID);
  const config = (id: string) => w.api.state.connections.find((c) => c.id === id)?.config ?? {};
  const read = async (owner: string, field: string, value: unknown) =>
    utf8Decode(
      await open(value as string, k1, fieldAssociatedData(uuidOf(owner), field), stored.publicKey),
    );
  return {
    access: await read(CONN_PREFIXED, "access-token", config(CONN_PREFIXED)["access-token"]),
    refresh: await read(CONN_PREFIXED, "refresh-token", config(CONN_PREFIXED)["refresh-token"]),
    region: config(CONN_PREFIXED)["region"],
    password: await read(CONN_BARE, "password", config(CONN_BARE)["password"]),
    secret: await read(APP, "client-secret", w.api.state.apps[0]?.copies.get(GROUP_ID)),
  };
}

describe("removeKey", () => {
  it("rotates the group so the removed key opens nothing and every survivor opens everything", async () => {
    const w = await world(3, true);
    const [a, b, c] = w.keys as [ApiKeyMaterial, ApiKeyMaterial, ApiKeyMaterial];
    const before = await readAll(w, c.bytes);

    const result = await removeKey({
      rotator: rotator(w.api),
      tenantId: TENANT,
      groupId: GROUP_ID,
      keyId: w.keyIds[2] as string,
      survivingKeys: [a.bytes, b.bytes],
      recoveryPublicKey: (w.k0 as GroupKeyPair).publicKey,
    });

    expect(result.removedKeyId).toBe(w.keyIds[2]);
    expect(result.group.generation).toBe(5);
    expect(result.group.public_key).toBe(w.group.publicKey);
    expect(result.group.public_key).not.toBe(base64Encode(w.k1.publicKey));
    expect(result.group.keys.map((k) => k.key_id)).toEqual(w.keyIds.slice(0, 2));
    // Labels and creation times survive; the API keeps them when none is sent.
    expect(result.group.keys.map((k) => [k.label, k.created_at])).toEqual([
      ["laptop", 100],
      [null, 101],
    ]);

    const expected = {
      access: "at-1",
      refresh: "rt-1",
      region: "eu",
      password: "hunter2",
      secret: "cs-1",
    };
    expect(before).toEqual(expected);
    expect(await readAll(w, a.bytes)).toEqual(expected);
    expect(await readAll(w, b.bytes)).toEqual(expected);
    expect(await readAll(w, c.bytes)).toBe("not in bucket");

    // The removed key's cached copy of the OLD private half opens none of it.
    const resealed = w.api.state.connections.find((x) => x.id === CONN_BARE)?.config["password"];
    await expect(
      open(resealed as string, w.k1.privateKey, fieldAssociatedData(uuidOf(CONN_BARE), "password")),
    ).rejects.toBeInstanceOf(VaultDecryptionError);

    // K0 recovers the new generation.
    const k0 = w.k0 as GroupKeyPair;
    const recovered = await openRecovery(
      w.group.recoveryEntry as string,
      k0.privateKey,
      GROUP_ID,
      asPublicKey(base64Decode(w.group.publicKey)),
    );
    const viaA = await findBucketEntry(asKeyGroup(w.group), a.bytes, TENANT);
    expect(recovered).toEqual(await unwrap(viaA as never, a.bytes, TENANT, GROUP_ID));
    expect(w.group.recoveryPublicKey).toBe(base64Encode(k0.publicKey));

    // Versions moved once, the untouched group and its copy did not move at all.
    expect(w.api.state.connections.map((x) => x.version)).toEqual([4, 2, 2, 7]);
    expect(w.api.state.groups[1]?.generation).toBe(0);

    // fetch-group, then one commit; no label, so the stored ones are kept.
    expect(w.api.calls.map((x) => [x.method, x.status])).toEqual([
      ["GET", 200],
      ["POST", 200],
    ]);
    const sent = w.api.calls[1]?.body as Record<string, unknown>;
    expect(sent["expected_generation"]).toBe(4);
    expect(Object.keys(sent).sort()).toEqual([
      "auth_apps",
      "challenge_id",
      "challenge_proof",
      "connections",
      "expected_generation",
      "keys",
      "public_key",
      "recovery_entry",
      "recovery_public_key",
    ]);
    // The proof: fetch-group's challenge, opened with the CURRENT K1, keys an
    // HMAC of exactly this body; the nonce itself is not sent.
    const challenge = w.api.challenges.get(sent["challenge_id"] as string);
    const { challenge_proof, ...unproven } = sent;
    expect(challenge_proof).toBe(
      await rotationProof(
        base64Decode(challenge?.nonce as string),
        GROUP_ID,
        unproven as unknown as Parameters<typeof rotationProof>[2],
      ),
    );
    expect(challenge?.spent).toBe(true);
  });

  it("removes the key it is called with even when the caller also holds it", async () => {
    const w = await world(2, false);
    const [a, b] = w.keys as [ApiKeyMaterial, ApiKeyMaterial];
    await removeKey({
      rotator: rotator(w.api),
      tenantId: TENANT,
      groupId: GROUP_ID,
      keyId: w.keyIds[0] as string,
      survivingKeys: [b.bytes],
    });
    expect(await readAll(w, a.bytes)).toBe("not in bucket");
    expect((await readAll(w, b.bytes)) as object).toMatchObject({ password: "hunter2" });
    const sent = w.api.calls[1]?.body as Record<string, unknown>;
    expect(sent).not.toHaveProperty("recovery_entry");
    expect(w.group.recoveryEntry).toBeNull();
  });

  it("replaces K0 when given a new recovery public key", async () => {
    const w = await world(2, true);
    const fresh = await generateGroup();
    await removeKey({
      rotator: rotator(w.api),
      tenantId: TENANT,
      groupId: GROUP_ID,
      keyId: w.keyIds[1] as string,
      survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
      recoveryPublicKey: fresh.publicKey,
    });
    expect(w.group.recoveryPublicKey).toBe(base64Encode(fresh.publicKey));
    const k1Public = asPublicKey(base64Decode(w.group.publicKey));
    await expect(
      openRecovery(w.group.recoveryEntry as string, fresh.privateKey, GROUP_ID, k1Public),
    ).resolves.toHaveLength(32);
    await expect(
      openRecovery(
        w.group.recoveryEntry as string,
        (w.k0 as GroupKeyPair).privateKey,
        GROUP_ID,
        k1Public,
      ),
    ).rejects.toBeInstanceOf(VaultDecryptionError);
  });

  it("refuses to remove the last key without asking the API anything", async () => {
    const w = await world(1, false);
    const err = await removeKey({
      rotator: rotator(w.api),
      tenantId: TENANT,
      groupId: GROUP_ID,
      keyId: w.keyIds[0] as string,
      survivingKeys: [],
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(KeyRemovalRefusedError);
    expect((err as KeyRemovalRefusedError).reason).toBe("last-key");
    expect(w.api.calls).toHaveLength(0);
  });

  it("refuses when the bucket holds only the key being removed, and commits nothing", async () => {
    const w = await world(1, false);
    const stranger = generateApiKey("test");
    const err = await removeKey({
      rotator: rotator(w.api),
      tenantId: TENANT,
      groupId: GROUP_ID,
      keyId: w.keyIds[0] as string,
      survivingKeys: [stranger.bytes],
    }).catch((e: unknown) => e);
    expect((err as KeyRemovalRefusedError).reason).toBe("last-key");
    expect(w.api.calls.map((x) => x.method)).toEqual(["GET"]);
  });

  it.each([
    [
      "not-in-group",
      "a key id the bucket does not hold",
      (w: World) => ({ keyId: "f".repeat(32), survivingKeys: w.keys.map((k) => k.bytes) }),
    ],
    [
      "unlisted-key",
      "a bucket key that is neither kept nor removed",
      (w: World) => ({
        keyId: w.keyIds[2] as string,
        survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
      }),
    ],
    [
      "unknown-survivor",
      "a surviving key the bucket does not hold",
      (w: World) => ({
        keyId: w.keyIds[2] as string,
        survivingKeys: [
          (w.keys[0] as ApiKeyMaterial).bytes,
          (w.keys[1] as ApiKeyMaterial).bytes,
          generateApiKey("test").bytes,
        ],
      }),
    ],
  ])("refuses %s (%s) after fetching and before committing", async (reason, _what, pick) => {
    const w = await world(3, false);
    const err = await removeKey({
      rotator: rotator(w.api),
      tenantId: TENANT,
      groupId: GROUP_ID,
      ...pick(w),
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(KeyRemovalRefusedError);
    expect((err as KeyRemovalRefusedError).reason).toBe(reason);
    expect(w.api.calls.map((x) => x.method)).toEqual(["GET"]);
    expect(w.group.generation).toBe(4);
  });

  it("refuses a survivor that is also the key being removed, or presented twice, before any request", async () => {
    const w = await world(2, false);
    const [a, b] = w.keys as [ApiKeyMaterial, ApiKeyMaterial];
    const both = removeKey({
      rotator: rotator(w.api),
      tenantId: TENANT,
      groupId: GROUP_ID,
      keyId: w.keyIds[0] as string,
      survivingKeys: [a.bytes, b.bytes],
    });
    await expect(both).rejects.toThrow(RangeError);
    const twice = removeKey({
      rotator: rotator(w.api),
      tenantId: TENANT,
      groupId: GROUP_ID,
      keyId: w.keyIds[0] as string,
      survivingKeys: [b.bytes, b.bytes],
    });
    await expect(twice).rejects.toThrow(RangeError);
    const malformed = removeKey({
      rotator: rotator(w.api),
      tenantId: TENANT,
      groupId: GROUP_ID,
      keyId: "ABC",
      survivingKeys: [b.bytes],
    });
    await expect(malformed).rejects.toThrow(RangeError);
    expect(w.api.calls).toHaveLength(0);
  });

  it("fetches again and redoes the rotation when the commit is stale", async () => {
    const w = await world(2, false);
    let writes = 0;
    w.api.beforeCommit = () => {
      // A renewal lands between fetch and commit, once.
      if (writes++ > 0) return;
      const conn = w.api.state.connections.find((x) => x.id === CONN_BARE);
      if (conn !== undefined) conn.version += 1;
    };
    await removeKey({
      rotator: rotator(w.api),
      tenantId: TENANT,
      groupId: GROUP_ID,
      keyId: w.keyIds[1] as string,
      survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
    });
    expect(w.api.calls.map((x) => [x.method, x.status])).toEqual([
      ["GET", 200],
      ["POST", 409],
      ["GET", 200],
      ["POST", 200],
    ]);
    expect(w.group.generation).toBe(5);
    // Each round answers the challenge its own fetch minted.
    const posted = w.api.calls
      .filter((x) => x.method === "POST")
      .map((x) => (x.body as Record<string, unknown>)["challenge_id"]);
    expect(new Set(posted).size).toBe(2);
  });

  it("gives up after maxAttempts stale commits with the API's 409", async () => {
    const w = await world(2, false);
    w.api.beforeCommit = () => {
      w.group.generation += 1;
    };
    const err = await removeKey({
      rotator: rotator(w.api),
      tenantId: TENANT,
      groupId: GROUP_ID,
      keyId: w.keyIds[1] as string,
      survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
      maxAttempts: 2,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(KeyGroupRegistrarError);
    expect((err as KeyGroupRegistrarError).status).toBe(409);
    expect((err as KeyGroupRegistrarError).apiError).toBe("stale");
    expect(w.api.calls.filter((x) => x.method === "POST")).toHaveLength(2);
  });

  it("does not retry a 409 that is not stale (K0 appeared after the fetch)", async () => {
    const w = await world(2, false);
    w.api.beforeCommit = () => {
      w.group.recoveryPublicKey = base64Encode(new Uint8Array(32).fill(9));
    };
    const err = await removeKey({
      rotator: rotator(w.api),
      tenantId: TENANT,
      groupId: GROUP_ID,
      keyId: w.keyIds[1] as string,
      survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
    }).catch((e: unknown) => e);
    expect((err as KeyGroupRegistrarError).apiError).toBe("recovery entry required");
    expect(w.api.calls.filter((x) => x.method === "POST")).toHaveLength(1);
  });

  it("propagates the API's 404 for a group that is not the tenant's", async () => {
    const w = await world(2, false);
    const err = await removeKey({
      rotator: rotator(w.api),
      tenantId: "someone-else",
      groupId: GROUP_ID,
      keyId: w.keyIds[1] as string,
      survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
    }).catch((e: unknown) => e);
    expect((err as KeyGroupRegistrarError).status).toBe(404);
    expect((err as KeyGroupRegistrarError).apiError).toBe("not found");
  });

  it("refuses material whose public half is not the one the bucket unwraps to", async () => {
    const w = await world(2, false);
    w.group.publicKey = base64Encode((await generateGroup()).publicKey);
    const err = await removeKey({
      rotator: rotator(w.api),
      tenantId: TENANT,
      groupId: GROUP_ID,
      keyId: w.keyIds[1] as string,
      survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(KeyRemovalRefusedError);
    expect((err as KeyRemovalRefusedError).reason).toBe("inconsistent-material");
    expect(w.api.calls.map((x) => x.method)).toEqual(["GET"]);
  });

  it("refuses a connection id that is neither a bare nor a tagged UUID", async () => {
    const w = await world(2, false);
    w.api.state.connections.push({ id: "not-a-uuid", groupId: GROUP_ID, version: 1, config: {} });
    const err = await removeKey({
      rotator: rotator(w.api),
      tenantId: TENANT,
      groupId: GROUP_ID,
      keyId: w.keyIds[1] as string,
      survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
    }).catch((e: unknown) => e);
    expect((err as KeyRemovalRefusedError).reason).toBe("inconsistent-material");
    expect(w.api.calls.map((x) => x.method)).toEqual(["GET"]);
  });

  it("stops before any request when the signal is already aborted", async () => {
    const w = await world(2, false);
    const controller = new AbortController();
    controller.abort(new Error("stop"));
    await expect(
      removeKey({
        rotator: rotator(w.api),
        tenantId: TENANT,
        groupId: GROUP_ID,
        keyId: w.keyIds[1] as string,
        survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
        signal: controller.signal,
      }),
    ).rejects.toThrow("stop");
    expect(w.api.calls).toHaveLength(0);
  });

  describe("trust boundary: what the API returns is checked, never trusted", () => {
    it("refuses to keep a K0 it was not given, so K1 is never sealed to a server-supplied key", async () => {
      const w = await world(2, true);
      const attacker = await generateGroup();
      w.group.recoveryPublicKey = base64Encode(attacker.publicKey);
      const err = await removeKey({
        rotator: rotator(w.api),
        tenantId: TENANT,
        groupId: GROUP_ID,
        keyId: w.keyIds[1] as string,
        survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(KeyRemovalRefusedError);
      expect((err as KeyRemovalRefusedError).reason).toBe("recovery-key-required");
      expect(w.api.calls.map((x) => x.method)).toEqual(["GET"]);
      expect(w.group.generation).toBe(4);
    });

    it("refuses a K0 that newly appears in the fetch of a group the caller holds without one", async () => {
      const w = await world(2, false);
      w.group.recoveryPublicKey = base64Encode((await generateGroup()).publicKey);
      const err = await removeKey({
        rotator: rotator(w.api),
        tenantId: TENANT,
        groupId: GROUP_ID,
        keyId: w.keyIds[1] as string,
        survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
      }).catch((e: unknown) => e);
      expect((err as KeyRemovalRefusedError).reason).toBe("recovery-key-required");
      expect(w.api.calls.map((x) => x.method)).toEqual(["GET"]);
    });

    it("seals the new K1 to the caller's K0 even when the fetch names another one", async () => {
      const w = await world(2, true);
      const attacker = await generateGroup();
      w.group.recoveryPublicKey = base64Encode(attacker.publicKey);
      const k0 = w.k0 as GroupKeyPair;
      await removeKey({
        rotator: rotator(w.api),
        tenantId: TENANT,
        groupId: GROUP_ID,
        keyId: w.keyIds[1] as string,
        survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
        recoveryPublicKey: k0.publicKey,
      });
      const k1Public = asPublicKey(base64Decode(w.group.publicKey));
      expect(w.group.recoveryPublicKey).toBe(base64Encode(k0.publicKey));
      await expect(
        openRecovery(w.group.recoveryEntry as string, k0.privateKey, GROUP_ID, k1Public),
      ).resolves.toHaveLength(32);
      await expect(
        openRecovery(w.group.recoveryEntry as string, attacker.privateKey, GROUP_ID, k1Public),
      ).rejects.toBeInstanceOf(VaultDecryptionError);
    });

    it("fails with nothing committed when the holder's fetched bucket entry does not open", async () => {
      const w = await world(2, false);
      const entry = w.group.keys[0] as (typeof w.group.keys)[number];
      const bytes = base64Decode(entry.wrapped);
      bytes[bytes.length - 1] = (bytes[bytes.length - 1] as number) ^ 1;
      entry.wrapped = base64Encode(bytes);
      const err = await removeKey({
        rotator: rotator(w.api),
        tenantId: TENANT,
        groupId: GROUP_ID,
        keyId: w.keyIds[1] as string,
        survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(VaultDecryptionError);
      expect(w.api.calls.map((x) => x.method)).toEqual(["GET"]);
      expect(w.group.generation).toBe(4);
    });

    it.each([
      [
        "the pre-rotation public half",
        (g: Committed, w: World) => ({ ...g, public_key: base64Encode(w.k1.publicKey) }),
      ],
      ["an unmoved generation", (g: Committed) => ({ ...g, generation: g.generation - 1 })],
      [
        "the removed key still listed",
        (g: Committed, w: World) => ({
          ...g,
          keys: [...g.keys, { key_id: w.keyIds[1] as string, label: null, created_at: 101 }],
        }),
      ],
    ])("does not report success for a commit 200 naming %s", async (_what, lie) => {
      const w = await world(2, false);
      const real = rotator(w.api);
      const lying: KeyGroupRotator = {
        fetchRotation: real.fetchRotation.bind(real),
        commitRotation: async (...args) => lie(await real.commitRotation(...args), w) as Committed,
      };
      const err = await removeKey({
        rotator: lying,
        tenantId: TENANT,
        groupId: GROUP_ID,
        keyId: w.keyIds[1] as string,
        survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(KeyRemovalOutcomeUnknownError);
      expect((err as KeyRemovalOutcomeUnknownError).removedKeyId).toBe(w.keyIds[1]);
      expect((err as KeyRemovalOutcomeUnknownError).publicKey).toBe(w.group.publicKey);
    });
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, 0, -1, 1.5])(
    "refuses maxAttempts %s before any request",
    async (maxAttempts) => {
      const w = await world(2, false);
      const err = removeKey({
        rotator: rotator(w.api),
        tenantId: TENANT,
        groupId: GROUP_ID,
        keyId: w.keyIds[1] as string,
        survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
        maxAttempts,
      });
      await expect(err).rejects.toThrow(RangeError);
      expect(w.api.calls).toHaveLength(0);
    },
  );

  describe("proof of possession of the current K1", () => {
    const run = (w: World) =>
      removeKey({
        rotator: rotator(w.api),
        tenantId: TENANT,
        groupId: GROUP_ID,
        keyId: w.keyIds[1] as string,
        survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
      }).catch((e: unknown) => e);

    it("propagates the API's 403 without retrying, and nothing lands", async () => {
      const w = await world(2, false);
      // The server keys the proof by another nonce than the one it sealed.
      w.api.beforeCommit = () => {
        for (const [id, c] of w.api.challenges) {
          w.api.challenges.set(id, { ...c, nonce: base64Encode(new Uint8Array(32).fill(9)) });
        }
      };
      const err = await run(w);
      expect(err).toBeInstanceOf(KeyGroupRegistrarError);
      expect((err as KeyGroupRegistrarError).status).toBe(403);
      expect((err as KeyGroupRegistrarError).apiError).toBe("proof invalid");
      expect(w.api.calls.map((x) => [x.method, x.status])).toEqual([
        ["GET", 200],
        ["POST", 403],
      ]);
      expect(w.group.generation).toBe(4);
    });

    it("computes the wire proof as specified (reference vector for socket0-api)", async () => {
      // HMAC-SHA256(key = nonce, "socket0/rotation-proof/v1" 0x00 group id 0x00
      // JCS(body without challenge_proof)), base64. Computed independently with
      // Python's hmac + json.dumps(sort_keys=True, separators=(",", ":")).
      const nonce = Uint8Array.from({ length: 32 }, (_, i) => i);
      const proof = await rotationProof(nonce, GROUP_ID, {
        expected_generation: 4,
        public_key: `${"A".repeat(43)}=`,
        keys: [{ key_id: "0".repeat(32), wrapped: "B".repeat(60) }],
        connections: [
          {
            id: "0192a7c1-0000-7000-8000-000000000002",
            version: 1,
            sealed: {
              password: "x25519-hkdf-aesgcm:AAAA" as SealedEnvelope,
              "api-key": "x25519-hkdf-aesgcm:BBBB" as SealedEnvelope,
            },
          },
        ],
        auth_apps: [],
        recovery_public_key: `${"C".repeat(43)}=`,
        recovery_entry: "x25519-hkdf-aesgcm:CCCC" as SealedEnvelope,
        challenge_id: "0192f1a0-cccc-7000-8000-000000000001",
      });
      expect(proof).toBe("tREhlSkaONczqDKwUGlLPMvvZErOMBV3UVyeZ/fRNiY=");
    });

    it("binds the answer to the body: a commit seen in transit cannot name another K1", async () => {
      const w = await world(2, false);
      // A proxy logs the commit body, then the connection drops before the
      // server judges it: the challenge is still unspent.
      const logged: string[] = [];
      const honestFetch = w.api.fetch;
      const dropping = (async (input: string | URL | Request, init?: RequestInit) => {
        if (init?.method === "POST") {
          logged.push(init.body as string);
          throw new TypeError("network dropped");
        }
        return honestFetch(input, init);
      }) as typeof globalThis.fetch;
      const err = await removeKey({
        rotator: httpKeyGroupRotator({
          baseUrl: FAKE_BASE_URL,
          accessToken: FAKE_TOKEN,
          fetch: dropping,
        }),
        tenantId: TENANT,
        groupId: GROUP_ID,
        keyId: w.keyIds[1] as string,
        survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(TypeError);
      expect(logged).toHaveLength(1);
      const seen = JSON.parse(logged[0] as string) as Record<string, unknown>;
      const minted = w.api.challenges.get(seen["challenge_id"] as string);
      // The opened nonce itself never leaves the SDK.
      expect(logged[0]).not.toContain(minted?.nonce as string);

      // A stolen session replays the proof with its own K1.
      const attacker = await generateGroup();
      const forged = await w.api.fetch(
        `${FAKE_BASE_URL}/tenants/${TENANT}/key-groups/${GROUP_ID}/rotation`,
        {
          method: "POST",
          headers: { authorization: `Bearer ${FAKE_TOKEN}`, "content-type": "application/json" },
          body: JSON.stringify({ ...seen, public_key: base64Encode(attacker.publicKey) }),
        },
      );
      expect(forged.status).toBe(403);
      expect(await forged.json()).toEqual({ error: "proof invalid" });
      expect(w.group.generation).toBe(4);
      expect(w.group.publicKey).toBe(base64Encode(w.k1.publicKey));
    });

    it("fetches again when the challenge expired before the commit (409 stale), and lands", async () => {
      const w = await world(2, false);
      // The first reseal is slower than the challenge's 300 s life.
      let slow = true;
      w.api.beforeCommit = () => {
        if (slow) w.api.now += 300;
        slow = false;
      };
      await expect(run(w)).resolves.toMatchObject({ removedKeyId: w.keyIds[1] });
      expect(w.api.calls.map((x) => [x.method, x.status])).toEqual([
        ["GET", 200],
        ["POST", 409],
        ["GET", 200],
        ["POST", 200],
      ]);
      expect(w.group.generation).toBe(5);
    });

    // socket0-api#42 review, round 4: a group holds eight unspent challenges
    // and a ninth fetch evicts the oldest. A stolen session fetching eight
    // times between this client's fetch and commit must not fail the removal.
    it("fetches again when other fetches evicted its challenge before the commit, and lands", async () => {
      const w = await world(2, false);
      const real = rotator(w.api);
      let evict = true;
      const crowded: KeyGroupRotator = {
        fetchRotation: real.fetchRotation.bind(real),
        commitRotation: async (...args) => {
          if (evict) {
            evict = false;
            for (let i = 0; i < 8; i += 1) await real.fetchRotation(TENANT, GROUP_ID);
          }
          return real.commitRotation(...args);
        },
      };
      const removed = await removeKey({
        rotator: crowded,
        tenantId: TENANT,
        groupId: GROUP_ID,
        keyId: w.keyIds[1] as string,
        survivingKeys: [(w.keys[0] as ApiKeyMaterial).bytes],
      });
      expect(removed.removedKeyId).toBe(w.keyIds[1]);
      expect(w.api.calls.map((x) => [x.method, x.status])).toEqual([
        ...Array.from({ length: 9 }, () => ["GET", 200]),
        ["POST", 409],
        ["GET", 200],
        ["POST", 200],
      ]);
      expect(w.group.generation).toBe(5);
    });

    it("lands with a challenge one second short of expiry", async () => {
      const w = await world(2, false);
      w.api.beforeCommit = () => {
        w.api.now += 299;
      };
      await expect(run(w)).resolves.toMatchObject({ removedKeyId: w.keyIds[1] });
      expect(w.group.generation).toBe(5);
    });

    it.each([
      [
        "sealed to a key other than the group's",
        async (c: { id: string }) =>
          seal(
            new Uint8Array(32),
            (await generateGroup()).publicKey,
            bucketAssociatedData(GROUP_ID, `rotation-challenge:${c.id}`),
          ),
      ],
      [
        "not 32 bytes",
        async (c: { id: string }, w: World) =>
          seal(
            new Uint8Array(31),
            w.k1.publicKey,
            bucketAssociatedData(GROUP_ID, `rotation-challenge:${c.id}`),
          ),
      ],
      [
        "a connection's sealed field - the server asking the SDK to decrypt it",
        async (_c: { id: string }, w: World) =>
          w.api.state.connections.find((x) => x.id === CONN_BARE)?.config["password"] as string,
      ],
      ["not an envelope at all", async () => "garbage"],
    ])("refuses a challenge %s, and sends nothing back", async (_what, forge) => {
      const w = await world(2, false);
      w.api.tamperChallenge = async (honest) => ({
        ...honest,
        sealed_nonce: await forge(honest, w),
      });
      const err = await run(w);
      expect(err).toBeInstanceOf(KeyRemovalRefusedError);
      expect((err as KeyRemovalRefusedError).reason).toBe("inconsistent-material");
      expect(w.api.calls.map((x) => x.method)).toEqual(["GET"]);
      expect(w.group.generation).toBe(4);
    });
  });
});
