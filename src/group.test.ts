import { describe, expect, it } from "vitest";

import { deriveWrapKey } from "./api-key.js";
import { fieldAssociatedData, open, seal } from "./envelope.js";
import {
  buildBucket,
  findBucketEntry,
  generateGroup,
  rotateGroup,
  unwrap,
  WRAPPED_PRIVATE_KEY_BYTES,
  wrap,
} from "./group.js";
import type {
  ApiKeyBytes,
  BucketEntry,
  KeyGroup,
  PrivateKey,
  PublicKey,
  SealedField,
} from "./types.js";
import { asApiKeyBytes, asPrivateKey, asPublicKey, VaultDecryptionError } from "./types.js";

const TENANT = "tenant_01JC0000000000000000000000";
const OTHER_TENANT = "tenant_01JC1111111111111111111111";
const GROUP = "default";
const OTHER_GROUP = "staging";

/** A stand-in for the raw 32 bytes `parseApiKey` hands back. */
function apiKeyBytes(): ApiKeyBytes {
  return asApiKeyBytes(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

/** An `ArrayBuffer`-backed copy, which is what Web Crypto's `BufferSource` wants. */
function buffer(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy;
}

function corrupt(entry: BucketEntry, index: number): BucketEntry {
  const wrapped = entry.wrapped.slice();
  const byte = wrapped[index];
  if (byte === undefined) {
    throw new RangeError(`index ${index} is outside the wrapped entry`);
  }
  wrapped[index] = byte ^ 0xff;
  return { keyId: entry.keyId, wrapped };
}

function groupOf(bucket: readonly BucketEntry[]): KeyGroup {
  return { groupId: GROUP, publicKey: asPublicKey(new Uint8Array(32)), generation: 1, bucket };
}

// ---------------------------------------------------------------------------
// Independent reimplementations of the two AAD constructions, so the vector
// tests pin what `group.ts` actually feeds AES-GCM rather than agreeing with
// the implementation they are meant to check.
// ---------------------------------------------------------------------------

/** `AAD(a, b, ...) = u32be(len(utf8(a))) || utf8(a) || ...` — the spec's rule. */
function lengthPrefixedAad(...parts: readonly string[]): Uint8Array<ArrayBuffer> {
  const encoded = parts.map((part) => new TextEncoder().encode(part));
  const out = new Uint8Array(encoded.reduce((sum, part) => sum + 4 + part.length, 0));
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const part of encoded) {
    view.setUint32(offset, part.length, false);
    offset += 4;
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** The defect the spec now forbids: plain concatenation of the components. */
function concatenatedAad(...parts: readonly string[]): Uint8Array<ArrayBuffer> {
  return buffer(new TextEncoder().encode(parts.join("")));
}

/** Open a wrapped entry by hand, under an associated data of the test's choosing. */
async function unwrapUnder(
  entry: BucketEntry,
  apiKey: ApiKeyBytes,
  tenantId: string,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array> {
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    buffer(await deriveWrapKey(apiKey, tenantId)),
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const opened = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: buffer(entry.wrapped.subarray(0, 12)), additionalData: aad },
    key,
    buffer(entry.wrapped.subarray(12)),
  );
  return new Uint8Array(opened);
}

/** One connection's worth of sealed fields, for the rotation tests. */
function sealFields(
  publicKey: PublicKey,
  values: ReadonlyMap<string, string>,
): Promise<SealedField[]> {
  return Promise.all(
    Array.from(values, async ([fieldName, value]) => ({
      identity: { connectionId: "conn_01JC", fieldName },
      envelope: await seal(
        new TextEncoder().encode(value),
        publicKey,
        fieldAssociatedData("conn_01JC", fieldName),
      ),
    })),
  );
}

async function openField(field: SealedField, privateKey: PrivateKey): Promise<string> {
  return new TextDecoder().decode(
    await open(
      field.envelope,
      privateKey,
      fieldAssociatedData(field.identity.connectionId, field.identity.fieldName),
    ),
  );
}

describe("generateGroup", () => {
  it("produces a 32-byte X25519 keypair", async () => {
    const pair = await generateGroup();

    expect(pair.publicKey).toHaveLength(32);
    expect(pair.privateKey).toHaveLength(32);
  });

  it("produces a different keypair every time", async () => {
    const [first, second] = await Promise.all([generateGroup(), generateGroup()]);

    expect(Array.from(second.privateKey)).not.toEqual(Array.from(first.privateKey));
    expect(Array.from(second.publicKey)).not.toEqual(Array.from(first.publicKey));
  });
});

describe("wrap", () => {
  it("produces nonce || ciphertext || tag and a 32-hex key id", async () => {
    const { privateKey } = await generateGroup();

    const entry = await wrap(privateKey, apiKeyBytes(), TENANT, GROUP);

    expect(entry.wrapped).toHaveLength(WRAPPED_PRIVATE_KEY_BYTES);
    expect(WRAPPED_PRIVATE_KEY_BYTES).toBe(60);
    expect(entry.keyId).toMatch(/^[0-9a-f]{32}$/);
  });

  it("never stores the private half in the clear", async () => {
    const { privateKey } = await generateGroup();

    const entry = await wrap(privateKey, apiKeyBytes(), TENANT, GROUP);

    const haystack = Array.from(entry.wrapped).join(",");
    expect(haystack).not.toContain(Array.from(privateKey).join(","));
  });

  it("uses a fresh nonce, so wrapping the same key twice differs", async () => {
    const { privateKey } = await generateGroup();
    const apiKey = apiKeyBytes();

    const [a, b] = await Promise.all([
      wrap(privateKey, apiKey, TENANT, GROUP),
      wrap(privateKey, apiKey, TENANT, GROUP),
    ]);

    expect(a.keyId).toBe(b.keyId);
    expect(Array.from(b.wrapped)).not.toEqual(Array.from(a.wrapped));
  });

  it("derives a key id that depends on the tenant, not on the group", async () => {
    const apiKey = apiKeyBytes();
    const { privateKey } = await generateGroup();

    const here = await wrap(privateKey, apiKey, TENANT, GROUP);
    const otherGroup = await wrap(privateKey, apiKey, TENANT, OTHER_GROUP);
    const otherTenant = await wrap(privateKey, apiKey, OTHER_TENANT, GROUP);

    expect(otherGroup.keyId).toBe(here.keyId);
    expect(otherTenant.keyId).not.toBe(here.keyId);
  });

  it("cannot be handed a private half that is not 32 bytes — the brand is the guard", () => {
    // `wrap` used to check this at runtime. `asPrivateKey` is now the only way
    // to produce a `PrivateKey`, so the malformed call no longer type-checks and
    // the check lives in the one place reachable with raw bytes.
    expect(() => asPrivateKey(new Uint8Array(31))).toThrow(RangeError);
    expect(() => asPrivateKey(new Uint8Array(33))).toThrow(RangeError);
  });
});

describe("the bucket's associated data", () => {
  it("is the length-prefixed AAD(group_id, key_id) of construction.md", async () => {
    const { privateKey } = await generateGroup();
    const apiKey = apiKeyBytes();

    const entry = await wrap(privateKey, apiKey, TENANT, GROUP);

    const recovered = await unwrapUnder(
      entry,
      apiKey,
      TENANT,
      lengthPrefixedAad(GROUP, entry.keyId),
    );
    expect(Array.from(recovered)).toEqual(Array.from(privateKey));
  });

  it("is NOT the plain concatenation the spec calls a defect", async () => {
    const { privateKey } = await generateGroup();
    const apiKey = apiKeyBytes();

    const entry = await wrap(privateKey, apiKey, TENANT, GROUP);

    await expect(
      unwrapUnder(entry, apiKey, TENANT, concatenatedAad(GROUP, entry.keyId)),
    ).rejects.toThrow();
  });

  it("prefixes each component, so ('ab','c') and ('a','bc') cannot collide", () => {
    // The vector the rule exists for, stated on the helper the two tests above
    // pin the implementation against.
    expect(Array.from(lengthPrefixedAad("ab", "c"))).not.toEqual(
      Array.from(lengthPrefixedAad("a", "bc")),
    );
    expect(Array.from(concatenatedAad("ab", "c"))).toEqual(Array.from(concatenatedAad("a", "bc")));
  });

  it("binds the group id byte for byte, uncanonicalised", async () => {
    const { privateKey } = await generateGroup();
    const apiKey = apiKeyBytes();
    const entry = await wrap(privateKey, apiKey, TENANT, "Default");

    await expect(unwrap(entry, apiKey, TENANT, "default")).rejects.toThrow(VaultDecryptionError);
    await expect(unwrap(entry, apiKey, TENANT, "Default")).resolves.toHaveLength(32);
  });
});

describe("unwrap", () => {
  it("recovers the exact private half", async () => {
    const { privateKey } = await generateGroup();
    const apiKey = apiKeyBytes();

    const recovered = await unwrap(
      await wrap(privateKey, apiKey, TENANT, GROUP),
      apiKey,
      TENANT,
      GROUP,
    );

    expect(Array.from(recovered)).toEqual(Array.from(privateKey));
  });

  it("refuses a different API key", async () => {
    const { privateKey } = await generateGroup();
    const entry = await wrap(privateKey, apiKeyBytes(), TENANT, GROUP);

    await expect(unwrap(entry, apiKeyBytes(), TENANT, GROUP)).rejects.toThrow(VaultDecryptionError);
  });

  it("refuses the right key under a different group — an API key opens its group and nothing else", async () => {
    const { privateKey } = await generateGroup();
    const apiKey = apiKeyBytes();
    const entry = await wrap(privateKey, apiKey, TENANT, GROUP);

    await expect(unwrap(entry, apiKey, TENANT, OTHER_GROUP)).rejects.toThrow(VaultDecryptionError);
  });

  it("refuses the right key under a different tenant", async () => {
    const { privateKey } = await generateGroup();
    const apiKey = apiKeyBytes();
    const entry = await wrap(privateKey, apiKey, TENANT, GROUP);

    await expect(unwrap(entry, apiKey, OTHER_TENANT, GROUP)).rejects.toThrow(VaultDecryptionError);
  });

  it("refuses an entry relabelled with somebody else's key id", async () => {
    const { privateKey } = await generateGroup();
    const apiKey = apiKeyBytes();
    const mine = await wrap(privateKey, apiKey, TENANT, GROUP);
    const theirs = await wrap(privateKey, apiKeyBytes(), TENANT, GROUP);

    // The label moves; the associated data is rebuilt from the key that is
    // actually presented, so a borrowed identity does not open anything.
    await expect(
      unwrap({ keyId: theirs.keyId, wrapped: mine.wrapped }, apiKey, TENANT, GROUP),
    ).resolves.toHaveLength(32);
    await expect(
      unwrap({ keyId: mine.keyId, wrapped: theirs.wrapped }, apiKey, TENANT, GROUP),
    ).rejects.toThrow(VaultDecryptionError);
  });

  it("refuses a flipped bit in the nonce, the ciphertext or the tag", async () => {
    const { privateKey } = await generateGroup();
    const apiKey = apiKeyBytes();
    const entry = await wrap(privateKey, apiKey, TENANT, GROUP);

    for (const index of [0, 20, WRAPPED_PRIVATE_KEY_BYTES - 1]) {
      await expect(unwrap(corrupt(entry, index), apiKey, TENANT, GROUP)).rejects.toThrow(
        VaultDecryptionError,
      );
    }
  });

  it("refuses a truncated or overlong entry without consulting a key", async () => {
    const apiKey = apiKeyBytes();

    for (const length of [0, WRAPPED_PRIVATE_KEY_BYTES - 1, WRAPPED_PRIVATE_KEY_BYTES + 1]) {
      await expect(
        unwrap({ keyId: "0".repeat(32), wrapped: new Uint8Array(length) }, apiKey, TENANT, GROUP),
      ).rejects.toThrow(VaultDecryptionError);
    }
  });

  it("reports every cryptographic failure as the same error, offering no enumeration oracle", async () => {
    const { privateKey } = await generateGroup();
    const apiKey = apiKeyBytes();
    const entry = await wrap(privateKey, apiKey, TENANT, GROUP);

    const messages = await Promise.all(
      [
        unwrap(entry, apiKeyBytes(), TENANT, GROUP),
        unwrap(entry, apiKey, TENANT, OTHER_GROUP),
        unwrap(corrupt(entry, 30), apiKey, TENANT, GROUP),
        unwrap({ keyId: entry.keyId, wrapped: new Uint8Array(3) }, apiKey, TENANT, GROUP),
      ].map((attempt) =>
        attempt.then(
          () => "opened",
          (error: unknown) => (error instanceof Error ? error.message : String(error)),
        ),
      ),
    );

    expect(new Set(messages).size).toBe(1);
  });

  it("rejects a stored key id that is not 32 lowercase hex, loudly", async () => {
    const { privateKey } = await generateGroup();
    const apiKey = apiKeyBytes();
    const entry = await wrap(privateKey, apiKey, TENANT, GROUP);

    // An uppercase id is a *different* string. It never equals a derived id, so
    // before this guard it produced a refusal rather than a corruption report.
    const malformed = [entry.keyId.toUpperCase(), "", "0".repeat(31), `${"0".repeat(32)}0`, "zz"];
    for (const keyId of malformed) {
      await expect(
        unwrap({ keyId, wrapped: entry.wrapped }, apiKey, TENANT, GROUP),
      ).rejects.toThrow(/32 lowercase hex characters/);
    }
  });

  it("corrupt(): guards against an index outside the entry", () => {
    expect(() => corrupt({ keyId: "x", wrapped: new Uint8Array(2) }, 9)).toThrow(RangeError);
  });
});

describe("the key bucket", () => {
  it("lets two different API keys recover the same private half", async () => {
    const { privateKey } = await generateGroup();
    const first = apiKeyBytes();
    const second = apiKeyBytes();

    const bucket = await buildBucket(privateKey, [first, second], TENANT, GROUP);

    expect(bucket).toHaveLength(2);
    expect(bucket[0]?.keyId).not.toBe(bucket[1]?.keyId);
    for (const [index, apiKey] of [first, second].entries()) {
      const entry = bucket[index];
      expect(entry).toBeDefined();
      if (entry === undefined) {
        return;
      }
      expect(Array.from(await unwrap(entry, apiKey, TENANT, GROUP))).toEqual(
        Array.from(privateKey),
      );
    }
  });

  it("refuses to build an empty bucket — a group with no key can never be read again", async () => {
    const { privateKey } = await generateGroup();

    await expect(buildBucket(privateKey, [], TENANT, GROUP)).rejects.toThrow(RangeError);
    await expect(buildBucket(privateKey, [], TENANT, GROUP)).rejects.toThrow(
      /at least one API key/,
    );
  });

  it("rotates: a new K1 wrapped only for the surviving keys", async () => {
    const surviving = apiKeyBytes();
    const removed = apiKeyBytes();
    const rotated = await generateGroup();

    const bucket = await buildBucket(rotated.privateKey, [surviving], TENANT, GROUP);
    const group = groupOf(bucket);

    await expect(findBucketEntry(group, surviving, TENANT)).resolves.toBeDefined();
    await expect(findBucketEntry(group, removed, TENANT)).resolves.toBeUndefined();
  });
});

describe("findBucketEntry", () => {
  it("finds the entry a key can open, wherever it sits in the bucket", async () => {
    const { privateKey } = await generateGroup();
    const keys = [apiKeyBytes(), apiKeyBytes(), apiKeyBytes()];
    const bucket = await buildBucket(privateKey, keys, TENANT, GROUP);
    const group = groupOf(bucket);

    for (const [index, apiKey] of keys.entries()) {
      const found = await findBucketEntry(group, apiKey, TENANT);
      expect(found?.keyId).toBe(bucket[index]?.keyId);
      expect(found).toBeDefined();
      if (found !== undefined) {
        expect(Array.from(await unwrap(found, apiKey, TENANT, GROUP))).toEqual(
          Array.from(privateKey),
        );
      }
    }
  });

  it("returns undefined for a key that is not in the bucket", async () => {
    const { privateKey } = await generateGroup();
    const bucket = await buildBucket(privateKey, [apiKeyBytes()], TENANT, GROUP);

    await expect(findBucketEntry(groupOf(bucket), apiKeyBytes(), TENANT)).resolves.toBeUndefined();
  });

  it("returns undefined for an empty bucket", async () => {
    // Unconstructable through `buildBucket`, but a bundle read off disk can
    // still carry one, and reading must not crash on it.
    await expect(findBucketEntry(groupOf([]), apiKeyBytes(), TENANT)).resolves.toBeUndefined();
  });

  it("does not match a key id derived under a different tenant", async () => {
    const { privateKey } = await generateGroup();
    const apiKey = apiKeyBytes();
    const bucket = await buildBucket(privateKey, [apiKey], TENANT, GROUP);

    await expect(findBucketEntry(groupOf(bucket), apiKey, OTHER_TENANT)).resolves.toBeUndefined();
  });

  it("reports a malformed stored key id as corruption instead of as a miss", async () => {
    const { privateKey } = await generateGroup();
    const apiKey = apiKeyBytes();
    const [entry] = await buildBucket(privateKey, [apiKey], TENANT, GROUP);
    expect(entry).toBeDefined();
    if (entry === undefined) {
      return;
    }

    // The entry IS this key's. Uppercased, it silently never matched.
    const shouted = { keyId: entry.keyId.toUpperCase(), wrapped: entry.wrapped };
    await expect(findBucketEntry(groupOf([shouted]), apiKey, TENANT)).rejects.toThrow(
      /32 lowercase hex characters/,
    );
    await expect(
      findBucketEntry(groupOf([{ keyId: "", wrapped: new Uint8Array(0) }]), apiKey, TENANT),
    ).rejects.toThrow(RangeError);
  });

  it("scans the whole bucket and does not stop early on a hit", async () => {
    const { privateKey } = await generateGroup();
    const keys = [apiKeyBytes(), apiKeyBytes(), apiKeyBytes()];
    const bucket = await buildBucket(privateKey, keys, TENANT, GROUP);
    const last = bucket[bucket.length - 1];
    const first = keys[0];
    expect(last).toBeDefined();
    expect(first).toBeDefined();
    if (last === undefined || first === undefined) {
      return;
    }

    // `adr/0012` requires the scan not to short-circuit. A getter on the last
    // entry proves the loop reaches it even though the first entry matched.
    let lastRead = 0;
    const observed: BucketEntry[] = [
      ...bucket.slice(0, -1),
      {
        get keyId(): string {
          lastRead += 1;
          return last.keyId;
        },
        wrapped: last.wrapped,
      },
    ];

    await expect(findBucketEntry(groupOf(observed), first, TENANT)).resolves.toBeDefined();
    // Once in the validation pass, once in the constant-time scan.
    expect(lastRead).toBe(2);
  });
});

describe("rotateGroup", () => {
  const FIELDS = new Map([
    ["password", "hunter2"],
    ["refresh_token", "rt_0000"],
  ]);

  it("returns a new K1, every field resealed to it, and a rebuilt bucket, as one result", async () => {
    const old = await generateGroup();
    const surviving = apiKeyBytes();
    const fields = await sealFields(old.publicKey, FIELDS);

    const rotation = await rotateGroup(old.privateKey, fields, [surviving], TENANT, GROUP);

    expect(Array.from(rotation.publicKey)).not.toEqual(Array.from(old.publicKey));
    expect(Array.from(rotation.privateKey)).not.toEqual(Array.from(old.privateKey));
    expect(rotation.fields).toHaveLength(2);
    expect(rotation.bucket).toHaveLength(1);

    for (const field of rotation.fields) {
      expect(await openField(field, rotation.privateKey)).toBe(
        FIELDS.get(field.identity.fieldName),
      );
    }
  });

  it("writes nothing: the caller's own fields are untouched", async () => {
    const old = await generateGroup();
    const fields = await sealFields(old.publicKey, FIELDS);
    const before = fields.map((field) => field.envelope);

    await rotateGroup(old.privateKey, fields, [apiKeyBytes()], TENANT, GROUP);

    expect(fields.map((field) => field.envelope)).toEqual(before);
  });

  it("carries each field's identity through unchanged — rotation changes the recipient only", async () => {
    const old = await generateGroup();
    const fields = await sealFields(old.publicKey, FIELDS);

    const rotation = await rotateGroup(old.privateKey, fields, [apiKeyBytes()], TENANT, GROUP);

    expect(rotation.fields.map((field) => field.identity)).toEqual(
      fields.map((field) => field.identity),
    );

    // The AAD still binds that identity, so a resealed envelope moved into
    // another field's slot still fails to open.
    const [resealed] = rotation.fields;
    expect(resealed).toBeDefined();
    if (resealed === undefined) {
      return;
    }
    await expect(
      open(
        resealed.envelope,
        rotation.privateKey,
        fieldAssociatedData(resealed.identity.connectionId, "api_key"),
      ),
    ).rejects.toThrow(VaultDecryptionError);
  });

  it("reseals to envelopes the old private half can no longer open", async () => {
    const old = await generateGroup();
    const fields = await sealFields(old.publicKey, FIELDS);

    const rotation = await rotateGroup(old.privateKey, fields, [apiKeyBytes()], TENANT, GROUP);

    for (const field of rotation.fields) {
      await expect(openField(field, old.privateKey)).rejects.toThrow(VaultDecryptionError);
    }
  });

  it("builds a bucket only the surviving keys can open", async () => {
    const old = await generateGroup();
    const surviving = apiKeyBytes();
    const removed = apiKeyBytes();

    const rotation = await rotateGroup(
      old.privateKey,
      await sealFields(old.publicKey, FIELDS),
      [surviving],
      TENANT,
      GROUP,
    );

    const [entry] = rotation.bucket;
    expect(entry).toBeDefined();
    if (entry === undefined) {
      return;
    }
    expect(Array.from(await unwrap(entry, surviving, TENANT, GROUP))).toEqual(
      Array.from(rotation.privateKey),
    );
    await expect(unwrap(entry, removed, TENANT, GROUP)).rejects.toThrow(VaultDecryptionError);
  });

  it("fails whole when one field cannot be opened — there is no partial result", async () => {
    const old = await generateGroup();
    const stranger = await generateGroup();
    const mine = await sealFields(old.publicKey, new Map([["password", "hunter2"]]));
    const orphan = await sealFields(stranger.publicKey, new Map([["refresh_token", "rt_0000"]]));

    await expect(
      rotateGroup(old.privateKey, [...mine, ...orphan], [apiKeyBytes()], TENANT, GROUP),
    ).rejects.toThrow(VaultDecryptionError);
  });

  it("refuses a rotation that would leave no surviving key", async () => {
    const old = await generateGroup();

    await expect(
      rotateGroup(old.privateKey, await sealFields(old.publicKey, FIELDS), [], TENANT, GROUP),
    ).rejects.toThrow(/at least one API key/);
  });

  it("rotates a group that holds no fields yet", async () => {
    const old = await generateGroup();

    const rotation = await rotateGroup(old.privateKey, [], [apiKeyBytes()], TENANT, GROUP);

    expect(rotation.fields).toEqual([]);
    expect(rotation.bucket).toHaveLength(1);
  });

  it("keeps every key id across the rotation — the salt is the tenant, not the public half", async () => {
    const old = await generateGroup();
    const apiKey = apiKeyBytes();
    const before = await buildBucket(old.privateKey, [apiKey], TENANT, GROUP);

    const rotation = await rotateGroup(
      old.privateKey,
      await sealFields(old.publicKey, FIELDS),
      [apiKey],
      TENANT,
      GROUP,
    );

    expect(rotation.bucket.map((entry) => entry.keyId)).toEqual(before.map((entry) => entry.keyId));
  });
});
