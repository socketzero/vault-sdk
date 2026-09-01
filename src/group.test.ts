import { describe, expect, it } from "vitest";

import {
  buildBucket,
  findBucketEntry,
  generateGroup,
  unwrap,
  WRAPPED_PRIVATE_KEY_BYTES,
  wrap,
} from "./group.js";
import type { BucketEntry, KeyGroup } from "./types.js";
import { VaultDecryptionError } from "./types.js";

const TENANT = "tenant_01JC0000000000000000000000";
const OTHER_TENANT = "tenant_01JC1111111111111111111111";
const GROUP = "default";
const OTHER_GROUP = "staging";

/** A stand-in for the raw 32 bytes `parseApiKey` hands back. */
function apiKeyBytes(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
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
  return { groupId: GROUP, publicKey: new Uint8Array(32), bucket };
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

  it("rejects a private half that is not 32 bytes", async () => {
    await expect(wrap(new Uint8Array(31), apiKeyBytes(), TENANT, GROUP)).rejects.toThrow(
      RangeError,
    );
    await expect(wrap(new Uint8Array(33), apiKeyBytes(), TENANT, GROUP)).rejects.toThrow(
      /a group private half is 32 bytes, got 33/,
    );
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

  it("reports every failure as the same error, offering no enumeration oracle", async () => {
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

  it("builds an empty bucket for no keys", async () => {
    const { privateKey } = await generateGroup();

    await expect(buildBucket(privateKey, [], TENANT, GROUP)).resolves.toEqual([]);
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
    await expect(findBucketEntry(groupOf([]), apiKeyBytes(), TENANT)).resolves.toBeUndefined();
  });

  it("does not match a key id derived under a different tenant", async () => {
    const { privateKey } = await generateGroup();
    const apiKey = apiKeyBytes();
    const bucket = await buildBucket(privateKey, [apiKey], TENANT, GROUP);

    await expect(findBucketEntry(groupOf(bucket), apiKey, OTHER_TENANT)).resolves.toBeUndefined();
  });

  it("ignores a malformed key id rather than throwing", async () => {
    await expect(
      findBucketEntry(groupOf([{ keyId: "", wrapped: new Uint8Array(0) }]), apiKeyBytes(), TENANT),
    ).resolves.toBeUndefined();
  });
});
