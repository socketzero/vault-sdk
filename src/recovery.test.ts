import { describe, expect, it } from "vitest";
import {
  derivePublicKey,
  fieldAssociatedData,
  open,
  recoveryAssociatedData,
  seal,
} from "./envelope.js";
import { generateGroup, rotateGroup } from "./group.js";
import { openRecovery, sealRecovery } from "./recovery.js";
import type { ApiKeyBytes, PrivateKey, PublicKey, SealedField } from "./types.js";
import { asApiKeyBytes, VaultDecryptionError } from "./types.js";

const TENANT = "tenant_01JC0000000000000000000000";
const GROUP = "default";
const OTHER_GROUP = "staging";
const CONNECTION = new Uint8Array(16).fill(7);

function apiKeyBytes(): ApiKeyBytes {
  return asApiKeyBytes(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

function bytes(key: PrivateKey | PublicKey): number[] {
  return Array.from(key);
}

async function sealedField(publicKey: PublicKey, value: string): Promise<SealedField> {
  const aad = fieldAssociatedData(CONNECTION, "password");
  return {
    identity: { connectionUuid: CONNECTION, fieldName: "password" },
    envelope: await seal(new TextEncoder().encode(value), publicKey, aad),
  };
}

describe("recoveryAssociatedData", () => {
  it("binds the group id and the K1 public half, so either changing gives different bytes", async () => {
    const k1 = await generateGroup();
    const other = await generateGroup();
    const base = recoveryAssociatedData(GROUP, k1.publicKey);

    expect(Array.from(recoveryAssociatedData(GROUP, k1.publicKey))).toEqual(Array.from(base));
    expect(Array.from(recoveryAssociatedData(OTHER_GROUP, k1.publicKey))).not.toEqual(
      Array.from(base),
    );
    expect(Array.from(recoveryAssociatedData(GROUP, other.publicKey))).not.toEqual(
      Array.from(base),
    );
  });

  it('is the length-prefixed AAD(group_id, "recovery", k1_public)', async () => {
    const k1 = await generateGroup();
    const aad = recoveryAssociatedData(GROUP, k1.publicKey);
    const view = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);

    expect(view.getUint32(0, false)).toBe(GROUP.length);
    expect(new TextDecoder().decode(aad.subarray(4, 4 + GROUP.length))).toBe(GROUP);
    const second = 4 + GROUP.length;
    expect(view.getUint32(second, false)).toBe("recovery".length);
    expect(new TextDecoder().decode(aad.subarray(second + 4, second + 12))).toBe("recovery");
    const third = second + 12;
    expect(view.getUint32(third, false)).toBe(32);
    expect(Array.from(aad.subarray(third + 4))).toEqual(bytes(k1.publicKey));
  });
});

describe("sealRecovery / openRecovery", () => {
  it("round-trips K1's private half through K0", async () => {
    const k0 = await generateGroup();
    const k1 = await generateGroup();

    const entry = await sealRecovery(k1.privateKey, k0.publicKey, GROUP);
    const recovered = await openRecovery(entry, k0.privateKey, GROUP, k1.publicKey);

    expect(bytes(recovered)).toEqual(bytes(k1.privateKey));
  });

  it("needs only K0's public half to seal — the phrase is never required to write an entry", async () => {
    const k0 = await generateGroup();
    const k1 = await generateGroup();
    // The signature is the proof: no private K0 goes in.
    const entry = await sealRecovery(k1.privateKey, k0.publicKey, GROUP);
    expect(entry.startsWith(`${entry.split(":")[0]}:`)).toBe(true);
  });

  it("refuses the wrong K0", async () => {
    const k0 = await generateGroup();
    const wrongK0 = await generateGroup();
    const k1 = await generateGroup();
    const entry = await sealRecovery(k1.privateKey, k0.publicKey, GROUP);

    await expect(
      openRecovery(entry, wrongK0.privateKey, GROUP, k1.publicKey),
    ).rejects.toBeInstanceOf(VaultDecryptionError);
  });

  it("refuses an entry moved to another group", async () => {
    const k0 = await generateGroup();
    const k1 = await generateGroup();
    const entry = await sealRecovery(k1.privateKey, k0.publicKey, GROUP);

    await expect(
      openRecovery(entry, k0.privateKey, OTHER_GROUP, k1.publicKey),
    ).rejects.toBeInstanceOf(VaultDecryptionError);
  });

  it("refuses an entry replayed against another generation's public half", async () => {
    const k0 = await generateGroup();
    const oldK1 = await generateGroup();
    const newK1 = await generateGroup();
    const oldEntry = await sealRecovery(oldK1.privateKey, k0.publicKey, GROUP);

    await expect(
      openRecovery(oldEntry, k0.privateKey, GROUP, newK1.publicKey),
    ).rejects.toBeInstanceOf(VaultDecryptionError);
  });
});

describe("openRecovery against a forged entry", () => {
  it("refuses a payload that is not a 32-byte private half, sealed under the right binding", async () => {
    const k0 = await generateGroup();
    const k1 = await generateGroup();
    const forged = await seal(
      new Uint8Array(16),
      k0.publicKey,
      recoveryAssociatedData(GROUP, k1.publicKey),
    );

    await expect(openRecovery(forged, k0.privateKey, GROUP, k1.publicKey)).rejects.toBeInstanceOf(
      VaultDecryptionError,
    );
  });

  it("refuses another private half sealed under this generation's binding", async () => {
    const k0 = await generateGroup();
    const k1 = await generateGroup();
    const impostor = await generateGroup();
    const forged = await seal(
      impostor.privateKey,
      k0.publicKey,
      recoveryAssociatedData(GROUP, k1.publicKey),
    );

    await expect(openRecovery(forged, k0.privateKey, GROUP, k1.publicKey)).rejects.toBeInstanceOf(
      VaultDecryptionError,
    );
  });
});

describe("rotateGroup with a recovery key", () => {
  it("returns a recovery entry for the new K1 when K0's public half is given", async () => {
    const k0 = await generateGroup();
    const old = await generateGroup();
    const fields = [await sealedField(old.publicKey, "hunter2")];

    const rotation = await rotateGroup(
      old.privateKey,
      fields,
      [apiKeyBytes()],
      TENANT,
      GROUP,
      k0.publicKey,
    );

    expect(rotation.recovery).toBeDefined();
    const recovered = await openRecovery(
      rotation.recovery as NonNullable<typeof rotation.recovery>,
      k0.privateKey,
      GROUP,
      rotation.publicKey,
    );
    expect(bytes(recovered)).toEqual(bytes(rotation.privateKey));
  });

  it("returns no recovery entry when K0 is not given", async () => {
    const old = await generateGroup();
    const rotation = await rotateGroup(old.privateKey, [], [apiKeyBytes()], TENANT, GROUP);
    expect(rotation.recovery).toBeUndefined();
  });

  it("the phrase survives the rotation: K0 opens every field of the new generation", async () => {
    const k0 = await generateGroup();
    const old = await generateGroup();
    const fields = [await sealedField(old.publicKey, "hunter2")];

    const rotation = await rotateGroup(
      old.privateKey,
      fields,
      [apiKeyBytes()],
      TENANT,
      GROUP,
      k0.publicKey,
    );
    const k1 = await openRecovery(
      rotation.recovery as NonNullable<typeof rotation.recovery>,
      k0.privateKey,
      GROUP,
      await derivePublicKey(rotation.privateKey),
    );
    const field = rotation.fields[0] as SealedField;
    const plaintext = await open(field.envelope, k1, fieldAssociatedData(CONNECTION, "password"));

    expect(new TextDecoder().decode(plaintext)).toBe("hunter2");
  });

  it("refuses an empty bucket even with a recovery key — K0 is not a key in the bucket", async () => {
    const k0 = await generateGroup();
    const old = await generateGroup();
    await expect(
      rotateGroup(old.privateKey, [], [], TENANT, GROUP, k0.publicKey),
    ).rejects.toBeInstanceOf(RangeError);
  });
});
