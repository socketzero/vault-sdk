import { describe, expect, it, vi } from "vitest";
import { parseApiKey } from "./api-key.js";
import {
  type BootstrapOptions,
  bootstrapKeyGroup,
  CustodyNotAcknowledgedError,
  custodyNotice,
  type KeyGroupRegistrar,
  type RegisteredKeyGroup,
  type RegisterKeyGroupRequest,
  SECOND_KEY_RECOMMENDATION,
  ShownAlreadyError,
  ShowOnce,
} from "./bootstrap.js";
import { base64Decode, base64Encode } from "./encoding.js";
import { derivePublicKey } from "./envelope.js";
import { unwrap } from "./group.js";
import { openRecovery } from "./recovery.js";
import type { ApiKeyMaterial, GroupKeyPair, SealedEnvelope } from "./types.js";
import { asPrivateKey, asPublicKey, requireApiKey, VaultError } from "./types.js";

// Record every keypair and API key the bootstrap mints, so a test can see that
// the copies the SDK held were zeroized. The originals run unchanged.
const minted = vi.hoisted(() => ({
  groups: [] as GroupKeyPair[],
  keys: [] as ApiKeyMaterial[],
}));
vi.mock("./group.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./group.js")>();
  return {
    ...original,
    generateGroup: async () => {
      const pair = await original.generateGroup();
      minted.groups.push(pair);
      return pair;
    },
  };
});
vi.mock("./api-key.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./api-key.js")>();
  return {
    ...original,
    generateApiKey: (environment: Parameters<typeof original.generateApiKey>[0]) => {
      const material = original.generateApiKey(environment);
      minted.keys.push(material);
      return material;
    },
  };
});

const TENANT = "0192f1a0-0000-7000-8000-000000000001";
const RESERVED = "0192f1a0-1111-7abc-8def-0123456789ab";

/**
 * The register route's body, as `socket0-api/src/routes/key-groups.ts` checks
 * it: a strict object, every field by shape, `custody_acknowledged` literally
 * `true`, and the recovery pair together or not at all.
 */
const ALLOWED_FIELDS = new Set([
  "id",
  "name",
  "public_key",
  "key_id",
  "wrapped",
  "label",
  "custody_acknowledged",
  "recovery_public_key",
  "recovery_entry",
]);
function assertRegisterBody(body: RegisterKeyGroupRequest): void {
  const wire = JSON.parse(JSON.stringify(body)) as Record<string, unknown>;
  for (const field of Object.keys(wire)) {
    expect(ALLOWED_FIELDS.has(field), `unexpected field ${field}`).toBe(true);
  }
  expect(wire["id"]).toMatch(
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  );
  expect(wire["name"]).toMatch(/^[a-z][a-z0-9-]{0,30}[a-z0-9]$/);
  expect(wire["public_key"]).toMatch(/^[A-Za-z0-9+/]{43}=$/);
  expect(wire["key_id"]).toMatch(/^[0-9a-f]{32}$/);
  expect(wire["wrapped"]).toMatch(/^[A-Za-z0-9+/]{60,}={0,2}$/);
  expect(wire["custody_acknowledged"]).toBe(true);
  expect("recovery_public_key" in wire).toBe("recovery_entry" in wire);
  if ("recovery_public_key" in wire) {
    expect(wire["recovery_public_key"]).toMatch(/^[A-Za-z0-9+/]{43}=$/);
  }
}

interface FakeApi extends KeyGroupRegistrar {
  readonly calls: string[];
  readonly bodies: RegisterKeyGroupRequest[];
}

function fakeApi(overrides: Partial<KeyGroupRegistrar> = {}): FakeApi {
  const calls: string[] = [];
  const bodies: RegisterKeyGroupRequest[] = [];
  return {
    calls,
    bodies,
    reserveKeyGroupId: async (tenantId) => {
      calls.push(`reserve:${tenantId}`);
      return overrides.reserveKeyGroupId
        ? overrides.reserveKeyGroupId(tenantId)
        : { id: RESERVED, expiresAt: 1_900_000_000 };
    },
    registerKeyGroup: async (tenantId, body) => {
      calls.push(`register:${tenantId}`);
      assertRegisterBody(body);
      bodies.push(body);
      if (overrides.registerKeyGroup) {
        return overrides.registerKeyGroup(tenantId, body);
      }
      const group: RegisteredKeyGroup = {
        id: body.id,
        name: body.name,
        public_key: body.public_key,
        generation: 0,
        created_at: 1_800_000_000,
        purpose: "tenant",
        keys: [
          {
            key_id: body.key_id,
            label: body.label ?? null,
            created_at: 1_800_000_000,
            kind: "tenant",
          },
        ],
        recovery_public_key: body.recovery_public_key ?? null,
        has_recovery: body.recovery_entry !== undefined,
      };
      return group;
    },
  };
}

function options(
  registrar: KeyGroupRegistrar,
  extra: Partial<BootstrapOptions> = {},
): BootstrapOptions {
  return {
    registrar,
    tenantId: TENANT,
    environment: "live",
    recoveryPhrase: false,
    acknowledgeCustody: () => true,
    ...extra,
  };
}

function allZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

describe("bootstrapKeyGroup", () => {
  it("registers a group whose first bucket entry opens to K1 with the key it returns once", async () => {
    const api = fakeApi();
    const result = await bootstrapKeyGroup(options(api));

    const [body] = api.bodies;
    expect(body).toBeDefined();
    if (body === undefined) return;
    expect(body.id).toBe(RESERVED);
    expect(body.name).toBe("default");
    expect(result.group.id).toBe(RESERVED);

    const display = result.apiKey.reveal();
    const material = requireApiKey(parseApiKey(display));
    expect(material.environment).toBe("live");

    const k1 = await unwrap(
      { keyId: body.key_id, wrapped: base64Decode(body.wrapped) },
      material.bytes,
      TENANT,
      RESERVED,
    );
    expect(base64Encode(await derivePublicKey(k1))).toBe(body.public_key);
  });

  it("reserves, then wraps, then registers — all after custody is acknowledged", async () => {
    const order: string[] = [];
    const api = fakeApi();
    await bootstrapKeyGroup(
      options(api, {
        acknowledgeCustody: () => {
          order.push("acknowledge");
          return true;
        },
      }),
    );
    expect([...order, ...api.calls]).toEqual([
      "acknowledge",
      `reserve:${TENANT}`,
      `register:${TENANT}`,
    ]);
  });

  it("passes the group name, the label and the environment through", async () => {
    const api = fakeApi();
    const result = await bootstrapKeyGroup(
      options(api, { name: "staging", label: "laptop", environment: "test" }),
    );
    expect(api.bodies[0]?.name).toBe("staging");
    expect(api.bodies[0]?.label).toBe("laptop");
    expect(result.apiKey.reveal()).toMatch(/^sk0_test_/);
  });

  it("sends no label field at all when none is given", async () => {
    const api = fakeApi();
    await bootstrapKeyGroup(options(api));
    expect(api.bodies[0] !== undefined && "label" in api.bodies[0]).toBe(false);
  });

  it("refuses to register without an acknowledgement, and reserves nothing", async () => {
    const api = fakeApi();
    await expect(
      bootstrapKeyGroup(options(api, { acknowledgeCustody: () => false })),
    ).rejects.toBeInstanceOf(CustodyNotAcknowledgedError);
    expect(api.calls).toEqual([]);
  });

  it("treats only `true` as an acknowledgement, never a truthy value", async () => {
    const api = fakeApi();
    const truthy = (() => "yes") as unknown as BootstrapOptions["acknowledgeCustody"];
    await expect(
      bootstrapKeyGroup(options(api, { acknowledgeCustody: truthy })),
    ).rejects.toBeInstanceOf(CustodyNotAcknowledgedError);
    expect(api.calls).toEqual([]);
  });

  it("shows the custodian notice that matches the recovery choice", async () => {
    const seen: { text: string; recoveryPhrase: boolean }[] = [];
    for (const recoveryPhrase of [false, true]) {
      await bootstrapKeyGroup(
        options(fakeApi(), {
          recoveryPhrase,
          acknowledgeCustody: (notice) => {
            seen.push(notice);
            return true;
          },
        }),
      );
    }
    expect(seen).toEqual([
      { text: custodyNotice(false), recoveryPhrase: false },
      { text: custodyNotice(true), recoveryPhrase: true },
    ]);
  });

  it("registers K0 and a recovery entry that opens to K1 when a phrase is chosen", async () => {
    const api = fakeApi();
    const result = await bootstrapKeyGroup(options(api, { recoveryPhrase: true }));
    const body = api.bodies[0];
    expect(body?.recovery_public_key).toBeDefined();
    expect(body?.recovery_entry).toBeDefined();
    expect(result.recoveryKey).toBeDefined();
    if (body?.recovery_entry === undefined || body.recovery_public_key === undefined) return;
    if (result.recoveryKey === undefined) return;

    const k0 = result.recoveryKey.reveal();
    expect(base64Encode(await derivePublicKey(k0))).toBe(body.recovery_public_key);
    const k1 = await openRecovery(
      body.recovery_entry as SealedEnvelope,
      k0,
      RESERVED,
      asPublicKey(base64Decode(body.public_key)),
    );
    expect(base64Encode(await derivePublicKey(k1))).toBe(body.public_key);
  });

  it("registers no recovery fields and returns no recovery key when the phrase is declined", async () => {
    const api = fakeApi();
    const result = await bootstrapKeyGroup(options(api));
    expect(api.bodies[0] !== undefined && "recovery_public_key" in api.bodies[0]).toBe(false);
    expect(api.bodies[0] !== undefined && "recovery_entry" in api.bodies[0]).toBe(false);
    expect(result.recoveryKey).toBeUndefined();
  });

  it("offers a second key in the same result", async () => {
    const result = await bootstrapKeyGroup(options(fakeApi()));
    expect(result.recommendation).toBe(SECOND_KEY_RECOMMENDATION);
  });

  it("refuses a reserved id that is not a canonical lowercase UUIDv7, before wrapping against it", async () => {
    for (const id of [
      RESERVED.toUpperCase(),
      "not-a-uuid",
      `${RESERVED} `,
      "0192f1a0-1111-4abc-8def-0123456789ab",
    ]) {
      const api = fakeApi({ reserveKeyGroupId: async () => ({ id, expiresAt: 1 }) });
      await expect(bootstrapKeyGroup(options(api))).rejects.toBeInstanceOf(VaultError);
      expect(api.calls).toEqual([`reserve:${TENANT}`]);
    }
  });

  it("refuses a registration answer that names another group or another public half", async () => {
    for (const lie of [
      { id: "0192f1a0-2222-7abc-8def-0123456789ab" },
      { public_key: `${"A".repeat(43)}=` },
    ]) {
      const api = fakeApi({
        registerKeyGroup: async (_tenant, body) => ({
          id: body.id,
          name: body.name,
          public_key: body.public_key,
          generation: 0,
          created_at: 0,
          purpose: "tenant",
          keys: [],
          recovery_public_key: null,
          has_recovery: false,
          ...lie,
        }),
      });
      await expect(bootstrapKeyGroup(options(api))).rejects.toBeInstanceOf(VaultError);
    }
  });

  it("zeroizes K1 and K2 once wrapped, and K0 once revealed", async () => {
    minted.groups.length = 0;
    minted.keys.length = 0;
    const result = await bootstrapKeyGroup(options(fakeApi(), { recoveryPhrase: true }));
    const [k1, k0] = minted.groups;
    const [k2] = minted.keys;
    expect(k1 && allZero(k1.privateKey)).toBe(true);
    expect(k2 && allZero(k2.bytes)).toBe(true);
    // K0 is the tenant's to write down, so it survives until it is shown.
    expect(k0 && allZero(k0.privateKey)).toBe(false);
    result.recoveryKey?.reveal();
    expect(k0 && allZero(k0.privateKey)).toBe(true);
  });

  it("zeroizes every secret when registration fails", async () => {
    minted.groups.length = 0;
    minted.keys.length = 0;
    const failure = new Error("409");
    const api = fakeApi({
      registerKeyGroup: async () => {
        throw failure;
      },
    });
    await expect(bootstrapKeyGroup(options(api, { recoveryPhrase: true }))).rejects.toBe(failure);
    for (const pair of minted.groups) expect(allZero(pair.privateKey)).toBe(true);
    for (const key of minted.keys) expect(allZero(key.bytes)).toBe(true);
  });

  it("zeroizes every secret when custody is not acknowledged", async () => {
    minted.groups.length = 0;
    minted.keys.length = 0;
    await expect(
      bootstrapKeyGroup(
        options(fakeApi(), { recoveryPhrase: true, acknowledgeCustody: async () => false }),
      ),
    ).rejects.toBeInstanceOf(CustodyNotAcknowledgedError);
    expect(minted.groups).toHaveLength(2);
    for (const pair of minted.groups) expect(allZero(pair.privateKey)).toBe(true);
    for (const key of minted.keys) expect(allZero(key.bytes)).toBe(true);
  });
});

describe("custodyNotice", () => {
  it("names the tenant as custodian and states the permanent loss, in both variants", () => {
    for (const recoveryPhrase of [false, true]) {
      const text = custodyNotice(recoveryPhrase);
      expect(text).toMatch(/yours/i);
      expect(text).toMatch(/permanently unreadable/);
      expect(text).toMatch(/no copy/i);
      expect(text).not.toMatch(/replaceable/i);
    }
  });

  it("states which recovery choice the tenant made", () => {
    expect(custodyNotice(true)).toMatch(/recovery phrase/);
    expect(custodyNotice(false)).toMatch(/no recovery phrase/);
    expect(custodyNotice(true)).not.toMatch(/no recovery phrase/);
  });
});

describe("ShowOnce", () => {
  it("reveals once, wipes its buffer, and refuses a second reveal", () => {
    const secret = new Uint8Array([1, 2, 3]);
    const once = new ShowOnce(secret, (bytes) => Array.from(bytes));
    expect(once.shown).toBe(false);
    expect(once.reveal()).toEqual([1, 2, 3]);
    expect(allZero(secret)).toBe(true);
    expect(once.shown).toBe(true);
    expect(() => once.reveal()).toThrow(ShownAlreadyError);
  });

  it("can be discarded unrevealed, which wipes it and closes it", () => {
    const secret = new Uint8Array([9, 9]);
    const once = new ShowOnce(secret, (bytes) =>
      asPrivateKey(new Uint8Array(32).fill(bytes[0] ?? 0)),
    );
    once.discard();
    expect(allZero(secret)).toBe(true);
    expect(() => once.reveal()).toThrow(ShownAlreadyError);
    once.discard();
  });
});
