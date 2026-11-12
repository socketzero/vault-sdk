import { describe, expect, it } from "vitest";
import type { RegisteredKeyGroup, RegisterKeyGroupRequest } from "./bootstrap.js";
import {
  httpKeyGroupRegistrar,
  httpKeyGroupRotator,
  KeyGroupRegistrarError,
  KeyGroupRegistrarResponseError,
} from "./registrar-http.js";
import { VaultError } from "./types.js";

const TENANT = "0192f1a0-0000-7000-8000-000000000001";

interface Recorded {
  readonly url: string;
  readonly init: RequestInit | undefined;
}

function fakeFetch(
  status: number,
  payload: unknown,
): { fetch: typeof globalThis.fetch; seen: Recorded[] } {
  const seen: Recorded[] = [];
  const fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    seen.push({ url: String(input), init });
    return new Response(typeof payload === "string" ? payload : JSON.stringify(payload), {
      status,
      headers: { "content-type": "application/json" },
    });
  }) as typeof globalThis.fetch;
  return { fetch, seen };
}

const GROUP: RegisteredKeyGroup = {
  id: "0192f1a0-1111-7abc-8def-0123456789ab",
  name: "default",
  public_key: `${"A".repeat(43)}=`,
  generation: 0,
  created_at: 1,
  purpose: "tenant",
  keys: [{ key_id: "0".repeat(32), label: null, created_at: 1, kind: "tenant" }],
  recovery_public_key: null,
  has_recovery: false,
};

const BODY: RegisterKeyGroupRequest = {
  id: GROUP.id,
  name: "default",
  public_key: GROUP.public_key,
  key_id: "0".repeat(32),
  wrapped: "B".repeat(80),
  custody_acknowledged: true,
};

describe("httpKeyGroupRegistrar", () => {
  it("reserves with a bearer-authenticated POST to the tenant's key-group-ids", async () => {
    const { fetch, seen } = fakeFetch(201, { id: GROUP.id, expires_at: 99 });
    const registrar = httpKeyGroupRegistrar({
      baseUrl: "https://api.example/v1/",
      accessToken: "tok",
      fetch,
    });
    expect(await registrar.reserveKeyGroupId(TENANT)).toEqual({ id: GROUP.id, expiresAt: 99 });
    expect(seen).toHaveLength(1);
    expect(seen[0]?.url).toBe(`https://api.example/v1/tenants/${TENANT}/key-group-ids`);
    expect(seen[0]?.init?.method).toBe("POST");
    expect(new Headers(seen[0]?.init?.headers).get("authorization")).toBe("Bearer tok");
  });

  it("registers by POSTing the body as JSON and returns the stored group", async () => {
    const { fetch, seen } = fakeFetch(201, GROUP);
    const registrar = httpKeyGroupRegistrar({
      baseUrl: "https://api.example/v1",
      accessToken: async () => "fresh",
      fetch,
    });
    expect(await registrar.registerKeyGroup(TENANT, BODY)).toEqual(GROUP);
    expect(seen[0]?.url).toBe(`https://api.example/v1/tenants/${TENANT}/key-groups`);
    expect(seen[0]?.init?.method).toBe("POST");
    const headers = new Headers(seen[0]?.init?.headers);
    expect(headers.get("authorization")).toBe("Bearer fresh");
    expect(headers.get("content-type")).toBe("application/json");
    expect(JSON.parse(String(seen[0]?.init?.body))).toEqual(BODY);
  });

  it("escapes the tenant id in the path", async () => {
    const { fetch, seen } = fakeFetch(201, { id: GROUP.id, expires_at: 1 });
    await httpKeyGroupRegistrar({
      baseUrl: "https://api.example/v1",
      accessToken: "t",
      fetch,
    }).reserveKeyGroupId("a/b");
    expect(seen[0]?.url).toBe("https://api.example/v1/tenants/a%2Fb/key-group-ids");
  });

  it("turns a refusal into a KeyGroupRegistrarError carrying the status and the API's error", async () => {
    for (const [status, payload, message] of [
      [410, { error: "reservation expired" }, "reservation expired"],
      [409, { error: "conflict" }, "conflict"],
      [500, "not json", undefined],
      [403, { message: "nope" }, undefined],
    ] as const) {
      const { fetch } = fakeFetch(status, payload);
      const registrar = httpKeyGroupRegistrar({
        baseUrl: "https://api.example/v1",
        accessToken: "t",
        fetch,
      });
      const error = await registrar
        .registerKeyGroup(TENANT, BODY)
        .catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(KeyGroupRegistrarError);
      expect(error).toBeInstanceOf(VaultError);
      expect((error as KeyGroupRegistrarError).status).toBe(status);
      expect((error as KeyGroupRegistrarError).apiError).toBe(message);
    }
  });

  it("treats any status but 201 as a refusal", async () => {
    const { fetch } = fakeFetch(200, { id: GROUP.id, expires_at: 1 });
    const registrar = httpKeyGroupRegistrar({
      baseUrl: "https://api.example/v1",
      accessToken: "t",
      fetch,
    });
    await expect(registrar.reserveKeyGroupId(TENANT)).rejects.toBeInstanceOf(
      KeyGroupRegistrarError,
    );
  });

  it("refuses a 201 whose body is not the declared shape", async () => {
    for (const payload of [{ id: 1, expires_at: 1 }, { id: GROUP.id }, null, "[]"]) {
      const { fetch } = fakeFetch(201, payload);
      const registrar = httpKeyGroupRegistrar({
        baseUrl: "https://api.example/v1",
        accessToken: "t",
        fetch,
      });
      await expect(registrar.reserveKeyGroupId(TENANT)).rejects.toBeInstanceOf(
        KeyGroupRegistrarError,
      );
    }
  });

  it("refuses a register 201 that is not the full KeyGroup shape, as an unreadable success", async () => {
    const entry = GROUP.keys[0];
    const malformed: unknown[] = [
      null,
      [],
      { ...GROUP, id: 7 },
      { ...GROUP, name: undefined },
      { ...GROUP, public_key: undefined },
      { ...GROUP, generation: "0" },
      { ...GROUP, generation: 0.5 },
      { ...GROUP, created_at: "1" },
      { ...GROUP, purpose: "other" },
      { ...GROUP, keys: undefined },
      { ...GROUP, keys: [null] },
      { ...GROUP, keys: [{ ...entry, key_id: 1 }] },
      { ...GROUP, keys: [{ ...entry, label: 1 }] },
      { ...GROUP, keys: [{ ...entry, label: undefined }] },
      { ...GROUP, keys: [{ ...entry, created_at: "1" }] },
      { ...GROUP, keys: [{ ...entry, kind: "admin" }] },
      { ...GROUP, recovery_public_key: undefined },
      { ...GROUP, recovery_public_key: 1 },
      { ...GROUP, has_recovery: "no" },
    ];
    for (const payload of malformed) {
      const { fetch } = fakeFetch(201, payload);
      const registrar = httpKeyGroupRegistrar({
        baseUrl: "https://api.example/v1",
        accessToken: "t",
        fetch,
      });
      const error = await registrar
        .registerKeyGroup(TENANT, BODY)
        .catch((caught: unknown) => caught);
      expect(error, JSON.stringify(payload)).toBeInstanceOf(KeyGroupRegistrarResponseError);
      expect((error as KeyGroupRegistrarError).refused).toBe(false);
    }
  });

  it("accepts every legal variant of the KeyGroup shape and returns only its declared fields", async () => {
    const variants: RegisteredKeyGroup[] = [
      { ...GROUP, purpose: "broker", keys: [] },
      {
        ...GROUP,
        recovery_public_key: `${"C".repeat(43)}=`,
        has_recovery: true,
        keys: [
          { key_id: "1".repeat(32), label: "laptop", created_at: 2, kind: "service" },
          { key_id: "2".repeat(32), label: null, created_at: 3, kind: "tenant" },
        ],
      },
    ];
    for (const group of variants) {
      const { fetch } = fakeFetch(201, { ...group, extra: "ignored" });
      const registrar = httpKeyGroupRegistrar({
        baseUrl: "https://api.example/v1",
        accessToken: "t",
        fetch,
      });
      expect(await registrar.registerKeyGroup(TENANT, BODY)).toEqual(group);
    }
  });

  it("classifies only a 4xx as a definitive refusal", async () => {
    for (const [status, refused] of [
      [400, true],
      [409, true],
      [410, true],
      [499, true],
      [399, false],
      [500, false],
      [200, false],
    ] as const) {
      expect(new KeyGroupRegistrarError(status, undefined, "x").refused, String(status)).toBe(
        refused,
      );
    }
    expect(new KeyGroupRegistrarResponseError("key-groups", 201).status).toBe(201);
  });

  it("calls fetch detached from the options object, as a browser's native fetch requires", async () => {
    const { fetch: inner, seen } = fakeFetch(201, { id: GROUP.id, expires_at: 1 });
    // A native fetch throws `TypeError: Illegal invocation` for any `this` but
    // the global object or undefined.
    const strictFetch = function (
      this: unknown,
      input: string | URL | Request,
      init?: RequestInit,
    ) {
      if (this !== undefined && this !== globalThis) {
        throw new TypeError("Illegal invocation");
      }
      return inner(input, init);
    } as typeof globalThis.fetch;
    const registrar = httpKeyGroupRegistrar({
      baseUrl: "https://api.example/v1",
      accessToken: "t",
      fetch: strictFetch,
    });
    await registrar.reserveKeyGroupId(TENANT);
    expect(seen).toHaveLength(1);
  });

  it("passes the caller's signal to fetch, and sends none when not given one", async () => {
    const controller = new AbortController();
    const { fetch, seen } = fakeFetch(201, GROUP);
    const registrar = httpKeyGroupRegistrar({
      baseUrl: "https://api.example/v1",
      accessToken: "t",
      fetch,
    });
    await registrar.registerKeyGroup(TENANT, BODY, controller.signal);
    await registrar.registerKeyGroup(TENANT, BODY);
    expect(seen[0]?.init?.signal).toBe(controller.signal);
    expect(seen[1]?.init !== undefined && "signal" in seen[1].init).toBe(false);
  });
});

describe("httpKeyGroupRotator", () => {
  const GROUP_ID = GROUP.id;
  const MATERIAL = {
    id: GROUP_ID,
    generation: 2,
    public_key: GROUP.public_key,
    recovery_public_key: null,
    keys: [{ key_id: "0".repeat(32), wrapped: "B".repeat(80), label: null, created_at: 1 }],
    connections: [{ id: "c", version: 1, sealed: { password: "x25519-hkdf-aesgcm:AAAA" } }],
    auth_apps: [{ id: "a", sealed_client_secret: "x25519-hkdf-aesgcm:AAAA" }],
    challenge: { id: "ch", sealed_nonce: "x25519-hkdf-aesgcm:AAAA", expires_at: 300 },
  };
  const COMMIT = {
    expected_generation: 2,
    public_key: GROUP.public_key,
    keys: [{ key_id: "0".repeat(32), wrapped: "B".repeat(80) }],
    connections: [],
    auth_apps: [],
    challenge_id: "ch",
    challenge_proof: "A".repeat(43) + "=",
  };

  it("fetches the group's rotation material with a bearer-authenticated GET", async () => {
    const { fetch, seen } = fakeFetch(200, MATERIAL);
    const rotator = httpKeyGroupRotator({
      baseUrl: "https://api.example/v1",
      accessToken: "tok",
      fetch,
    });
    expect(await rotator.fetchRotation(TENANT, GROUP_ID)).toEqual(MATERIAL);
    expect(seen[0]?.url).toBe(
      `https://api.example/v1/tenants/${TENANT}/key-groups/${GROUP_ID}/rotation`,
    );
    expect(seen[0]?.init?.method).toBe("GET");
    expect(seen[0]?.init?.body).toBeUndefined();
    expect(new Headers(seen[0]?.init?.headers).get("authorization")).toBe("Bearer tok");
  });

  it("commits with a JSON POST and returns the rotated group", async () => {
    const { fetch, seen } = fakeFetch(200, { ...GROUP, generation: 3 });
    const rotator = httpKeyGroupRotator({
      baseUrl: "https://api.example/v1",
      accessToken: "tok",
      fetch,
    });
    const controller = new AbortController();
    expect(
      (await rotator.commitRotation(TENANT, GROUP_ID, COMMIT, controller.signal)).generation,
    ).toBe(3);
    expect(seen[0]?.init?.method).toBe("POST");
    expect(JSON.parse(seen[0]?.init?.body as string)).toEqual(COMMIT);
    expect(seen[0]?.init?.signal).toBe(controller.signal);
  });

  it("surfaces a 403's reason on the error: the proof of possession was refused", async () => {
    const { fetch } = fakeFetch(403, { error: "proof required" });
    const rotator = httpKeyGroupRotator({
      baseUrl: "https://api.example/v1",
      accessToken: "tok",
      fetch,
    });
    const err = await rotator.commitRotation(TENANT, GROUP_ID, COMMIT).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(KeyGroupRegistrarError);
    expect((err as KeyGroupRegistrarError).status).toBe(403);
    expect((err as KeyGroupRegistrarError).apiError).toBe("proof required");
  });

  it("surfaces a 409's reason on the error", async () => {
    const { fetch } = fakeFetch(409, { error: "stale" });
    const rotator = httpKeyGroupRotator({
      baseUrl: "https://api.example/v1",
      accessToken: "tok",
      fetch,
    });
    const err = await rotator.commitRotation(TENANT, GROUP_ID, COMMIT).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(KeyGroupRegistrarError);
    expect((err as KeyGroupRegistrarError).status).toBe(409);
    expect((err as KeyGroupRegistrarError).apiError).toBe("stale");
  });

  it.each([
    ["not an object", []],
    ["a missing generation", { ...MATERIAL, generation: undefined }],
    ["a numeric recovery key", { ...MATERIAL, recovery_public_key: 1 }],
    ["keys that are not an array", { ...MATERIAL, keys: {} }],
    ["a key without created_at", { ...MATERIAL, keys: [{ ...MATERIAL.keys[0], created_at: "1" }] }],
    ["a key with a numeric label", { ...MATERIAL, keys: [{ ...MATERIAL.keys[0], label: 1 }] }],
    [
      "a connection with a non-string seal",
      { ...MATERIAL, connections: [{ id: "c", version: 1, sealed: { p: 1 } }] },
    ],
    ["a connection without sealed", { ...MATERIAL, connections: [{ id: "c", version: 1 }] }],
    ["an app that is not an object", { ...MATERIAL, auth_apps: ["a"] }],
    ["an app without its copy", { ...MATERIAL, auth_apps: [{ id: "a" }] }],
    ["no challenge", { ...MATERIAL, challenge: undefined }],
    ["a challenge that is not an object", { ...MATERIAL, challenge: "ch" }],
    ["a challenge without an id", { ...MATERIAL, challenge: { ...MATERIAL.challenge, id: 1 } }],
    [
      "a challenge without its nonce",
      { ...MATERIAL, challenge: { ...MATERIAL.challenge, sealed_nonce: undefined } },
    ],
    [
      "a challenge with a fractional expiry",
      { ...MATERIAL, challenge: { ...MATERIAL.challenge, expires_at: 1.5 } },
    ],
  ])("refuses fetched material with %s", async (_what, body) => {
    const { fetch } = fakeFetch(200, body);
    const rotator = httpKeyGroupRotator({
      baseUrl: "https://api.example/v1",
      accessToken: "tok",
      fetch,
    });
    await expect(rotator.fetchRotation(TENANT, GROUP_ID)).rejects.toBeInstanceOf(
      KeyGroupRegistrarResponseError,
    );
  });

  it("refuses a 200 commit whose body is not a KeyGroup", async () => {
    const { fetch } = fakeFetch(200, { ok: true });
    const rotator = httpKeyGroupRotator({
      baseUrl: "https://api.example/v1",
      accessToken: "tok",
      fetch,
    });
    await expect(rotator.commitRotation(TENANT, GROUP_ID, COMMIT)).rejects.toBeInstanceOf(
      KeyGroupRegistrarResponseError,
    );
  });
});
