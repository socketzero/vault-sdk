import { describe, expect, it } from "vitest";
import type { RegisteredKeyGroup, RegisterKeyGroupRequest } from "./bootstrap.js";
import { httpKeyGroupRegistrar, KeyGroupRegistrarError } from "./registrar-http.js";
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
  keys: [],
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
    for (const payload of [
      { ...GROUP, id: 7 },
      { ...GROUP, public_key: undefined },
    ]) {
      const { fetch } = fakeFetch(201, payload);
      const registrar = httpKeyGroupRegistrar({
        baseUrl: "https://api.example/v1",
        accessToken: "t",
        fetch,
      });
      await expect(registrar.registerKeyGroup(TENANT, BODY)).rejects.toBeInstanceOf(
        KeyGroupRegistrarError,
      );
    }
  });
});
