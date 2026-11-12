/**
 * The stock `KeyGroupRegistrar`: socket0-api's two key-group routes over
 * `fetch`, authenticated as a person with a bearer access token.
 *
 * Never with an API key. The API key is the key-encryption key, and these
 * routes take a JWT precisely so that no control-plane component ever holds one
 * (`socket0-api/src/routes/key-groups.ts`, DECISION 1).
 *
 * `fetch` is an argument, not a global: the package does no ambient I/O, and a
 * browser, a worker and a test all hand in their own.
 */

import {
  type KeyGroupRegistrar,
  KeyGroupRegistrarError,
  KeyGroupRegistrarResponseError,
  type RegisteredApiKey,
  type RegisteredKeyGroup,
  type RegisterKeyGroupRequest,
  type ReservedKeyGroupId,
} from "./bootstrap.js";
import type { KeyGroupRotator, RotationMaterial } from "./remove-key.js";

export { KeyGroupRegistrarError, KeyGroupRegistrarResponseError };

/** Both register routes answer `201` on success and nothing else. */
const CREATED = 201;
/** Both rotation routes answer `200` on success and nothing else. */
const OK = 200;

export interface HttpKeyGroupRegistrarOptions {
  /** The API root including its version, e.g. `https://api.socket0.com/v1`. */
  readonly baseUrl: string;
  /** The person's access token, or a function returning a current one. */
  readonly accessToken: string | (() => string | Promise<string>);
  /** Called detached (`this` undefined), so a browser's native `fetch` can be passed as is. */
  readonly fetch: typeof globalThis.fetch;
}

/**
 * A non-201 answer is a `KeyGroupRegistrarError` with that status; a 201 whose
 * body is not the route's declared shape is a `KeyGroupRegistrarResponseError`,
 * which for the register route means the group very likely exists.
 */
export function httpKeyGroupRegistrar(options: HttpKeyGroupRegistrarOptions): KeyGroupRegistrar {
  async function post(
    tenantId: string,
    path: string,
    body: RegisterKeyGroupRequest | undefined,
    signal: AbortSignal | undefined,
  ): Promise<unknown> {
    return send(options, "POST", tenantId, path, body, signal, CREATED);
  }

  return {
    async reserveKeyGroupId(tenantId: string, signal?: AbortSignal): Promise<ReservedKeyGroupId> {
      const payload = await post(tenantId, "key-group-ids", undefined, signal);
      if (
        !isRecord(payload) ||
        typeof payload["id"] !== "string" ||
        typeof payload["expires_at"] !== "number"
      ) {
        throw new KeyGroupRegistrarResponseError("key-group-ids", CREATED);
      }
      return { id: payload["id"], expiresAt: payload["expires_at"] };
    },

    async registerKeyGroup(
      tenantId: string,
      body: RegisterKeyGroupRequest,
      signal?: AbortSignal,
    ): Promise<RegisteredKeyGroup> {
      const payload = await post(tenantId, "key-groups", body, signal);
      const group = keyGroup(payload);
      if (group === undefined) {
        throw new KeyGroupRegistrarResponseError("key-groups", CREATED);
      }
      return group;
    },
  };
}

/**
 * One authenticated JSON request to a tenant-scoped route. Anything but
 * `expected` is a `KeyGroupRegistrarError` carrying the API's `error` string.
 */
async function send(
  options: HttpKeyGroupRegistrarOptions,
  method: "GET" | "POST",
  tenantId: string,
  path: string,
  body: object | undefined,
  signal: AbortSignal | undefined,
  expected: number,
): Promise<unknown> {
  const root = options.baseUrl.replace(/\/+$/, "");
  // Detached: `options.fetch(...)` would call it with `this === options`, and a
  // browser's or a Worker's native fetch throws "Illegal invocation" for that.
  const doFetch = options.fetch;
  const token =
    typeof options.accessToken === "string" ? options.accessToken : await options.accessToken();
  const authorization = `Bearer ${token}`;
  const init: RequestInit = {
    method,
    ...(body === undefined
      ? { headers: { authorization } }
      : {
          headers: { authorization, "content-type": "application/json" },
          body: JSON.stringify(body),
        }),
    ...(signal === undefined ? {} : { signal }),
  };
  const response = await doFetch(`${root}/tenants/${encodeURIComponent(tenantId)}/${path}`, init);
  const payload: unknown = await response.json().catch(() => undefined);
  if (response.status !== expected) {
    const apiError =
      isRecord(payload) && typeof payload["error"] === "string" ? payload["error"] : undefined;
    throw new KeyGroupRegistrarError(
      response.status,
      apiError,
      `${path} answered ${response.status}`,
    );
  }
  return payload;
}

/**
 * The stock `KeyGroupRotator`: fetch-group and commit-rotation over `fetch`,
 * with the same bearer-token auth as the register routes. Both answer `200`.
 * A non-200 is a `KeyGroupRegistrarError` (a `409` names its reason in
 * `apiError`); a 200 whose body is not the route's shape is a
 * `KeyGroupRegistrarResponseError`.
 */
export function httpKeyGroupRotator(options: HttpKeyGroupRegistrarOptions): KeyGroupRotator {
  const path = (groupId: string): string => `key-groups/${encodeURIComponent(groupId)}/rotation`;
  return {
    async fetchRotation(tenantId, groupId, signal) {
      const payload = await send(options, "GET", tenantId, path(groupId), undefined, signal, OK);
      const material = rotationMaterial(payload);
      if (material === undefined) throw new KeyGroupRegistrarResponseError(path(groupId), OK);
      return material;
    },
    async commitRotation(tenantId, groupId, body, signal) {
      const payload = await send(options, "POST", tenantId, path(groupId), body, signal, OK);
      const group = keyGroup(payload);
      if (group === undefined) throw new KeyGroupRegistrarResponseError(path(groupId), OK);
      return group;
    },
  };
}

/** `RotationMaterial`, field for field, or `undefined` when the body is not one. */
function rotationMaterial(value: unknown): RotationMaterial | undefined {
  const ok =
    isRecord(value) &&
    typeof value["id"] === "string" &&
    Number.isInteger(value["generation"]) &&
    typeof value["public_key"] === "string" &&
    (value["recovery_public_key"] === null || typeof value["recovery_public_key"] === "string") &&
    everyRecord(
      value["keys"],
      (k) =>
        typeof k["key_id"] === "string" &&
        typeof k["wrapped"] === "string" &&
        (k["label"] === null || typeof k["label"] === "string") &&
        typeof k["created_at"] === "number",
    ) &&
    everyRecord(
      value["connections"],
      (c) =>
        typeof c["id"] === "string" &&
        Number.isInteger(c["version"]) &&
        isRecord(c["sealed"]) &&
        Object.values(c["sealed"]).every((v) => typeof v === "string"),
    ) &&
    everyRecord(
      value["auth_apps"],
      (a) => typeof a["id"] === "string" && typeof a["sealed_client_secret"] === "string",
    );
  return ok ? (value as unknown as RotationMaterial) : undefined;
}

function everyRecord(value: unknown, test: (item: Record<string, unknown>) => boolean): boolean {
  return Array.isArray(value) && value.every((item) => isRecord(item) && test(item));
}

/** The register route's `KeyGroup`, field for field, or `undefined` when the body is not one. */
function keyGroup(value: unknown): RegisteredKeyGroup | undefined {
  if (
    !isRecord(value) ||
    typeof value["id"] !== "string" ||
    typeof value["name"] !== "string" ||
    typeof value["public_key"] !== "string" ||
    !Number.isInteger(value["generation"]) ||
    typeof value["created_at"] !== "number" ||
    (value["purpose"] !== "tenant" && value["purpose"] !== "broker") ||
    !Array.isArray(value["keys"]) ||
    (value["recovery_public_key"] !== null && typeof value["recovery_public_key"] !== "string") ||
    typeof value["has_recovery"] !== "boolean"
  ) {
    return undefined;
  }
  const keys: RegisteredApiKey[] = [];
  for (const entry of value["keys"] as unknown[]) {
    const key = apiKeySummary(entry);
    if (key === undefined) return undefined;
    keys.push(key);
  }
  return {
    id: value["id"],
    name: value["name"],
    public_key: value["public_key"],
    generation: value["generation"] as number,
    created_at: value["created_at"],
    purpose: value["purpose"],
    keys,
    recovery_public_key: value["recovery_public_key"],
    has_recovery: value["has_recovery"],
  };
}

/** `ApiKeySummary`, or `undefined`. */
function apiKeySummary(value: unknown): RegisteredApiKey | undefined {
  if (
    !isRecord(value) ||
    typeof value["key_id"] !== "string" ||
    (value["label"] !== null && typeof value["label"] !== "string") ||
    typeof value["created_at"] !== "number" ||
    (value["kind"] !== "tenant" && value["kind"] !== "service")
  ) {
    return undefined;
  }
  return {
    key_id: value["key_id"],
    label: value["label"],
    created_at: value["created_at"],
    kind: value["kind"],
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
