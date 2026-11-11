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

import type {
  KeyGroupRegistrar,
  RegisteredKeyGroup,
  RegisterKeyGroupRequest,
  ReservedKeyGroupId,
} from "./bootstrap.js";
import { VaultError } from "./types.js";

/** Both routes answer `201` on success and nothing else. */
const CREATED = 201;

export interface HttpKeyGroupRegistrarOptions {
  /** The API root including its version, e.g. `https://api.socket0.com/v1`. */
  readonly baseUrl: string;
  /** The person's access token, or a function returning a current one. */
  readonly accessToken: string | (() => string | Promise<string>);
  readonly fetch: typeof globalThis.fetch;
}

/**
 * A key-group route refused, or answered with a body that is not its declared
 * shape. `status` is the HTTP status; `apiError` is the API's `error` string
 * when the body had one.
 *
 * Statuses worth acting on, from the register route: `409` the name is taken or
 * the reservation was already used, `410` the reservation expired.
 */
export class KeyGroupRegistrarError extends VaultError {
  readonly status: number;
  readonly apiError: string | undefined;
  constructor(status: number, apiError: string | undefined, message: string) {
    super(message);
    this.name = "KeyGroupRegistrarError";
    this.status = status;
    this.apiError = apiError;
  }
}

export function httpKeyGroupRegistrar(options: HttpKeyGroupRegistrarOptions): KeyGroupRegistrar {
  const root = options.baseUrl.replace(/\/+$/, "");

  async function post(
    tenantId: string,
    path: string,
    body?: RegisterKeyGroupRequest,
  ): Promise<unknown> {
    const token =
      typeof options.accessToken === "string" ? options.accessToken : await options.accessToken();
    const authorization = `Bearer ${token}`;
    const init: RequestInit =
      body === undefined
        ? { method: "POST", headers: { authorization } }
        : {
            method: "POST",
            headers: { authorization, "content-type": "application/json" },
            body: JSON.stringify(body),
          };
    const response = await options.fetch(
      `${root}/tenants/${encodeURIComponent(tenantId)}/${path}`,
      init,
    );
    const payload: unknown = await response.json().catch(() => undefined);
    if (response.status !== CREATED) {
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

  return {
    async reserveKeyGroupId(tenantId: string): Promise<ReservedKeyGroupId> {
      const payload = await post(tenantId, "key-group-ids");
      if (
        !isRecord(payload) ||
        typeof payload["id"] !== "string" ||
        typeof payload["expires_at"] !== "number"
      ) {
        throw malformed("key-group-ids");
      }
      return { id: payload["id"], expiresAt: payload["expires_at"] };
    },

    async registerKeyGroup(
      tenantId: string,
      body: RegisterKeyGroupRequest,
    ): Promise<RegisteredKeyGroup> {
      const payload = await post(tenantId, "key-groups", body);
      // The bootstrap compares these two against what it sent; the rest is the
      // API's own published shape and is passed through as it came.
      if (
        !isRecord(payload) ||
        typeof payload["id"] !== "string" ||
        typeof payload["public_key"] !== "string"
      ) {
        throw malformed("key-groups");
      }
      return payload as unknown as RegisteredKeyGroup;
    },
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function malformed(path: string): KeyGroupRegistrarError {
  return new KeyGroupRegistrarError(
    CREATED,
    undefined,
    `${path} answered 201 with a body of the wrong shape`,
  );
}
