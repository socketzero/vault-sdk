/**
 * socket0-api's two rotation routes, in memory, behind a `fetch`.
 *
 * Test-only and excluded from coverage. It follows the contract of
 * `socket0-api/src/routes/key-groups.ts` (fetch-group, commit-rotation; PR #42)
 * rule for rule, because a fake that accepts what the real route refuses proves
 * nothing about the SDK that talks to it:
 *
 *   - `requireUser` bearer auth; a tenant other than the token's, an unknown
 *     group and another tenant's group are all `404 {"error":"not found"}`;
 *   - the commit body is a strict object: an unknown field, a malformed value,
 *     empty `keys`, a repeated id or half a recovery pair is
 *     `400 {"error":"invalid request"}`;
 *   - `409` with `stale`, `incomplete`, `unknown key`, `recovery entry
 *     required` or `public key not new`, and nothing written;
 *   - fetch-group never returns the recovery entry, and seals are found by
 *     SHAPE: every top-level config string that is an envelope;
 *   - fetch-group mints a single-use challenge: 32 random bytes sealed to the
 *     group's current public half under
 *     `bucketAssociatedData(group id, "rotation-challenge:" + id)`. The commit
 *     must carry `challenge_id` and `challenge_nonce` (base64 of the opened
 *     bytes): absent is `403 proof required`; wrong, another group's, expired
 *     (`expires_at`, 300 s after minting on `now`, is exclusive), or an
 *     earlier generation's sent with a generation other than its own is
 *     `403 proof invalid`; spent is `409 stale`. A landed commit spends it.
 *
 * The only cryptography here is that `seal`, which needs no secret. The server
 * cannot open anything, and neither can this fake: whether the SDK resealed
 * correctly is for the test to prove by opening what was stored.
 */

import { base64Decode, base64Encode } from "./encoding.js";
import { bucketAssociatedData, seal } from "./envelope.js";
import { asPublicKey } from "./types.js";

export const FAKE_BASE_URL = "https://api.test/v1";
export const FAKE_TOKEN = "user-jwt";

const SEALED = /^x25519-hkdf-aesgcm:[A-Za-z0-9+/]+={0,2}$/;
const KEY_ID = /^[0-9a-f]{32}$/;
const PUBLIC_KEY = /^[A-Za-z0-9+/]{43}=$/;
const WRAPPED = /^[A-Za-z0-9+/]{60,}={0,2}$/;
const UUID7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export interface FakeKey {
  key_id: string;
  wrapped: string;
  label: string | null;
  created_at: number;
}

export interface FakeGroup {
  readonly id: string;
  readonly tenantId: string;
  readonly name: string;
  generation: number;
  publicKey: string;
  recoveryPublicKey: string | null;
  recoveryEntry: string | null;
  keys: FakeKey[];
}

export interface FakeConnection {
  readonly id: string;
  readonly groupId: string;
  version: number;
  config: Record<string, unknown>;
}

export interface FakeApp {
  readonly id: string;
  /** groupId → that group's sealed copy of the client secret. */
  readonly copies: Map<string, string>;
}

export interface FakeState {
  readonly tenantId: string;
  readonly groups: FakeGroup[];
  readonly connections: FakeConnection[];
  readonly apps: FakeApp[];
}

export interface FakeCall {
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
  readonly status: number;
  readonly response: unknown;
}

export interface FakeRotationApi {
  readonly fetch: typeof globalThis.fetch;
  readonly state: FakeState;
  readonly calls: FakeCall[];
  /** Runs once per commit, before it is judged — where a concurrent writer goes. */
  beforeCommit: (() => void) | undefined;
  /** Every challenge minted, by id: the nonce as base64, and whether it was spent. */
  readonly challenges: Map<string, FakeChallenge>;
  /** The server's clock, unix seconds: what a challenge's expiry is judged on. */
  now: number;
  /**
   * Replaces the challenge fetch-group would send — where a server that lies
   * about it goes. Receives the honest one, already stored.
   */
  tamperChallenge:
    | ((honest: SentChallenge, group: FakeGroup) => Promise<SentChallenge>)
    | undefined;
}

export interface FakeChallenge {
  readonly groupId: string;
  readonly generation: number;
  readonly nonce: string;
  readonly expiresAt: number;
  spent: boolean;
}

export interface SentChallenge {
  readonly id: string;
  readonly sealed_nonce: string;
  readonly expires_at: number;
}

const NOT_FOUND = { error: "not found" };
/** socket0-api's challenge life, seconds. */
const CHALLENGE_TTL = 300;
const INVALID = { error: "invalid request" };

export function fakeRotationApi(state: FakeState): FakeRotationApi {
  const calls: FakeCall[] = [];
  let minted = 0;
  const api: FakeRotationApi = {
    state,
    calls,
    beforeCommit: undefined,
    challenges: new Map(),
    now: 1_800_000_000,
    tamperChallenge: undefined,
    fetch: (async (input: string | URL | Request, init?: RequestInit) => {
      init?.signal?.throwIfAborted();
      const url = new URL(String(input));
      const method = init?.method ?? "GET";
      const body = typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
      const [status, response] = await route(method, url.pathname, init, body);
      calls.push({ method, path: url.pathname, body, status, response });
      return new Response(JSON.stringify(response), {
        status,
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch,
  };

  async function route(
    method: string,
    path: string,
    init: RequestInit | undefined,
    body: unknown,
  ): Promise<[number, unknown]> {
    if (new Headers(init?.headers).get("authorization") !== `Bearer ${FAKE_TOKEN}`) {
      return [401, { error: "unauthorized" }];
    }
    const match = /^\/v1\/tenants\/([^/]+)\/key-groups\/([^/]+)\/rotation$/.exec(path);
    if (match === null) return [404, NOT_FOUND];
    const tenantId = decodeURIComponent(match[1] as string);
    const groupId = decodeURIComponent(match[2] as string);
    if (tenantId !== state.tenantId) return [404, NOT_FOUND];
    const group = state.groups.find((g) => g.id === groupId && g.tenantId === tenantId);
    if (group === undefined) return [404, NOT_FOUND];
    if (method === "GET") return [200, await material(group)];
    if (method === "POST") return commit(group, body);
    return [405, { error: "method not allowed" }];
  }

  function connectionsOf(group: FakeGroup): FakeConnection[] {
    return state.connections
      .filter((c) => c.groupId === group.id)
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  }

  function appsOf(group: FakeGroup): { app: FakeApp; copy: string }[] {
    return state.apps.flatMap((app) => {
      const copy = app.copies.get(group.id);
      return copy === undefined ? [] : [{ app, copy }];
    });
  }

  async function challengeFor(group: FakeGroup): Promise<SentChallenge> {
    minted += 1;
    const id = `0192f1a0-cccc-7000-8000-${minted.toString(16).padStart(12, "0")}`;
    const nonce = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const expiresAt = api.now + CHALLENGE_TTL;
    api.challenges.set(id, {
      groupId: group.id,
      generation: group.generation,
      nonce: base64Encode(nonce),
      expiresAt,
      spent: false,
    });
    const honest = {
      id,
      sealed_nonce: await seal(
        nonce,
        asPublicKey(base64Decode(group.publicKey)),
        bucketAssociatedData(group.id, `rotation-challenge:${id}`),
      ),
      expires_at: expiresAt,
    };
    return api.tamperChallenge === undefined ? honest : api.tamperChallenge(honest, group);
  }

  async function material(group: FakeGroup): Promise<unknown> {
    return {
      id: group.id,
      generation: group.generation,
      public_key: group.publicKey,
      recovery_public_key: group.recoveryPublicKey,
      keys: group.keys.map((k) => ({ ...k })),
      connections: connectionsOf(group).map((c) => ({
        id: c.id,
        version: c.version,
        sealed: sealedOf(c.config),
      })),
      auth_apps: appsOf(group).map(({ app, copy }) => ({ id: app.id, sealed_client_secret: copy })),
      challenge: await challengeFor(group),
    };
  }

  function commit(group: FakeGroup, raw: unknown): [number, unknown] {
    const body = parseCommit(raw);
    if (body === undefined) return [400, INVALID];
    api.beforeCommit?.();

    if (body.challenge_id === undefined || body.challenge_nonce === undefined) {
      return [403, { error: "proof required" }];
    }
    const challenge = api.challenges.get(body.challenge_id);
    if (
      challenge === undefined ||
      challenge.groupId !== group.id ||
      challenge.nonce !== body.challenge_nonce
    ) {
      return [403, { error: "proof invalid" }];
    }
    if (challenge.spent) return [409, { error: "stale" }];
    if (challenge.expiresAt <= api.now) return [403, { error: "proof invalid" }];
    // Another generation's challenge is a lost race when sent with its own
    // generation (409 stale below), and no proof otherwise.
    if (
      challenge.generation !== group.generation &&
      challenge.generation !== body.expected_generation
    ) {
      return [403, { error: "proof invalid" }];
    }

    const connections = connectionsOf(group);
    const apps = appsOf(group);
    const sentConnections = new Map(body.connections.map((c) => [c.id, c]));
    const sentApps = new Map(body.auth_apps.map((a) => [a.id, a]));
    if (
      body.expected_generation !== group.generation ||
      connections.length !== body.connections.length ||
      connections.some((c) => sentConnections.get(c.id)?.version !== c.version) ||
      apps.length !== body.auth_apps.length ||
      apps.some(({ app, copy }) => sentApps.get(app.id)?.previous_sealed_client_secret !== copy)
    ) {
      return [409, { error: "stale" }];
    }
    if (body.keys.some((k) => !group.keys.some((g) => g.key_id === k.key_id))) {
      return [409, { error: "unknown key" }];
    }
    for (const c of connections) {
      const held = Object.keys(sealedOf(c.config)).sort();
      const sent = Object.keys((sentConnections.get(c.id) as SentConnection).sealed).sort();
      if (held.length !== sent.length || held.some((name, i) => name !== sent[i])) {
        return [409, { error: "incomplete" }];
      }
    }
    if (group.recoveryPublicKey !== null && body.recovery_entry === undefined) {
      return [409, { error: "recovery entry required" }];
    }
    if (body.public_key === group.publicKey) return [409, { error: "public key not new" }];

    // One generation, all of it, and the challenge spent with it.
    challenge.spent = true;
    group.generation += 1;
    group.publicKey = body.public_key;
    group.keys = body.keys.map((k) => {
      const old = group.keys.find((g) => g.key_id === k.key_id) as FakeKey;
      return {
        key_id: k.key_id,
        wrapped: k.wrapped,
        label: k.label === undefined ? old.label : k.label,
        created_at: old.created_at,
      };
    });
    for (const c of connections) {
      c.config = { ...c.config, ...(sentConnections.get(c.id) as SentConnection).sealed };
      c.version += 1;
    }
    for (const { app } of apps) {
      app.copies.set(group.id, (sentApps.get(app.id) as SentApp).sealed_client_secret);
    }
    if (body.recovery_public_key !== undefined && body.recovery_entry !== undefined) {
      group.recoveryPublicKey = body.recovery_public_key;
      group.recoveryEntry = body.recovery_entry;
    }
    return [
      200,
      {
        id: group.id,
        name: group.name,
        public_key: group.publicKey,
        generation: group.generation,
        created_at: 1,
        purpose: "tenant",
        keys: group.keys.map((k) => ({
          key_id: k.key_id,
          label: k.label,
          created_at: k.created_at,
          kind: "tenant",
        })),
        recovery_public_key: group.recoveryPublicKey,
        has_recovery: group.recoveryEntry !== null,
      },
    ];
  }

  return api;
}

function sealedOf(config: Record<string, unknown>): Record<string, string> {
  const sealed: Record<string, string> = {};
  for (const [name, value] of Object.entries(config)) {
    if (typeof value === "string" && SEALED.test(value)) sealed[name] = value;
  }
  return sealed;
}

interface SentKey {
  key_id: string;
  wrapped: string;
  label?: string;
}
interface SentConnection {
  id: string;
  version: number;
  sealed: Record<string, string>;
}
interface SentApp {
  id: string;
  previous_sealed_client_secret: string;
  sealed_client_secret: string;
}
interface SentCommit {
  expected_generation: number;
  public_key: string;
  keys: SentKey[];
  connections: SentConnection[];
  auth_apps: SentApp[];
  recovery_public_key?: string;
  recovery_entry?: string;
  challenge_id?: string;
  challenge_nonce?: string;
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const onlyKeys = (v: Record<string, unknown>, allowed: string[]): boolean =>
  Object.keys(v).every((k) => allowed.includes(k));
const isInt = (v: unknown, min: number): boolean => Number.isInteger(v) && (v as number) >= min;
const unique = (ids: string[]): boolean => new Set(ids).size === ids.length;

/** `CommitRotationBody` as a strictObject, or `undefined` for a 400. */
function parseCommit(raw: unknown): SentCommit | undefined {
  if (
    !isRecord(raw) ||
    !onlyKeys(raw, [
      "expected_generation",
      "public_key",
      "keys",
      "connections",
      "auth_apps",
      "recovery_public_key",
      "recovery_entry",
      "challenge_id",
      "challenge_nonce",
    ]) ||
    (raw["challenge_id"] !== undefined && typeof raw["challenge_id"] !== "string") ||
    (raw["challenge_nonce"] !== undefined && typeof raw["challenge_nonce"] !== "string") ||
    !isInt(raw["expected_generation"], 0) ||
    typeof raw["public_key"] !== "string" ||
    !PUBLIC_KEY.test(raw["public_key"]) ||
    !Array.isArray(raw["keys"]) ||
    raw["keys"].length < 1 ||
    !Array.isArray(raw["connections"]) ||
    !Array.isArray(raw["auth_apps"]) ||
    (raw["recovery_public_key"] === undefined) !== (raw["recovery_entry"] === undefined) ||
    (raw["recovery_public_key"] !== undefined &&
      (typeof raw["recovery_public_key"] !== "string" ||
        !PUBLIC_KEY.test(raw["recovery_public_key"]))) ||
    (raw["recovery_entry"] !== undefined &&
      (typeof raw["recovery_entry"] !== "string" || !SEALED.test(raw["recovery_entry"])))
  ) {
    return undefined;
  }
  const keysOk = (raw["keys"] as unknown[]).every(
    (k) =>
      isRecord(k) &&
      onlyKeys(k, ["key_id", "wrapped", "label"]) &&
      typeof k["key_id"] === "string" &&
      KEY_ID.test(k["key_id"]) &&
      typeof k["wrapped"] === "string" &&
      WRAPPED.test(k["wrapped"]) &&
      (k["label"] === undefined || typeof k["label"] === "string"),
  );
  const connectionsOk = (raw["connections"] as unknown[]).every(
    (c) =>
      isRecord(c) &&
      onlyKeys(c, ["id", "version", "sealed"]) &&
      typeof c["id"] === "string" &&
      isInt(c["version"], 1) &&
      isRecord(c["sealed"]) &&
      Object.values(c["sealed"]).every((v) => typeof v === "string" && SEALED.test(v)),
  );
  const appsOk = (raw["auth_apps"] as unknown[]).every(
    (a) =>
      isRecord(a) &&
      onlyKeys(a, ["id", "previous_sealed_client_secret", "sealed_client_secret"]) &&
      typeof a["id"] === "string" &&
      UUID7.test(a["id"]) &&
      typeof a["previous_sealed_client_secret"] === "string" &&
      SEALED.test(a["previous_sealed_client_secret"]) &&
      typeof a["sealed_client_secret"] === "string" &&
      SEALED.test(a["sealed_client_secret"]),
  );
  if (!keysOk || !connectionsOk || !appsOk) return undefined;
  const body = raw as unknown as SentCommit;
  if (
    !unique(body.keys.map((k) => k.key_id)) ||
    !unique(body.connections.map((c) => c.id)) ||
    !unique(body.auth_apps.map((a) => a.id))
  ) {
    return undefined;
  }
  return body;
}
