/**
 * Removing an API key (`protocol/tenant-management`, `workflows/remove-key.yaml`):
 * the one client-side operation that runs a rotation end to end, per the
 * socketzero/solution#28 decision that rotation runs on the tenant's machine.
 *
 *     refuse the last key            before any request
 *     fetch-group                    GET  /tenants/{t}/key-groups/{g}/rotation
 *     unwrap old K1                  with a surviving key
 *     open the challenge             with the old K1: proof of possession
 *     rotateGroup                    new K1, every field resealed, bucket rebuilt,
 *                                    K1 sealed to the caller's K0 when given one
 *     commit-rotation                POST /tenants/{t}/key-groups/{g}/rotation
 *
 * **Every surviving key is presented.** The new bucket wraps the new K1 under
 * each key that stays, and a wrap key is derived from the raw API key — nothing
 * else can produce it. So the caller names the key that goes by its id (the
 * holder may be gone) and hands in the raw bytes of every key that stays. A
 * bucket key that is in neither list is refused rather than silently revoked.
 *
 * **K0 comes from the caller, never from the API.** The new K1 private half is
 * sealed to K0's public half, so whoever names that key can read the group. The
 * fetched `recovery_public_key` only tells whether the group has one; a group
 * that does is refused unless the caller presents K0 itself, from a source it
 * trusts.
 *
 * **The commit proves possession of the current K1.** A user session alone
 * cannot rotate a group: fetch-group seals a fresh 32-byte nonce to the current
 * public half, and the commit carries an HMAC of its own body keyed by the
 * opened nonce (`rotationProof`). The nonce itself is never sent, so a body
 * seen in transit or in a log proves nothing about any other body: it cannot
 * name another K1. The challenge is opened under associated data the SDK
 * builds itself, from the group it asked for, so a server cannot pass off a
 * connection's field as a challenge; and only an exactly 32-byte nonce is used.
 *
 * **"stale" is retried, nothing else is.** A `409 stale` means a field, an app
 * copy or the generation moved between fetch and commit, and nothing was
 * written; the whole rotation is redone from a fresh fetch, up to `maxAttempts`.
 *
 * **No I/O of its own**: both calls go through the `KeyGroupRotator` the caller
 * passes in (`httpKeyGroupRotator` is the stock adapter).
 */

import { deriveKeyIdHex } from "./api-key.js";
import type { RegisteredKeyGroup } from "./bootstrap.js";
import { KeyGroupRegistrarError } from "./bootstrap.js";
import { parseUuid } from "./bundle/layout.js";
import { base64Decode, base64Encode, timingSafeEqual, utf8Encode } from "./encoding.js";
import { bucketAssociatedData, derivePublicKey, open } from "./envelope.js";
import { findBucketEntry, rotateGroup, unwrap } from "./group.js";
import {
  type ApiKeyBytes,
  asPublicKey,
  type PrivateKey,
  type PublicKey,
  type SealedEnvelope,
  type SealedField,
  VaultError,
} from "./types.js";

// ---------------------------------------------------------------------------
// The rotator port: socket0-api's fetch-group and commit-rotation routes
// ---------------------------------------------------------------------------

/** `200` of `GET /tenants/{tenantId}/key-groups/{groupId}/rotation` (`RotationMaterial`). */
export interface RotationMaterial {
  readonly id: string;
  /** Sent back as `expected_generation`. */
  readonly generation: number;
  readonly public_key: string;
  /** K0's public half, or null. When set, the commit must bring a recovery entry. */
  readonly recovery_public_key: string | null;
  readonly keys: readonly {
    readonly key_id: string;
    readonly wrapped: string;
    readonly label: string | null;
    readonly created_at: number;
  }[];
  /** Every connection of the group, any status, sorted by id. */
  readonly connections: readonly {
    readonly id: string;
    readonly version: number;
    /** Every top-level config value that is an envelope, by property name. */
    readonly sealed: Readonly<Record<string, string>>;
  }[];
  /** Only the apps holding a copy for this group, and only that copy. */
  readonly auth_apps: readonly { readonly id: string; readonly sealed_client_secret: string }[];
  /**
   * Proof of possession: 32 random bytes sealed to `public_key` under
   * `bucketAssociatedData(group id, "rotation-challenge:" + id)`. Single use,
   * valid until `expires_at` (unix seconds, exclusive).
   */
  readonly challenge: {
    readonly id: string;
    readonly sealed_nonce: string;
    readonly expires_at: number;
  };
}

/** The body of `POST /tenants/{tenantId}/key-groups/{groupId}/rotation` (`CommitRotation`). */
export interface CommitRotationRequest {
  readonly expected_generation: number;
  readonly public_key: string;
  /** No `label`: absent keeps each entry's current one. */
  readonly keys: readonly { readonly key_id: string; readonly wrapped: string }[];
  readonly connections: readonly {
    readonly id: string;
    readonly version: number;
    readonly sealed: Readonly<Record<string, SealedEnvelope>>;
  }[];
  readonly auth_apps: readonly {
    readonly id: string;
    readonly previous_sealed_client_secret: string;
    readonly sealed_client_secret: SealedEnvelope;
  }[];
  readonly recovery_public_key?: string;
  readonly recovery_entry?: SealedEnvelope;
  /** `challenge.id` from the fetch this body was built from. */
  readonly challenge_id: string;
  /**
   * `rotationProof(nonce, groupId, every other field of this body)`: base64 of
   * an HMAC-SHA256 keyed by the challenge's opened nonce. Never the nonce.
   */
  readonly challenge_proof: string;
}

export interface KeyGroupRotator {
  fetchRotation(tenantId: string, groupId: string, signal?: AbortSignal): Promise<RotationMaterial>;
  /**
   * Throws a `KeyGroupRegistrarError` for any non-200; `403` (the proof was
   * refused) and `409` carry the API's reason.
   */
  commitRotation(
    tenantId: string,
    groupId: string,
    body: CommitRotationRequest,
    signal?: AbortSignal,
  ): Promise<RegisteredKeyGroup>;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Why `removeKey` refused, always before the commit, so nothing was written:
 *
 * - `last-key` — no key would survive. A group with no key can never be read
 *   again, and Socket0 holds nothing that could recover it.
 * - `not-in-group` — the bucket holds no key with that id.
 * - `unlisted-key` — a bucket key is neither kept nor removed; presenting it
 *   is the only way it can be rewrapped, and dropping it silently would revoke it.
 * - `unknown-survivor` — a surviving key is not in the bucket. Rotation never
 *   adds a key; that is add-key.
 * - `inconsistent-material` — the fetched group does not hang together: its
 *   public half is not what the bucket unwraps to, an id is malformed, or its
 *   challenge does not open under the current K1 to exactly 32 bytes.
 * - `recovery-key-required` — the API says the group has a recovery key (K0)
 *   and the caller did not present one. The new K1 is never sealed to a K0 the
 *   API supplied: a substituted one would hand the attacker the group.
 */
export type KeyRemovalRefusal =
  | "last-key"
  | "not-in-group"
  | "unlisted-key"
  | "unknown-survivor"
  | "inconsistent-material"
  | "recovery-key-required";

export class KeyRemovalRefusedError extends VaultError {
  readonly reason: KeyRemovalRefusal;
  constructor(reason: KeyRemovalRefusal, message: string) {
    super(message);
    this.name = "KeyRemovalRefusedError";
    this.reason = reason;
  }
}

/**
 * The commit answered 200, but the group it returned is not the one committed:
 * a public half other than the new one, a generation other than expected + 1,
 * or a bucket that is not exactly the surviving keys. The rotation may or may
 * not have landed; fetch the group and compare `publicKey` before retrying.
 */
export class KeyRemovalOutcomeUnknownError extends VaultError {
  readonly removedKeyId: string;
  /** The new K1 public half, base64, as committed. */
  readonly publicKey: string;
  /** What the API returned. */
  readonly group: RegisteredKeyGroup;
  constructor(removedKeyId: string, publicKey: string, group: RegisteredKeyGroup, why: string) {
    super(`removing key ${removedKeyId} may not have landed: the commit answered ${why}`);
    this.name = "KeyRemovalOutcomeUnknownError";
    this.removedKeyId = removedKeyId;
    this.publicKey = publicKey;
    this.group = group;
  }
}

// ---------------------------------------------------------------------------
// removeKey
// ---------------------------------------------------------------------------

export interface RemoveKeyOptions {
  readonly rotator: KeyGroupRotator;
  /** The HKDF salt of every key in the group, and the tenant in the route. */
  readonly tenantId: string;
  readonly groupId: string;
  /** The key to remove, as the bucket lists it: 32 lowercase hex characters. */
  readonly keyId: string;
  /** The raw bytes of EVERY key that stays. The first one unwraps the old K1. */
  readonly survivingKeys: readonly ApiKeyBytes[];
  /**
   * K0's public half, from a source the caller trusts — never read back from
   * the API. The new K1 is sealed to it: the group's current K0 keeps it, a new
   * one replaces it. Required when the group has a K0 (refused otherwise, as
   * `recovery-key-required`); omitted for a group without one, which stays so.
   */
  readonly recoveryPublicKey?: PublicKey;
  /** How many fetch-and-commit rounds a run of `409 stale` may take: an integer >= 1. Default 3. */
  readonly maxAttempts?: number;
  readonly signal?: AbortSignal;
}

export interface RemovedKey {
  /**
   * The group as committed, checked: the new public half, generation
   * incremented, exactly the surviving keys.
   */
  readonly group: RegisteredKeyGroup;
  readonly removedKeyId: string;
}

const KEY_ID = /^[0-9a-f]{32}$/;
const DEFAULT_MAX_ATTEMPTS = 3;
/** `<tag>-<uuid>`: a four-letter shard tag, a dash, the UUID the fields bind. */
const TAGGED_ID = /^[a-z]{4}-(.{36})$/;
/** The field name an app's client secret is sealed under (adr/0033 D16). */
const CLIENT_SECRET_FIELD = "client-secret";
/** The challenge's nonce: what the commit sends back opened, and nothing else. */
const CHALLENGE_NONCE_BYTES = 32;
/** Domain tag of the commit proof's MAC input. */
const PROOF_DOMAIN = "socket0/rotation-proof/v1";

/**
 * Remove one API key from a key group: fetch, unwrap with a surviving key,
 * rotate (sealed to the caller's K0 when given one), commit — as one generation.
 *
 * @throws {RangeError} for a malformed `keyId`, a surviving key presented twice
 *   or one that is also the key being removed, or a `maxAttempts` that is not
 *   an integer >= 1 — before any request.
 * @throws {KeyRemovalRefusedError} before the commit; see its reasons.
 * @throws {KeyGroupRegistrarError} for a refusal by the API: `403` the proof
 *   of possession was refused (`proof required` / `proof invalid`), `404` not
 *   this tenant's group, `409` with the API's reason (a `stale` one - which
 *   includes a challenge that expired or was evicted before the commit - only
 *   after `maxAttempts` rounds).
 * @throws {VaultDecryptionError} when the surviving key does not open its entry
 *   or a stored field does not open under the old K1. Nothing was committed.
 * @throws {KeyRemovalOutcomeUnknownError} when the commit's 200 names a group
 *   other than the one committed.
 */
export async function removeKey(options: RemoveKeyOptions): Promise<RemovedKey> {
  const { rotator, tenantId, groupId, keyId, survivingKeys, signal } = options;
  if (!KEY_ID.test(keyId)) {
    throw new RangeError(`a key id is 32 lowercase hex characters, got ${JSON.stringify(keyId)}`);
  }
  if (survivingKeys.length === 0) {
    throw new KeyRemovalRefusedError(
      "last-key",
      "removing the last key would leave a group nothing can ever open; reset or delete the group instead",
    );
  }
  const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1) {
    throw new RangeError(`maxAttempts is an integer >= 1, got ${maxAttempts}`);
  }
  const survivorIds = await Promise.all(survivingKeys.map((k) => deriveKeyIdHex(k, tenantId)));
  if (new Set(survivorIds).size !== survivorIds.length || survivorIds.includes(keyId)) {
    throw new RangeError("each surviving key is presented once, and not the key being removed");
  }

  for (let attempt = 1; ; attempt += 1) {
    signal?.throwIfAborted();
    const material = await rotator.fetchRotation(tenantId, groupId, signal);
    const body = await rotation(material, options, survivorIds);
    let group: RegisteredKeyGroup;
    try {
      group = await rotator.commitRotation(tenantId, groupId, body, signal);
    } catch (error) {
      const stale =
        error instanceof KeyGroupRegistrarError &&
        error.status === 409 &&
        error.apiError === "stale";
      if (!stale || attempt >= maxAttempts) throw error;
      continue;
    }
    const why = mismatch(group, body);
    if (why !== undefined) {
      throw new KeyRemovalOutcomeUnknownError(keyId, body.public_key, group, why);
    }
    return { group, removedKeyId: keyId };
  }
}

/** Why the commit's answer is not the group just committed, or undefined when it is. */
function mismatch(group: RegisteredKeyGroup, body: CommitRotationRequest): string | undefined {
  if (group.public_key !== body.public_key) return "another public half";
  if (group.generation !== body.expected_generation + 1) {
    return `generation ${group.generation}, not ${body.expected_generation + 1}`;
  }
  const committed = body.keys.map((k) => k.key_id).sort();
  const returned = group.keys.map((k) => k.key_id).sort();
  if (committed.length !== returned.length || committed.some((id, i) => id !== returned[i])) {
    return "a bucket other than the surviving keys";
  }
  return undefined;
}

/** Check the fetched material against the request and build the commit body. */
async function rotation(
  material: RotationMaterial,
  options: RemoveKeyOptions,
  survivorIds: readonly string[],
): Promise<CommitRotationRequest> {
  const { tenantId, groupId, keyId, survivingKeys } = options;
  const bucketIds = material.keys.map((k) => k.key_id);
  if (!bucketIds.includes(keyId)) {
    throw new KeyRemovalRefusedError("not-in-group", `the group holds no key ${keyId}`);
  }
  if (bucketIds.length === 1) {
    throw new KeyRemovalRefusedError(
      "last-key",
      "removing the last key would leave a group nothing can ever open; reset or delete the group instead",
    );
  }
  if (survivorIds.some((id) => !bucketIds.includes(id))) {
    throw new KeyRemovalRefusedError(
      "unknown-survivor",
      "a surviving key is not in the group; a rotation never adds a key",
    );
  }
  const unlisted = bucketIds.filter((id) => id !== keyId && !survivorIds.includes(id));
  if (unlisted.length > 0) {
    throw new KeyRemovalRefusedError(
      "unlisted-key",
      `keys ${unlisted.join(", ")} would be revoked silently; present them to keep them`,
    );
  }
  // The fetched K0 is only a hint that the group has one; sealing the new K1 to
  // it would let whoever wrote it read the group.
  const k0 = options.recoveryPublicKey;
  if (k0 === undefined && material.recovery_public_key !== null) {
    throw new KeyRemovalRefusedError(
      "recovery-key-required",
      "the group has a recovery key; present its public half (recoveryPublicKey) from a source you trust",
    );
  }

  const fields = fieldsOf(material);
  const oldPublicKey = asPublicKey(base64Decode(material.public_key));
  const bucket = {
    groupId,
    publicKey: oldPublicKey,
    generation: material.generation,
    bucket: material.keys.map((k) => ({ keyId: k.key_id, wrapped: base64Decode(k.wrapped) })),
  };
  const holder = survivingKeys[0] as ApiKeyBytes;
  // Present: survivorIds were all just found in the bucket.
  const entry = await findBucketEntry(bucket, holder, tenantId);
  let oldPrivateKey: PrivateKey | undefined;
  let newPrivateKey: PrivateKey | undefined;
  let nonce: Uint8Array | undefined;
  try {
    oldPrivateKey = await unwrap(entry as NonNullable<typeof entry>, holder, tenantId, groupId);
    if (!timingSafeEqual(await derivePublicKey(oldPrivateKey), oldPublicKey)) {
      throw new KeyRemovalRefusedError(
        "inconsistent-material",
        "the group's public half is not the one its bucket unwraps to",
      );
    }
    nonce = await answer(material.challenge, oldPrivateKey, oldPublicKey, groupId);
    const rotated = await rotateGroup(
      oldPrivateKey,
      fields.map((f) => f.field),
      survivingKeys,
      tenantId,
      groupId,
      k0,
    );
    newPrivateKey = rotated.privateKey;

    const sealed = rotated.fields.map((f) => f.envelope);
    const connections = material.connections.map((c) => ({
      id: c.id,
      version: c.version,
      sealed: {} as Record<string, SealedEnvelope>,
    }));
    const apps: CommitRotationRequest["auth_apps"][number][] = [];
    fields.forEach((f, i) => {
      const envelope = sealed[i] as SealedEnvelope;
      if (f.kind === "connection") {
        (connections[f.index] as (typeof connections)[number]).sealed[f.field.identity.fieldName] =
          envelope;
      } else {
        const app = material.auth_apps[f.index] as RotationMaterial["auth_apps"][number];
        apps.push({
          id: app.id,
          previous_sealed_client_secret: app.sealed_client_secret,
          sealed_client_secret: envelope,
        });
      }
    });

    const unproven: Omit<CommitRotationRequest, "challenge_proof"> = {
      expected_generation: material.generation,
      public_key: base64Encode(rotated.publicKey),
      keys: rotated.bucket.map((e) => ({ key_id: e.keyId, wrapped: base64Encode(e.wrapped) })),
      connections,
      auth_apps: apps,
      // rotateGroup returns `recovery` exactly when it was given K0.
      ...(rotated.recovery === undefined
        ? {}
        : {
            recovery_public_key: base64Encode(k0 as PublicKey),
            recovery_entry: rotated.recovery,
          }),
      challenge_id: material.challenge.id,
    };
    return { ...unproven, challenge_proof: await rotationProof(nonce, groupId, unproven) };
  } finally {
    oldPrivateKey?.fill(0);
    newPrivateKey?.fill(0);
    nonce?.fill(0);
  }
}

/**
 * The commit's proof of possession, bound to the body it travels in:
 *
 *     base64(HMAC-SHA256(key = nonce,
 *       "socket0/rotation-proof/v1" 0x00 groupId 0x00 JCS(body)))
 *
 * `nonce` is the challenge opened with the current K1 (32 bytes), `body` is
 * the commit without `challenge_proof` — `challenge_id` included — and JCS is
 * RFC 8785; for a commit body (strings and integers only) that is
 * `JSON.stringify` with every object's keys sorted. The server recomputes it
 * over the body it parsed: one changed byte anywhere (a K1, a wrap, a field)
 * and the proof does not match.
 */
export async function rotationProof(
  nonce: Uint8Array,
  groupId: string,
  body: Omit<CommitRotationRequest, "challenge_proof">,
): Promise<string> {
  const subtle = globalThis.crypto.subtle;
  const key = await subtle.importKey(
    "raw",
    nonce as Uint8Array<ArrayBuffer>,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const message = utf8Encode(`${PROOF_DOMAIN}\0${groupId}\0${canonicalJson(body)}`);
  return base64Encode(new Uint8Array(await subtle.sign("HMAC", key, message)));
}

/**
 * RFC 8785 for what a commit body holds — strings, numbers, arrays, plain
 * objects: ES `JSON.stringify` serializes those leaves exactly as JCS does, so
 * only the key order (UTF-16 code units, which `<` compares) is added here.
 */
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value !== "object" || value === null) return JSON.stringify(value);
  const entries = Object.entries(value)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : 1));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

/**
 * Open fetch-group's challenge with the current K1 and return the nonce.
 *
 * The associated data is built here, from the group the caller named, so the
 * only envelopes that open are ones sealed AS a challenge for this group: a
 * connection's field or an app's secret binds 16 uuid bytes first and fails
 * the tag. Anything that does not open to exactly 32 bytes is refused, and
 * nothing is sent.
 */
async function answer(
  challenge: RotationMaterial["challenge"],
  privateKey: PrivateKey,
  publicKey: PublicKey,
  groupId: string,
): Promise<Uint8Array> {
  let nonce: Uint8Array;
  try {
    nonce = await open(
      challenge.sealed_nonce,
      privateKey,
      bucketAssociatedData(groupId, `rotation-challenge:${challenge.id}`),
      publicKey,
    );
  } catch {
    throw new KeyRemovalRefusedError(
      "inconsistent-material",
      "the rotation challenge does not open under the group's current key",
    );
  }
  if (nonce.byteLength !== CHALLENGE_NONCE_BYTES) {
    nonce.fill(0);
    throw new KeyRemovalRefusedError(
      "inconsistent-material",
      `the rotation challenge is ${nonce.byteLength} bytes, not ${CHALLENGE_NONCE_BYTES}`,
    );
  }
  return nonce;
}

interface LocatedField {
  readonly kind: "connection" | "app";
  /** Into `material.connections` or `material.auth_apps`. */
  readonly index: number;
  readonly field: SealedField;
}

/** Every sealed field of the group, each with the identity its associated data binds. */
function fieldsOf(material: RotationMaterial): LocatedField[] {
  const located: LocatedField[] = [];
  material.connections.forEach((c, index) => {
    const connectionUuid = uuidBytes(TAGGED_ID.exec(c.id)?.[1] ?? c.id);
    for (const [fieldName, envelope] of Object.entries(c.sealed)) {
      located.push({
        kind: "connection",
        index,
        field: { identity: { connectionUuid, fieldName }, envelope: envelope as SealedEnvelope },
      });
    }
  });
  material.auth_apps.forEach((a, index) => {
    located.push({
      kind: "app",
      index,
      field: {
        identity: { connectionUuid: uuidBytes(a.id), fieldName: CLIENT_SECRET_FIELD },
        envelope: a.sealed_client_secret as SealedEnvelope,
      },
    });
  });
  return located;
}

function uuidBytes(uuid: string): Uint8Array {
  try {
    return parseUuid(uuid);
  } catch {
    throw new KeyRemovalRefusedError(
      "inconsistent-material",
      `${JSON.stringify(uuid)} is not a UUID a sealed field can be bound to`,
    );
  }
}
