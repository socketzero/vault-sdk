/**
 * Removing an API key (`protocol/tenant-management`, `workflows/remove-key.yaml`):
 * the one client-side operation that runs a rotation end to end, per the
 * socketzero/solution#28 decision that rotation runs on the tenant's machine.
 *
 *     refuse the last key            before any request
 *     fetch-group                    GET  /tenants/{t}/key-groups/{g}/rotation
 *     unwrap old K1                  with a surviving key
 *     rotateGroup                    new K1, every field resealed, bucket rebuilt,
 *                                    K1 sealed to K0 when the group has one
 *     commit-rotation                POST /tenants/{t}/key-groups/{g}/rotation
 *
 * **Every surviving key is presented.** The new bucket wraps the new K1 under
 * each key that stays, and a wrap key is derived from the raw API key — nothing
 * else can produce it. So the caller names the key that goes by its id (the
 * holder may be gone) and hands in the raw bytes of every key that stays. A
 * bucket key that is in neither list is refused rather than silently revoked.
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
import { base64Decode, base64Encode, timingSafeEqual } from "./encoding.js";
import { derivePublicKey } from "./envelope.js";
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
}

export interface KeyGroupRotator {
  fetchRotation(tenantId: string, groupId: string, signal?: AbortSignal): Promise<RotationMaterial>;
  /** Throws a `KeyGroupRegistrarError` for any non-200; `409` carries the API's reason. */
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
 *   public half is not what the bucket unwraps to, or an id is malformed.
 */
export type KeyRemovalRefusal =
  | "last-key"
  | "not-in-group"
  | "unlisted-key"
  | "unknown-survivor"
  | "inconsistent-material";

export class KeyRemovalRefusedError extends VaultError {
  readonly reason: KeyRemovalRefusal;
  constructor(reason: KeyRemovalRefusal, message: string) {
    super(message);
    this.name = "KeyRemovalRefusedError";
    this.reason = reason;
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
   * A new K0 public half, replacing the group's. Omitted, the group's current
   * K0 (as fetched) is kept, and a group without one stays without one.
   */
  readonly recoveryPublicKey?: PublicKey;
  /** How many fetch-and-commit rounds a run of `409 stale` may take. Default 3. */
  readonly maxAttempts?: number;
  readonly signal?: AbortSignal;
}

export interface RemovedKey {
  /** The group as committed: generation incremented, the new public half. */
  readonly group: RegisteredKeyGroup;
  readonly removedKeyId: string;
}

const KEY_ID = /^[0-9a-f]{32}$/;
const DEFAULT_MAX_ATTEMPTS = 3;
/** `<tag>-<uuid>`: a four-letter shard tag, a dash, the UUID the fields bind. */
const TAGGED_ID = /^[a-z]{4}-(.{36})$/;
/** The field name an app's client secret is sealed under (adr/0033 D16). */
const CLIENT_SECRET_FIELD = "client-secret";

/**
 * Remove one API key from a key group: fetch, unwrap with a surviving key,
 * rotate (with K0 when the group has one), commit — as one generation.
 *
 * @throws {RangeError} for a malformed `keyId`, a surviving key presented twice
 *   or one that is also the key being removed — before any request.
 * @throws {KeyRemovalRefusedError} before the commit; see its reasons.
 * @throws {KeyGroupRegistrarError} for a refusal by the API: `404` not this
 *   tenant's group, `409` with the API's reason (a `stale` one only after
 *   `maxAttempts` rounds).
 * @throws {VaultDecryptionError} when the surviving key does not open its entry
 *   or a stored field does not open under the old K1. Nothing was committed.
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
  const survivorIds = await Promise.all(survivingKeys.map((k) => deriveKeyIdHex(k, tenantId)));
  if (new Set(survivorIds).size !== survivorIds.length || survivorIds.includes(keyId)) {
    throw new RangeError("each surviving key is presented once, and not the key being removed");
  }

  const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  for (let attempt = 1; ; attempt += 1) {
    signal?.throwIfAborted();
    const material = await rotator.fetchRotation(tenantId, groupId, signal);
    const body = await rotation(material, options, survivorIds);
    try {
      const group = await rotator.commitRotation(tenantId, groupId, body, signal);
      return { group, removedKeyId: keyId };
    } catch (error) {
      const stale =
        error instanceof KeyGroupRegistrarError &&
        error.status === 409 &&
        error.apiError === "stale";
      if (!stale || attempt >= maxAttempts) throw error;
    }
  }
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
  try {
    oldPrivateKey = await unwrap(entry as NonNullable<typeof entry>, holder, tenantId, groupId);
    if (!timingSafeEqual(await derivePublicKey(oldPrivateKey), oldPublicKey)) {
      throw new KeyRemovalRefusedError(
        "inconsistent-material",
        "the group's public half is not the one its bucket unwraps to",
      );
    }
    const k0 =
      options.recoveryPublicKey ??
      (material.recovery_public_key === null
        ? undefined
        : asPublicKey(base64Decode(material.recovery_public_key)));
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

    return {
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
    };
  } finally {
    oldPrivateKey?.fill(0);
    newPrivateKey?.fill(0);
  }
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
