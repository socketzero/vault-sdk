/**
 * A real tenant, built the way the control plane builds one.
 *
 * Test-only, and excluded from coverage — but deliberately *not* a stub. Every
 * key here is a real X25519 keypair, every API key comes out of
 * `generateApiKey`, every envelope is a real seal and the bundle is the writer's
 * own output. A fixture that faked any of that would prove the tests pass and
 * nothing else.
 */

import { generateApiKey } from "./api-key.js";
import { parseUuid } from "./bundle/layout.js";
import { writeBundleWithChecksum } from "./bundle/writer.js";
import { utf8Encode } from "./encoding.js";
import { fieldAssociatedData, seal } from "./envelope.js";
import { buildBucket, generateGroup } from "./group.js";
import type {
  ApiKeyMaterial,
  BundleInput,
  ConnectionInput,
  GroupKeyPair,
  KeyGroup,
  SealedEnvelope,
} from "./types.js";

export const TENANT = "tnt_01j9x4m2q8";
export const SHARD = "eumc";

/** `high32`, eight zero bytes, `low32` — a UUID whose index bucket is chosen. */
export function makeUuid(high32: number, low32: number): string {
  const hex = `${(high32 >>> 0).toString(16).padStart(8, "0")}0000000000000000${(low32 >>> 0)
    .toString(16)
    .padStart(8, "0")}`;
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** A connection id is a bare canonical UUID; shards are not in the format. */
export function connectionId(low32: number): string {
  return makeUuid(0x0192a7c1, low32);
}

/** What one group looks like once the control plane has finished with it. */
export interface FixtureGroup {
  readonly groupId: string;
  readonly pair: GroupKeyPair;
  readonly keys: readonly ApiKeyMaterial[];
  readonly keyGroup: KeyGroup;
}

export interface FixtureSpec {
  readonly groupId: string;
  /** How many API keys go in this group's bucket, and in which environment. */
  readonly keys: readonly ("live" | "test")[];
}

export async function makeGroup(spec: FixtureSpec, tenantId = TENANT): Promise<FixtureGroup> {
  const pair = await generateGroup();
  const keys = spec.keys.map((environment) => generateApiKey(environment));
  const bucket = await buildBucket(
    pair.privateKey,
    keys.map((key) => key.bytes),
    tenantId,
    spec.groupId,
  );
  return {
    groupId: spec.groupId,
    pair,
    keys,
    keyGroup: { groupId: spec.groupId, publicKey: pair.publicKey, generation: 0, bucket },
  };
}

export interface ConnectionSpec {
  readonly connectionId: string;
  readonly group: FixtureGroup;
  readonly target: string;
  readonly visible?: Record<string, string | number | boolean>;
  readonly secrets: Record<string, string>;
  readonly filters?: readonly number[];
  readonly expiresAt?: number | null;
}

/** Seal every secret to the group's public half — no private key involved. */
export async function makeConnection(spec: ConnectionSpec): Promise<ConnectionInput> {
  const sealed: Record<string, SealedEnvelope> = {};
  for (const [name, value] of Object.entries(spec.secrets)) {
    sealed[name] = await seal(
      utf8Encode(value),
      spec.group.pair.publicKey,
      fieldAssociatedData(parseUuid(spec.connectionId), name),
    );
  }
  return {
    connectionId: spec.connectionId,
    groupId: spec.group.groupId,
    target: spec.target,
    visible: spec.visible ?? {},
    sealed,
    filters: spec.filters ?? [],
    expiresAt: spec.expiresAt ?? null,
  };
}

export interface Fixture {
  readonly groups: readonly FixtureGroup[];
  readonly input: BundleInput;
  readonly bytes: Uint8Array;
}

/**
 * The default shape: two groups, three connections, a filter, and a connection
 * that shares an index bucket with another so the probe path is always live.
 */
export async function makeFixture(tenantId = TENANT): Promise<Fixture> {
  const alpha = await makeGroup(
    { groupId: makeUuid(0xa1a1a1a1, 1), keys: ["test", "live"] },
    tenantId,
  );
  const beta = await makeGroup({ groupId: makeUuid(0xb2b2b2b2, 2), keys: ["test"] }, tenantId);

  const connections = [
    await makeConnection({
      connectionId: connectionId(0x00000001),
      group: alpha,
      target: "https://api.stripe.com",
      visible: { limit: 100, live: true, label: "primary" },
      secrets: { username: "acct_1QZ", password: "sk_test_51H" },
      filters: [0],
      expiresAt: 1_800_000_000_000,
    }),
    await makeConnection({
      // Same low 32 bits as the first once masked at the floor slot count, so
      // the reader's linear probe is exercised by the default fixture.
      connectionId: connectionId(0x00000009),
      group: alpha,
      target: "https://api.twilio.com",
      visible: { limit: 25.5 },
      secrets: { token: "AC0123456789" },
    }),
    await makeConnection({
      connectionId: connectionId(0x0000002a),
      group: beta,
      target: "https://api.sendgrid.com",
      visible: {},
      secrets: { apiKey: "SG.xxxxxxxx" },
    }),
  ];

  const input: BundleInput = {
    header: { version: 1, generation: 47n, builtAt: 1_726_000_000_000n },
    groups: [alpha.keyGroup, beta.keyGroup],
    connections,
    filters: [{ kind: 1, args: utf8Encode("allow:GET,POST") }],
  };

  return { groups: [alpha, beta], input, bytes: await writeBundleWithChecksum(input) };
}

/**
 * Flip bits in one byte, in place.
 *
 * A helper rather than `bytes[i] ^= mask` at each call site because
 * `noUncheckedIndexedAccess` types that read as `number | undefined`, and the
 * honest fix is a bounds check rather than an assertion that silences one.
 */
export function flipByte(bytes: Uint8Array, index: number, mask = 0x01): void {
  const current = bytes[index];
  if (current === undefined) throw new RangeError(`index ${index} is outside the buffer`);
  bytes[index] = current ^ mask;
}
