/**
 * Decrypting a dump — the dangerous operation, kept out of the library.
 *
 * `inspect.ts` deliberately has no path to a key. This module is where the path
 * exists, and it lives under `cli/` rather than beside the format for a reason:
 * the only sanctioned caller is a human at a terminal who has confirmed what
 * they are asking for. Nothing in the shard's read path, the control plane's
 * write path, or the library's public surface reaches it.
 *
 * It works on a *dump*, not on a buffer, so it is a second pass over data
 * `inspectBundle` already produced. That keeps the decrypting code away from
 * offset arithmetic entirely — it cannot read out of bounds because it never
 * reads a buffer.
 */

import { parseUuid } from "../bundle/layout.js";
import { base64Decode, hexDecode, utf8Decode } from "../encoding.js";
import { fieldAssociatedData, open } from "../envelope.js";
import { findBucketEntry, unwrap } from "../group.js";
import { type BundleDump, revealKey } from "../inspect.js";
import { type ApiKeyBytes, asPublicKey, type KeyGroup, type PrivateKey } from "../types.js";

export interface RevealResult {
  /** Field identity (`revealKey`) to plaintext, for the fields this key opens. */
  readonly revealed: ReadonlyMap<string, string>;
  /** Groups and fields this key could not open, said plainly rather than thrown. */
  readonly problems: readonly string[];
  /** How many groups this key holds an entry in. Zero means the wrong key. */
  readonly groupsOpened: number;
}

/**
 * Open every sealed field this API key can reach.
 *
 * A key opens the groups whose bucket carries its key id and nothing else, so a
 * partial result is the normal case, not an error: a tenant with three key
 * groups and a key scoped to one of them gets one group's fields and two
 * problems saying so.
 */
export async function revealDump(
  dump: BundleDump,
  apiKey: ApiKeyBytes,
  tenantId: string,
): Promise<RevealResult> {
  const revealed = new Map<string, string>();
  const problems: string[] = [];
  const privateKeys = new Map<string, PrivateKey>();

  for (const group of dump.groups) {
    const keyGroup: KeyGroup = {
      groupId: group.groupId,
      publicKey: asPublicKey(hexDecode(group.publicKey)),
      generation: group.generation,
      bucket: group.bucket.map((entry) => ({
        keyId: entry.keyId,
        wrapped: base64Decode(entry.wrapped),
      })),
    };
    const entry = await findBucketEntry(keyGroup, apiKey, tenantId);
    if (entry === undefined) {
      problems.push(`group ${group.groupId}: this API key has no entry in the bucket`);
      continue;
    }
    try {
      privateKeys.set(group.groupId, await unwrap(entry, apiKey, tenantId, group.groupId));
    } catch (cause) {
      // The entry names this key id but does not open under it. That is either
      // corruption or the wrong tenant; `unwrap` refuses to say which, and so
      // does this.
      problems.push(`group ${group.groupId}: the bucket entry did not open (${describe(cause)})`);
    }
  }

  for (const connection of dump.connections) {
    const privateKey = privateKeys.get(connection.groupId);
    if (privateKey === undefined) continue;
    for (const [name, field] of Object.entries(connection.sealed)) {
      if (field.state !== "sealed") {
        problems.push(
          `${connection.connectionId}/${name}: already written back; no envelope to open`,
        );
        continue;
      }
      try {
        const plaintext = await open(
          field.envelope,
          privateKey,
          fieldAssociatedData(parseUuid(connection.connectionId), name),
        );
        revealed.set(revealKey(connection.connectionId, name), utf8Decode(plaintext));
      } catch (cause) {
        problems.push(`${connection.connectionId}/${name}: did not open (${describe(cause)})`);
      }
    }
  }

  return { revealed, problems, groupsOpened: privateKeys.size };
}

/**
 * `String(cause)` rather than `cause.message`: every throw on this path is an
 * `Error`, so the branch that distinguishes them can never be taken, and the
 * `name: message` form `String` produces is what a human reading stderr wants
 * anyway — `VaultDecryptionError: ...` says more than the bare message.
 */
function describe(cause: unknown): string {
  return String(cause);
}
