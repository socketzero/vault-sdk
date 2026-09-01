/**
 * The bundle reader. Used by the shard on the hot path, and by tooling offline.
 *
 * **The bundle is never deserialised.** There is no parse step, no object graph
 * and no instantiation. `readBundle` returns accessors that compute offsets and
 * read through one `DataView` over the caller's buffer, for the life of the
 * isolate. A 10 MiB bundle materialised as objects would end the isolate.
 *
 * A reader must not deserialise, must not copy, must not eagerly open, and must
 * not trust an unknown `version`.
 */

import type { BundleView, FieldDescriptor } from "../types.js";

/**
 * Open a view over a bundle.
 *
 * Validates the magic, the header size and the section table only; the checksum
 * is verified separately via `view.verifyChecksum()`, once, at load.
 *
 * @param buffer the bundle. Held by reference — the view reads and writes back
 *   into these exact bytes.
 * @throws {BundleFormatError} on a bad magic, a truncated header, or a section
 *   table that points outside the buffer.
 * @throws {UnsupportedBundleVersionError} on a version this reader does not
 *   know. Refuse the whole bundle and keep serving the previous generation:
 *   partial understanding of a security artifact is worse than none.
 */
export function readBundle(buffer: Uint8Array | ArrayBuffer): BundleView {
  void buffer;
  throw new Error("not implemented");
}

/**
 * Write plaintext into the slot its own ciphertext occupied, and publish it.
 *
 * Order is load-bearing and synchronous: the plaintext bytes, then `plain_len`,
 * then `state = 1`, with no `await` between them. A reader that sees `state == 1`
 * must be guaranteed the bytes and the length are already there.
 *
 * The write always fits: an envelope is exactly 60 bytes larger than its
 * plaintext, unconditionally.
 *
 * A duplicated open is harmless — two callers write identical bytes to identical
 * offsets and the second flag write is a no-op — which is why there is no lock
 * on this path.
 *
 * @param buffer the buffer the caller *started* from. The unwrap is async and a
 *   refresh can swap the active buffer mid-flight; writing into the newly active
 *   one would place plaintext at an offset that means something else.
 * @returns the descriptor as it now reads.
 * @throws {RangeError} if the plaintext does not fit the sealed slot.
 */
export function writeBackPlaintext(
  buffer: Uint8Array,
  descriptor: FieldDescriptor,
  plaintext: Uint8Array,
): FieldDescriptor {
  void buffer;
  void descriptor;
  void plaintext;
  throw new Error("not implemented");
}

/** Read one field descriptor in place. */
export function readFieldDescriptor(buffer: Uint8Array, descriptorOffset: number): FieldDescriptor {
  void buffer;
  void descriptorOffset;
  throw new Error("not implemented");
}

/**
 * Zero everything past `length`.
 *
 * Called on every load: after a swap the inactive buffer still holds the
 * previous generation's opened plaintext, and if the new bundle is shorter the
 * tail would never be overwritten at all. Residue must not outlive the
 * generation it belonged to.
 */
export function zeroTail(buffer: Uint8Array, length: number): void {
  void buffer;
  void length;
  throw new Error("not implemented");
}

/**
 * Perform a dummy unwrap against a fixed decoy group.
 *
 * A miss costs one read and a hit costs a read, an unwrap and a decrypt; the
 * difference is observable and says whether a connection id exists. The shard
 * promises every pre-relay refusal is indistinguishable, and that promise has
 * to cover elapsed time. Roughly 0.03 ms, on a path that is already refusing.
 */
export function decoyUnwrap(): Promise<void> {
  void 0;
  throw new Error("not implemented");
}
