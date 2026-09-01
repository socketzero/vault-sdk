/**
 * Forged bundles.
 *
 * The checksum is unkeyed, so anyone who can write to the store can re-stamp it.
 * That is a stated property of the format, not a bug: `datamodel/bundle` says a
 * forged bundle may be able to misroute a call, but must never be able to
 * *produce a credential*. The one thing standing between those two outcomes is
 * that a freshly loaded bundle is entirely sealed — if a record can arrive with
 * `state == 1`, the open path is skipped and the attacker's bytes are returned
 * as plaintext with no cryptography executed at all.
 *
 * Each test here re-stamps a valid checksum after tampering, because an attack
 * that a checksum catches is not an attack.
 */

import { describe, expect, it } from "vitest";
import { CONN_RECORD_BYTES, FIELD_DESCRIPTOR_OFFSET, SECTION_KIND } from "./bundle/layout.js";
import { readBundle } from "./bundle/reader.js";
import { computeChecksum, writeChecksum } from "./bundle/writer.js";
import { utf8Encode } from "./encoding.js";
import { connectionId, makeFixture } from "./lifecycle.fixture.js";
import { BundleFormatError, FieldState } from "./types.js";

const ATTACKER = "ATTACKER-CREDENTIAL";

/** Re-stamp the checksum so the tampering is not caught by integrity alone. */
async function restamp(bytes: Uint8Array): Promise<Uint8Array> {
  writeChecksum(bytes, await computeChecksum(bytes));
  return bytes;
}

/** Find a section table entry's byte offset by kind. */
function sectionEntryAt(bytes: Uint8Array, kind: number): number {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const sections = dv.getUint32(56, true);
  for (let i = 0; i < sections; i += 1) {
    const at = 64 + i * 16;
    if (dv.getUint32(at, true) === kind) return at;
  }
  throw new Error("section not found");
}

/**
 * Overwrite one field's arena slot with attacker bytes and mark it open, the
 * way somebody with write access to the store would.
 */
function forgeOpenField(bytes: Uint8Array, id: string, fieldName: string): void {
  const view = readBundle(bytes);
  const record = view.lookup(id);
  const descriptor = record?.field(fieldName);
  if (descriptor === undefined) throw new Error(`no field ${fieldName} on ${id}`);

  const payload = utf8Encode(ATTACKER);
  if (payload.length > descriptor.sealedLen) throw new Error("attacker payload does not fit");
  bytes.set(payload, descriptor.strsOffset);

  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  dv.setUint32(
    descriptor.descriptorOffset + FIELD_DESCRIPTOR_OFFSET.PLAIN_LEN,
    payload.length,
    true,
  );
  dv.setUint8(descriptor.descriptorOffset + FIELD_DESCRIPTOR_OFFSET.STATE, FieldState.Open);
}

describe("a bundle forged by someone with write access to the store", () => {
  it("is refused when a field arrives pre-opened", async () => {
    const { bytes } = await makeFixture();
    const forged = bytes.slice();
    forgeOpenField(forged, connectionId(0x00000001), "password");
    await restamp(forged);

    // The checksum is valid. The seal audit is what refuses it.
    expect(() => readBundle(forged)).toThrow(BundleFormatError);
    expect(() => readBundle(forged)).toThrow(
      /arrives open; a freshly loaded bundle is entirely sealed/,
    );
  });

  it("is refused when the forged record is hidden past a lowered CONN count", async () => {
    // The bypass the seal audit had: `assertEntirelySealed` walked `conn.count`,
    // but `lookup` reaches a record through the index and bounds it by
    // `conn.length`. Lowering `count` hid the doctored record from the audit
    // and left it fully reachable — attacker plaintext, valid checksum, no
    // cryptography executed. Both halves are closed now, so this must throw.
    const { bytes } = await makeFixture();
    const forged = bytes.slice();
    forgeOpenField(forged, connectionId(0x0000002a), "apiKey");

    const dv = new DataView(forged.buffer, forged.byteOffset, forged.byteLength);
    const entry = sectionEntryAt(forged, SECTION_KIND.CONN);
    expect(dv.getUint32(entry + 12, true)).toBe(3);
    dv.setUint32(entry + 12, 2, true); // hide the third record from every walk
    await restamp(forged);

    expect(() => readBundle(forged)).toThrow(BundleFormatError);
  });

  it("refuses a CONN section whose count and length disagree in either direction", async () => {
    const { bytes } = await makeFixture();

    for (const count of [2, 4]) {
      const forged = bytes.slice();
      const dv = new DataView(forged.buffer, forged.byteOffset, forged.byteLength);
      const entry = sectionEntryAt(forged, SECTION_KIND.CONN);
      dv.setUint32(entry + 12, count, true);
      await restamp(forged);

      expect(() => readBundle(forged)).toThrow(
        new RegExp(`section CONN claims ${count} records but holds ${3 * CONN_RECORD_BYTES} bytes`),
      );
    }
  });

  it("refuses a FILT section whose count and length disagree", async () => {
    const { bytes } = await makeFixture();
    const forged = bytes.slice();
    const dv = new DataView(forged.buffer, forged.byteOffset, forged.byteLength);
    const entry = sectionEntryAt(forged, SECTION_KIND.FILT);
    dv.setUint32(entry + 12, 0, true);
    await restamp(forged);

    expect(() => readBundle(forged)).toThrow(/section FILT claims 0 records/);
  });

  it("still refuses a group whose private half arrives unwrapped", async () => {
    const { bytes } = await makeFixture();
    const forged = bytes.slice();
    const view = readBundle(forged);
    const group = view.group(0);
    if (group === undefined) throw new Error("no group");
    const descriptor = group.privateKeyDescriptor();

    const dv = new DataView(forged.buffer, forged.byteOffset, forged.byteLength);
    dv.setUint32(descriptor.descriptorOffset + FIELD_DESCRIPTOR_OFFSET.PLAIN_LEN, 32, true);
    dv.setUint8(descriptor.descriptorOffset + FIELD_DESCRIPTOR_OFFSET.STATE, FieldState.Open);
    await restamp(forged);

    expect(() => readBundle(forged)).toThrow(/the private half of group 0 arrives open/);
  });

  it("lets a forged bundle misroute a call — which is the boundary, and is stated", async () => {
    // The format does not claim to prevent this. Someone who can write to the
    // store can point a connection at their own host. What they cannot do is
    // obtain the credential that would be sent there, because the target is
    // visible and the credential is not.
    const { bytes } = await makeFixture();
    const forged = bytes.slice();
    const view = readBundle(forged);
    const record = view.lookup(connectionId(0x00000001));
    const descriptor = record?.field("password");
    if (record === undefined || descriptor === undefined) throw new Error("no field");

    // The ciphertext is still a ciphertext; nothing here reveals it.
    const stored = record.fieldBytes(descriptor);
    expect(descriptor.state).toBe(FieldState.Sealed);
    expect(new TextDecoder().decode(stored)).not.toContain("sk_test");
  });
});
