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
import {
  CONN_OFFSET,
  CONN_RECORD_BYTES,
  FIELD_DESCRIPTOR_OFFSET,
  GRUP_OFFSET,
  HEADER_OFFSET,
  SECTION_KIND,
} from "./bundle/layout.js";
import { readBundle } from "./bundle/reader.js";
import { computeChecksum, writeBundleWithChecksum, writeChecksum } from "./bundle/writer.js";
import { utf8Encode } from "./encoding.js";
import {
  connectionId,
  makeConnection,
  makeFixture,
  makeGroup,
  makeUuid,
} from "./lifecycle.fixture.js";
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

/**
 * H1 — a forged bundle that aliases a mutable field slot to a region the reader
 * hands back in the clear. Every bundle here re-stamps a valid checksum, loads
 * with every field still sealed, and yet — before the fix — would leak a
 * decrypted credential the moment the shard opened the field for a real request.
 * `readBundle` now refuses each at load; the boundary "misroute yes, credential
 * no" holds again.
 */
describe("a forged bundle that aliases a writable slot", () => {
  it("is refused when a connection target is repointed at its own field slot", async () => {
    const { bytes } = await makeFixture();
    const forged = bytes.slice();

    const view = readBundle(forged);
    const record = view.lookup(connectionId(0x00000001));
    const descriptor = record?.field("password");
    if (record === undefined || descriptor === undefined) throw new Error("no field");

    // The plaintext length is public: an envelope is always 60 bytes larger.
    const dv = new DataView(forged.buffer, forged.byteOffset, forged.byteLength);
    dv.setUint32(record.recordOffset + CONN_OFFSET.TARGET_OFFSET, descriptor.strsOffset, true);
    dv.setUint32(record.recordOffset + CONN_OFFSET.TARGET_LENGTH, descriptor.sealedLen - 60, true);
    await restamp(forged);

    expect(() => readBundle(forged)).toThrow(BundleFormatError);
    expect(() => readBundle(forged)).toThrow(/writable slot would be read back/);
  });

  it("is refused when a target is repointed at another connection's field slot", async () => {
    const { bytes } = await makeFixture();
    const forged = bytes.slice();

    const view = readBundle(forged);
    const victim = view.lookup(connectionId(0x00000001));
    const donor = view.lookup(connectionId(0x0000002a));
    const donorField = donor?.field("apiKey");
    if (victim === undefined || donorField === undefined) throw new Error("no field");

    const dv = new DataView(forged.buffer, forged.byteOffset, forged.byteLength);
    dv.setUint32(victim.recordOffset + CONN_OFFSET.TARGET_OFFSET, donorField.strsOffset, true);
    dv.setUint32(victim.recordOffset + CONN_OFFSET.TARGET_LENGTH, donorField.sealedLen - 60, true);
    await restamp(forged);

    expect(() => readBundle(forged)).toThrow(/writable slot would be read back/);
  });

  it("is refused when two field descriptors point at one slot", async () => {
    const { bytes } = await makeFixture();
    const forged = bytes.slice();

    const view = readBundle(forged);
    const record = view.lookup(connectionId(0x00000001));
    const first = record?.field("username");
    const second = record?.field("password");
    if (first === undefined || second === undefined) throw new Error("no fields");

    // Alias the second descriptor onto the first's slot: opening one publishes
    // plaintext the other reads back.
    const dv = new DataView(forged.buffer, forged.byteOffset, forged.byteLength);
    dv.setUint32(
      second.descriptorOffset + FIELD_DESCRIPTOR_OFFSET.STRS_OFFSET,
      first.strsOffset,
      true,
    );
    dv.setUint32(
      second.descriptorOffset + FIELD_DESCRIPTOR_OFFSET.SEALED_LEN,
      first.sealedLen,
      true,
    );
    await restamp(forged);

    expect(() => readBundle(forged)).toThrow(/two writable slots share bytes/);
  });

  it("is refused when a field slot points outside the STRS arena", async () => {
    const { bytes } = await makeFixture();
    const forged = bytes.slice();

    const view = readBundle(forged);
    const record = view.lookup(connectionId(0x00000001));
    const descriptor = record?.field("password");
    if (record === undefined || descriptor === undefined) throw new Error("no field");

    // Point the slot back into the CONN section, where a write-back would corrupt
    // record pointers rather than land in the value arena.
    const dv = new DataView(forged.buffer, forged.byteOffset, forged.byteLength);
    dv.setUint32(
      descriptor.descriptorOffset + FIELD_DESCRIPTOR_OFFSET.STRS_OFFSET,
      record.recordOffset,
      true,
    );
    await restamp(forged);

    expect(() => readBundle(forged)).toThrow(/lies outside the STRS arena/);
  });

  it("still loads a legitimate bundle whose immutable values are interned and shared", async () => {
    // The audit rejects only mutable-slot aliases. A legitimate bundle interns
    // identical targets, visible maps and field-name tables, so many records
    // share one immutable region — which must remain legal.
    const group = await makeGroup({ groupId: makeUuid(0xc3c3c3c3, 3), keys: ["test"] });
    const shared = {
      group,
      target: "https://api.shared.test",
      visible: { tier: "gold", live: true },
      secrets: { token: "shared-secret" },
    };
    const input = {
      header: { version: 1, generation: 1n, shard: "eumc", builtAt: 1n },
      groups: [group.keyGroup],
      connections: [
        await makeConnection({ ...shared, connectionId: connectionId(0x00000011) }),
        await makeConnection({ ...shared, connectionId: connectionId(0x00000012) }),
        await makeConnection({ ...shared, connectionId: connectionId(0x00000013) }),
      ],
      filters: [],
    };
    const bytes = await writeBundleWithChecksum(input);

    const view = readBundle(bytes);
    expect(view.connectionCount).toBe(3);
    const record = view.lookup(connectionId(0x00000012));
    expect(record?.target()).toBe("https://api.shared.test");
  });

  it("is refused when a group's bucket offset points past the buffer", async () => {
    const { bytes } = await makeFixture();
    const forged = bytes.slice();

    const group = readBundle(forged).group(0);
    if (group === undefined) throw new Error("no group");
    const dv = new DataView(forged.buffer, forged.byteOffset, forged.byteLength);
    dv.setUint32(group.recordOffset + GRUP_OFFSET.BUCKET_OFFSET, 0xfffffff0, true);
    await restamp(forged);

    expect(() => readBundle(forged)).toThrow(/bucket entry of group 0 runs past the buffer/);
  });

  it("is refused when the STRS section is dropped but sealed fields remain", async () => {
    const { bytes } = await makeFixture();
    const forged = bytes.slice();

    // Drop STRS — the last section — from the table walk. The field slots still
    // point where STRS was, but there is no longer a declared arena to prove they
    // live inside, so a bundle that still carries sealed fields must be refused.
    const dv = new DataView(forged.buffer, forged.byteOffset, forged.byteLength);
    const sections = dv.getUint32(HEADER_OFFSET.SECTIONS, true);
    dv.setUint32(HEADER_OFFSET.SECTIONS, sections - 1, true);
    await restamp(forged);

    expect(() => readBundle(forged)).toThrow(/must carry a STRS section/);
  });
});
