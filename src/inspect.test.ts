/**
 * The dump, and the two properties that make it worth having.
 *
 * It must never print a secret it was not handed, and a whole dump must rebuild
 * the exact bytes it came from. Everything else here is detail.
 */

import { describe, expect, it } from "vitest";
import { readBundle } from "./bundle/reader.js";
import { writeBundle, writeBundleWithChecksum } from "./bundle/writer.js";
import { utf8Encode } from "./encoding.js";
import {
  BUNDLE_CAP_BYTES,
  type BundleDump,
  BundleDumpError,
  bundleFromJSON,
  DUMP_FORMAT,
  DUMP_FORMAT_VERSION,
  inspectBundle,
  RECORD_BYTES,
  revealKey,
  SECTION_KINDS,
  verifyBundle,
} from "./inspect.js";
import { connectionId, flipByte, makeFixture, SHARD } from "./lifecycle.fixture.js";
import { FieldState } from "./types.js";

/** JSON.parse(JSON.stringify(x)) — proves the dump really is JSON-safe. */
function throughJSON(dump: BundleDump): BundleDump {
  return JSON.parse(JSON.stringify(dump)) as BundleDump;
}

describe("a dump of a whole bundle", () => {
  it("carries the header the writer stamped, uint64s as decimal strings", async () => {
    const { bytes, input } = await makeFixture();
    const dump = throughJSON(inspectBundle(readBundle(bytes)));

    expect(dump.format).toBe(DUMP_FORMAT);
    expect(dump.formatVersion).toBe(DUMP_FORMAT_VERSION);
    expect(dump.header.magic).toBe("S0BUNDLE");
    expect(dump.header.shard).toBe(SHARD);
    // JSON has no uint64, so a generation survives as a string or not at all.
    expect(dump.header.generation).toBe("47");
    expect(dump.header.builtAt).toBe(input.header.builtAt.toString());
    expect(typeof dump.header.generation).toBe("string");
  });

  it("is not partial, and says so", async () => {
    const { bytes } = await makeFixture();
    const dump = inspectBundle(readBundle(bytes));
    expect(dump.partial).toBe(false);
    expect(dump.partialReason).toBeUndefined();
    expect(dump.page).toEqual({ offset: 0, limit: null, returned: 3, total: 3 });
  });

  it("names every section in buffer order with its own record count", async () => {
    const { bytes } = await makeFixture();
    const dump = inspectBundle(readBundle(bytes));
    expect(dump.sections.map((s) => s.kind)).toEqual(["INDX", "CONN", "GRUP", "FILT", "STRS"]);
    for (const section of dump.sections) {
      expect(section.offset).toBeGreaterThan(0);
      expect(section.length).toBeGreaterThan(0);
    }
  });

  it("reports the visible configuration with its types intact", async () => {
    const { bytes } = await makeFixture();
    const dump = inspectBundle(readBundle(bytes));
    const first = dump.connections[0];
    if (first === undefined) throw new Error("no connections in the fixture");

    expect(first.connectionId).toBe(connectionId(0x00000001));
    expect(first.target).toBe("https://api.stripe.com");
    // A number stays a number and a boolean stays a boolean: the arena stores
    // them tagged, and a dump that stringified them would hide a writer bug.
    expect(first.visible).toEqual({ limit: 100, live: true, label: "primary" });
    expect(first.expiresAt).toBe(1_800_000_000_000);
    expect(first.filters).toEqual([0]);
  });

  it("reports a connection that does not expire as null, not as zero", async () => {
    const { bytes } = await makeFixture();
    const dump = inspectBundle(readBundle(bytes));
    expect(dump.connections[1]?.expiresAt).toBeNull();
    expect(dump.connections[1]?.filters).toEqual([]);
  });

  it("gives each group its public half in the clear and its bucket key ids", async () => {
    const { bytes, groups } = await makeFixture();
    const dump = inspectBundle(readBundle(bytes));

    expect(dump.groups).toHaveLength(2);
    expect(dump.groups[0]?.groupId).toBe(groups[0]?.groupId);
    // The public half is public. There is nothing here to protect.
    expect(dump.groups[0]?.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(dump.groups[0]?.bucket).toHaveLength(2);
    expect(dump.groups[0]?.bucket[0]?.keyId).toMatch(/^[0-9a-f]{32}$/);
  });

  it("carries a filter's kind and its opaque arguments", async () => {
    const { bytes } = await makeFixture();
    const dump = inspectBundle(readBundle(bytes));
    expect(dump.filters).toHaveLength(1);
    expect(dump.filters[0]?.kind).toBe(1);
    expect(dump.filters[0]?.args).toBe(
      Buffer.from(utf8Encode("allow:GET,POST")).toString("base64"),
    );
  });
});

// ---------------------------------------------------------------------------
// The property the module exists for
// ---------------------------------------------------------------------------

describe("a sealed field", () => {
  it("renders as its envelope and its length — never as a secret", async () => {
    const { bytes } = await makeFixture();
    const dump = inspectBundle(readBundle(bytes));
    const field = dump.connections[0]?.sealed["password"];

    expect(field?.state).toBe("sealed");
    if (field === undefined || field.state !== "sealed") throw new Error("expected a sealed field");
    expect(field.envelope.startsWith("x25519-hkdf-aesgcm:")).toBe(true);
    expect(field.sealedBytes).toBeGreaterThan(60);
    expect("value" in field).toBe(false);
  });

  it("does not contain any plaintext anywhere in the serialised dump", async () => {
    const { bytes } = await makeFixture();
    const json = JSON.stringify(inspectBundle(readBundle(bytes)));
    // The fixture's actual secrets. If any of these appear, the dump leaks.
    for (const secret of ["acct_1QZ", "sk_test_51H", "AC0123456789", "SG.xxxxxxxx"]) {
      expect(json).not.toContain(secret);
    }
  });

  it("shows plaintext only when the caller hands it in, and marks every one", async () => {
    const { bytes } = await makeFixture();
    const view = readBundle(bytes);
    const id = connectionId(0x00000001);
    const revealed = new Map([[revealKey(id, "password"), "sk_test_51H"]]);

    const dump = inspectBundle(view, { revealed });
    const opened = dump.connections[0]?.sealed["password"];
    const untouched = dump.connections[0]?.sealed["username"];

    if (opened === undefined || opened.state !== "sealed" || !("revealed" in opened)) {
      throw new Error("expected the revealed field");
    }
    expect(opened.revealed).toBe(true);
    expect(opened.value).toBe("sk_test_51H");
    // The field the caller did not decrypt stays opaque, and carries no marker.
    expect(untouched && "revealed" in untouched).toBe(false);
  });

  it("shows a written-back field as open, with no envelope to recover", async () => {
    const { bytes } = await makeFixture();
    const view = readBundle(bytes);
    const record = view.lookup(connectionId(0x00000001));
    const descriptor = record?.field("password");
    if (record === undefined || descriptor === undefined) throw new Error("no field to write back");

    view.writeBack(descriptor, utf8Encode("plain"));
    const dump = inspectBundle(view);
    const field = dump.connections[0]?.sealed["password"];

    expect(field?.state).toBe("open");
    if (field === undefined || field.state !== "open") throw new Error("expected an open field");
    expect(field.plainBytes).toBe(5);
    // The write-back destroyed the ciphertext, so the dump is no longer a
    // faithful description of a publishable generation.
    expect(dump.partial).toBe(true);
    expect(dump.partialReason?.join(" ")).toContain("written back");
  });
});

// ---------------------------------------------------------------------------
// Paging
// ---------------------------------------------------------------------------

describe("paging", () => {
  it("returns the window asked for and reports the total", async () => {
    const { bytes } = await makeFixture();
    const view = readBundle(bytes);
    const dump = inspectBundle(view, { offset: 1, limit: 1 });

    expect(dump.connections).toHaveLength(1);
    expect(dump.connections[0]?.connectionId).toBe(connectionId(0x00000009));
    expect(dump.page).toEqual({ offset: 1, limit: 1, returned: 1, total: 3 });
    expect(dump.partial).toBe(true);
    expect(dump.partialReason?.join(" ")).toContain("connections 1..2 of 3");
  });

  it("clamps a limit past the end rather than failing", async () => {
    const { bytes } = await makeFixture();
    const dump = inspectBundle(readBundle(bytes), { offset: 2, limit: 100 });
    expect(dump.connections).toHaveLength(1);
    expect(dump.partial).toBe(true);
  });

  it("returns nothing past the end, and still carries the groups and stats", async () => {
    const { bytes } = await makeFixture();
    const dump = inspectBundle(readBundle(bytes), { offset: 99 });
    expect(dump.connections).toHaveLength(0);
    // The point of `stat`: totals without paying for the records.
    expect(dump.groups).toHaveLength(2);
    expect(dump.stats.connectionCount).toBe(3);
  });

  it("treats limit 0 as 'the totals only' — and the totals are still totals", async () => {
    const { bytes } = await makeFixture();
    const dump = inspectBundle(readBundle(bytes), { limit: 0 });

    expect(dump.connections).toHaveLength(0);
    expect(dump.stats.connectionCount).toBe(3);
    // Field counts walk the whole generation rather than the rendered page:
    // this is exactly what `stat` asks for, and a zero here would be a lie
    // about a bundle full of sealed fields.
    expect(dump.stats.sealedFieldCount).toBe(4);
    expect(dump.stats.openFieldCount).toBe(0);
  });

  it("rejects a negative or fractional offset or limit", async () => {
    const { bytes } = await makeFixture();
    const view = readBundle(bytes);
    expect(() => inspectBundle(view, { offset: -1 })).toThrow(BundleDumpError);
    expect(() => inspectBundle(view, { limit: 1.5 })).toThrow(BundleDumpError);
  });
});

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

describe("stats", () => {
  it("counts the records and holds the index load factor at or under a quarter", async () => {
    const { bytes } = await makeFixture();
    const s = inspectBundle(readBundle(bytes)).stats;

    expect(s.connectionCount).toBe(3);
    expect(s.groupCount).toBe(2);
    expect(s.filterCount).toBe(1);
    expect(s.sealedFieldCount).toBe(4);
    expect(s.openFieldCount).toBe(0);
    expect(s.bucketEntryCount).toBe(3);
    expect(s.indexLoadFactor).toBeLessThanOrEqual(0.25);
    expect(s.totalBytes).toBe(bytes.length);
    expect(s.capBytesRemaining).toBe(BUNDLE_CAP_BYTES - bytes.length);
  });

  it("accounts every section's bytes", async () => {
    const { bytes } = await makeFixture();
    const s = inspectBundle(readBundle(bytes)).stats;
    const sum = Object.values(s.sectionBytes).reduce((a, b) => a + b, 0);
    // Everything but the fixed header and the section table.
    expect(sum).toBeLessThan(bytes.length);
    expect(sum).toBeGreaterThan(0);
  });

  it("re-exports the record widths and section kinds tooling prints", () => {
    expect(RECORD_BYTES.connection).toBe(192);
    expect(RECORD_BYTES.indexSlot).toBe(8);
    expect(SECTION_KINDS.INDX).toBeTypeOf("number");
  });
});

// ---------------------------------------------------------------------------
// The round trip
// ---------------------------------------------------------------------------

describe("bin -> JSON -> bin", () => {
  it("reproduces the original bytes exactly", async () => {
    const { bytes } = await makeFixture();
    const dump = throughJSON(inspectBundle(readBundle(bytes)));

    const rebuilt = await writeBundleWithChecksum(bundleFromJSON(dump));

    // Byte-identical, not merely equivalent. This is what lets a dump be
    // committed as a golden vector: a future refactor that changes the layout
    // fails here rather than silently shipping a bundle a shard cannot read.
    expect(rebuilt).toEqual(bytes);
  });

  it("survives a second round trip, so the dump is a fixed point", async () => {
    const { bytes } = await makeFixture();
    const once = await writeBundleWithChecksum(bundleFromJSON(inspectBundle(readBundle(bytes))));
    const twice = await writeBundleWithChecksum(bundleFromJSON(inspectBundle(readBundle(once))));
    expect(twice).toEqual(once);
  });

  it("rebuilds a bundle a real API key can still open", async () => {
    const { bytes } = await makeFixture();
    const rebuilt = await writeBundleWithChecksum(bundleFromJSON(inspectBundle(readBundle(bytes))));
    const view = readBundle(rebuilt);

    expect(await view.verifyChecksum()).toBe(true);
    const record = view.lookup(connectionId(0x00000009));
    expect(record?.target()).toBe("https://api.twilio.com");
    expect(record?.field("token")?.state).toBe(FieldState.Sealed);
  });

  it("refuses a paged dump instead of rebuilding something smaller", async () => {
    const { bytes } = await makeFixture();
    const dump = inspectBundle(readBundle(bytes), { limit: 1 });
    expect(() => bundleFromJSON(dump)).toThrow(/cannot rebuild a partial dump/);
  });

  it("refuses a dump containing a written-back field", async () => {
    const { bytes } = await makeFixture();
    const view = readBundle(bytes);
    const descriptor = view.lookup(connectionId(0x00000001))?.field("password");
    if (descriptor === undefined) throw new Error("no field");
    view.writeBack(descriptor, utf8Encode("plain"));

    expect(() => bundleFromJSON(inspectBundle(view))).toThrow(/cannot rebuild a partial dump/);
  });

  it("refuses an open field even when the dump was hand-edited to look whole", async () => {
    const { bytes } = await makeFixture();
    const view = readBundle(bytes);
    const descriptor = view.lookup(connectionId(0x00000001))?.field("password");
    if (descriptor === undefined) throw new Error("no field");
    view.writeBack(descriptor, utf8Encode("plain"));

    const forged = { ...inspectBundle(view), partial: false, partialReason: undefined };
    expect(() => bundleFromJSON(forged as unknown as BundleDump)).toThrow(
      /is open; its envelope cannot be recovered/,
    );
  });

  it("refuses a file that is not a dump", () => {
    expect(() => bundleFromJSON({ format: "something-else" } as unknown as BundleDump)).toThrow(
      /not a bundle dump/,
    );
  });

  it("refuses a dump format version it does not know", async () => {
    const { bytes } = await makeFixture();
    const dump = { ...inspectBundle(readBundle(bytes)), formatVersion: 99 };
    expect(() => bundleFromJSON(dump as unknown as BundleDump)).toThrow(
      /unsupported dump format version 99/,
    );
  });

  it("refuses a partial dump whose reason was stripped", async () => {
    const { bytes } = await makeFixture();
    const dump = { ...inspectBundle(readBundle(bytes)), partial: true };
    expect(() => bundleFromJSON(dump as BundleDump)).toThrow(/reason not recorded/);
  });

  it("refuses a public key that is not hex, and a bucket entry that is not base64", async () => {
    const { bytes } = await makeFixture();
    const base = inspectBundle(readBundle(bytes));
    const [first, ...rest] = base.groups;
    const entry = first?.bucket[0];
    if (first === undefined || entry === undefined) throw new Error("fixture has no bucket entry");

    /** `base`, with its first group replaced by one field's worth of damage. */
    const damaged = (group: Record<string, unknown>): BundleDump =>
      ({ ...base, groups: [{ ...first, ...group }, ...rest] }) as unknown as BundleDump;

    expect(() => bundleFromJSON(damaged({ publicKey: "zz" }))).toThrow(/is not valid hex/);
    expect(() => bundleFromJSON(damaged({ publicKey: 7 }))).toThrow(/is not a hex string/);
    expect(() =>
      bundleFromJSON(damaged({ bucket: [{ keyId: entry.keyId, wrapped: "!!!!" }] })),
    ).toThrow(/is not valid base64/);
    expect(() => bundleFromJSON(damaged({ bucket: [{ keyId: entry.keyId, wrapped: 7 }] }))).toThrow(
      /is not a base64 string/,
    );
  });

  it("refuses filter arguments that are not base64", async () => {
    const { bytes } = await makeFixture();
    const base = inspectBundle(readBundle(bytes));
    const bad = { ...base, filters: [{ kind: 1, args: "!!!" }] };
    expect(() => bundleFromJSON(bad as BundleDump)).toThrow(/filter 0 args is not valid base64/);
  });
});

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

describe("verifyBundle", () => {
  it("passes a bundle straight off the writer", async () => {
    const { bytes } = await makeFixture();
    const report = await verifyBundle(readBundle(bytes));

    expect(report.ok).toBe(true);
    expect(report.checksumValid).toBe(true);
    // The check a checksum cannot make: every record is reachable through the
    // index, at the offset the index claims.
    expect(report.indexResolved).toBe(report.connectionCount);
    expect(report.problems).toEqual([]);
  });

  it("catches a corrupted body", async () => {
    const { bytes } = await makeFixture();
    const corrupted = bytes.slice();
    // Flip a bit well past the header, so only the checksum notices.
    flipByte(corrupted, corrupted.length - 1);

    const report = await verifyBundle(readBundle(corrupted));
    expect(report.checksumValid).toBe(false);
    expect(report.ok).toBe(false);
    expect(report.problems.join(" ")).toContain("checksum does not match");
  });

  it("catches an index slot pointed at the wrong record", async () => {
    const { bytes, input } = await makeFixture();
    const view = readBundle(bytes);
    const indx = view.section("INDX");
    const conn = view.section("CONN");
    if (indx === undefined || conn === undefined) throw new Error("no sections");

    const damaged = bytes.slice();
    const dv = new DataView(damaged.buffer, damaged.byteOffset, damaged.byteLength);
    // Repoint every occupied slot at the first record. Two connections then
    // resolve to an offset that is not theirs, and one still resolves correctly.
    for (let slot = 0; slot < indx.count; slot += 1) {
      const at = indx.offset + slot * 8;
      if (dv.getUint32(at + 4, true) !== 0) dv.setUint32(at + 4, conn.offset, true);
    }

    const report = await verifyBundle(readBundle(damaged));
    expect(report.ok).toBe(false);
    expect(report.indexResolved).toBeLessThan(input.connections.length);
    expect(report.problems.join(" ")).toMatch(
      /resolves to record offset|not addressable|unreadable/,
    );
  });

  it("catches a view that counts connections but exposes no CONN section", async () => {
    const { bytes } = await makeFixture();
    const view = readBundle(bytes);
    // `readBundle` refuses a bundle with no CONN section outright, so this
    // state is only reachable through a hand-built view. The branch stays
    // because `BundleView` is an interface a caller may implement, and a
    // verifier that trusted its input would be the wrong shape of tool.
    const headless = {
      ...view,
      section: (kind: "INDX" | "CONN" | "GRUP" | "FILT" | "STRS") =>
        kind === "CONN" ? undefined : view.section(kind),
    };

    const report = await verifyBundle(headless);
    expect(report.ok).toBe(false);
    expect(report.problems.join(" ")).toContain("CONN section missing");
    // The dump degrades the same way: totals, no records, rather than a throw.
    expect(inspectBundle(headless).connections).toHaveLength(0);
  });

  it("catches an index sized for a different number of connections", async () => {
    const { input } = await makeFixture();
    // Write a bundle, then lie in the INDX section's record count.
    const bytes = await writeBundleWithChecksum(input);
    const view = readBundle(bytes);
    const indx = view.section("INDX");
    if (indx === undefined) throw new Error("no INDX section");

    const damaged = bytes.slice();
    const dv = new DataView(damaged.buffer, damaged.byteOffset, damaged.byteLength);
    for (let i = 0; i < view.header.sections; i += 1) {
      const at = 64 + i * 16;
      if (dv.getUint32(at, true) === SECTION_KINDS.INDX) dv.setUint32(at + 12, 4, true);
    }

    const report = await verifyBundle(readBundle(damaged));
    expect(report.problems.join(" ")).toMatch(/index has 4 slots/);
  });

  it("reports an empty generation as ok", async () => {
    const bytes = await writeBundleWithChecksum({
      header: { version: 1, generation: 1n, shard: SHARD, builtAt: 1n },
      groups: [],
      connections: [],
      filters: [],
    });
    const report = await verifyBundle(readBundle(bytes));
    expect(report.ok).toBe(true);
    expect(report.connectionCount).toBe(0);
  });

  it("round-trips an empty generation too", async () => {
    const input = {
      header: { version: 1, generation: 1n, shard: SHARD, builtAt: 1n },
      groups: [],
      connections: [],
      filters: [],
    };
    const bytes = await writeBundleWithChecksum(input);
    const rebuilt = await writeBundleWithChecksum(bundleFromJSON(inspectBundle(readBundle(bytes))));
    expect(rebuilt).toEqual(bytes);
  });

  it("notices a bundle over the ten-mebibyte cap", async () => {
    const { bytes } = await makeFixture();
    const view = readBundle(bytes);
    // The cap is a property of the buffer's length, so a view over an
    // oversized buffer is the honest way to reach the branch.
    const oversized = { ...view, buffer: new Uint8Array(BUNDLE_CAP_BYTES + 1) };
    const report = await verifyBundle(oversized);
    expect(report.problems.join(" ")).toContain("over the");
  });
});

describe("verifyBundle against a view that lies about itself", () => {
  /**
   * `readBundle` now rejects most malformed bundles at load — the CONN section's
   * count and length must agree exactly, and every addressable record must
   * arrive sealed. That is the right place for those checks, and it leaves
   * `verifyBundle`'s remaining branches reachable only through a hand-built
   * view. They stay because `BundleView` is an interface: a debugging tool that
   * assumed its input was well-formed would be the wrong shape of tool.
   */
  async function view() {
    const { bytes } = await makeFixture();
    return readBundle(bytes);
  }

  it("reports a record the index cannot resolve", async () => {
    const real = await view();
    const report = await verifyBundle({ ...real, lookup: () => undefined });
    expect(report.indexResolved).toBe(0);
    expect(report.problems.join(" ")).toContain("is not addressable through the index");
  });

  it("reports a record the index resolves to somebody else's offset", async () => {
    const real = await view();
    const conn = real.section("CONN");
    if (conn === undefined) throw new Error("no CONN section");
    const decoy = real.connectionAt(conn.offset);

    const report = await verifyBundle({ ...real, lookup: () => decoy });
    // The first record resolves to itself; the other two resolve to it too.
    expect(report.indexResolved).toBe(1);
    expect(report.problems.join(" ")).toContain("resolves to record offset");
  });

  it("reports a connection naming a group that is not there", async () => {
    const real = await view();
    const report = await verifyBundle({ ...real, group: () => undefined });
    expect(report.problems.join(" ")).toContain("which does not exist");
  });

  it("reports an unreadable record rather than throwing, whatever was thrown", async () => {
    const real = await view();

    const errored = await verifyBundle({
      ...real,
      connectionAt: () => {
        throw new Error("offset arithmetic went off the end");
      },
    });
    expect(errored.ok).toBe(false);
    expect(errored.problems[0]).toContain("is unreadable: offset arithmetic went off the end");

    // A non-Error throw is still a diagnosis, not a crash.
    const thrown = await verifyBundle({
      ...real,
      connectionAt: () => {
        throw "not an Error at all";
      },
    });
    expect(thrown.problems[0]).toContain("is unreadable: not an Error at all");
  });
});

describe("a view that reports records it will not hand over", () => {
  /**
   * Every accessor on `BundleView` is allowed to return `undefined`, and
   * `inspectBundle` walks all of them by count. A view whose counts and
   * accessors disagree is not something `readBundle` produces — but it is
   * exactly what a partially-implemented view, or a future section, looks like.
   * Degrading to fewer records beats throwing on the tool of last resort.
   */
  async function real() {
    const { bytes } = await makeFixture();
    return readBundle(bytes);
  }

  it("skips a group, a bucket entry and a filter it is not given", async () => {
    const view = await real();
    const dump = inspectBundle({
      ...view,
      group: () => undefined,
      filter: () => undefined,
    });

    expect(dump.groups).toEqual([]);
    expect(dump.filters).toEqual([]);
    expect(dump.stats.bucketEntryCount).toBe(0);
    // A connection whose group vanished keeps its own identity and loses only
    // the group id, rather than taking the whole dump down with it.
    expect(dump.connections).toHaveLength(3);
    expect(dump.connections[0]?.groupId).toBe("");
  });

  it("skips a bucket entry the group will not hand over", async () => {
    const view = await real();
    const dump = inspectBundle({
      ...view,
      group: (i) => {
        const group = view.group(i);
        return group === undefined ? undefined : { ...group, bucketEntry: () => undefined };
      },
    });
    expect(dump.stats.bucketEntryCount).toBe(0);
    expect(dump.groups).toHaveLength(2);
    expect(dump.groups[0]?.bucket).toEqual([]);
  });

  it("skips a visible key and a field name the record will not resolve", async () => {
    const view = await real();
    const conn = view.section("CONN");
    if (conn === undefined) throw new Error("no CONN section");

    const dump = inspectBundle({
      ...view,
      connectionAt: (offset) => {
        const record = view.connectionAt(offset);
        return {
          ...record,
          // Both lists name something the accessors then decline to produce.
          visibleKeys: () => [...record.visibleKeys(), "ghost"],
          fieldNames: () => [...record.fieldNames(), "phantom"],
          visible: (name) => (name === "ghost" ? undefined : record.visible(name)),
          field: (name) => (name === "phantom" ? undefined : record.field(name)),
        };
      },
    });

    const first = dump.connections[0];
    expect(first).toBeDefined();
    expect(Object.keys(first?.visible ?? {})).not.toContain("ghost");
    expect(Object.keys(first?.sealed ?? {})).not.toContain("phantom");
    // The real ones are all still there.
    expect(Object.keys(first?.sealed ?? {}).sort()).toEqual(["password", "username"]);
  });

  it("falls back to a computed slot count and a zero filter count with no sections", async () => {
    const view = await real();
    const dump = inspectBundle({ ...view, section: () => undefined });

    expect(dump.sections).toEqual([]);
    expect(dump.stats.filterCount).toBe(0);
    // No INDX section to read, so the slot count is derived the way the writer
    // would have derived it.
    expect(dump.stats.indexSlots).toBe(16);
    expect(dump.stats.indexLoadFactor).toBeCloseTo(3 / 16);
  });

  it("reports a load factor of zero rather than dividing by it", async () => {
    const view = await real();
    const dump = inspectBundle({
      ...view,
      connectionCount: 0,
      section: (kind) =>
        kind === "INDX" ? { kind: 0, offset: 0, length: 0, count: 0 } : undefined,
    });
    expect(dump.stats.indexSlots).toBe(0);
    expect(dump.stats.indexLoadFactor).toBe(0);
  });

  it("stays quiet about a missing CONN section when there are no connections", async () => {
    const view = await real();
    const report = await verifyBundle({
      ...view,
      connectionCount: 0,
      section: () => undefined,
    });
    // Nothing to walk, so nothing to complain about on that count — the only
    // problem is the index, which is now reported as zero slots.
    expect(report.problems.join(" ")).not.toContain("CONN section missing");
    expect(report.problems.join(" ")).toContain("index has 0 slots");
  });
});

describe("a bundle whose checksum was never stamped", () => {
  it("dumps fine and fails verification, which is the correct pair", async () => {
    const { input } = await makeFixture();
    const unstamped = writeBundle(input);
    const view = readBundle(unstamped);

    // A dump is a view, not an assertion of integrity: it must work on a broken
    // bundle, because a broken bundle is exactly when someone reaches for it.
    expect(inspectBundle(view).stats.connectionCount).toBe(3);
    expect((await verifyBundle(view)).checksumValid).toBe(false);
  });
});
