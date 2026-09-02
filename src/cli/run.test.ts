/**
 * The tool, against a fake terminal.
 *
 * `CliIO` exists so this file can exercise the reveal gate without a TTY and
 * without a real filesystem. The gate is the part worth the trouble: it is the
 * only path in the package that prints a credential, and every one of its three
 * refusals is tested here as a refusal, not as an option.
 */

import { describe, expect, it } from "vitest";
import { generateApiKey } from "../api-key.js";
import { readBundle } from "../bundle/reader.js";
import { writeBundleWithChecksum } from "../bundle/writer.js";
import { utf8Decode, utf8Encode } from "../encoding.js";
import { type BundleDump, inspectBundle, revealKey } from "../inspect.js";
import { connectionId, flipByte, makeFixture, TENANT } from "../lifecycle.fixture.js";
import { revealDump } from "./reveal.js";
import { type CliIO, PLAINTEXT_ENV_VAR, REVEAL_PHRASE, runCli, USAGE } from "./run.js";

interface Harness {
  readonly io: CliIO;
  readonly stdout: string[];
  readonly stderr: string[];
  readonly written: Map<string, Uint8Array>;
  readonly prompts: string[];
}

function harness(
  files: Record<string, Uint8Array | string>,
  options: {
    interactive?: boolean;
    answer?: string;
    env?: Record<string, string | undefined>;
  } = {},
): Harness {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const written = new Map<string, Uint8Array>();
  const prompts: string[] = [];

  const io: CliIO = {
    readFile: async (path) => {
      const file = files[path];
      if (file === undefined) throw new Error(`no such file: ${path}`);
      return typeof file === "string" ? utf8Encode(file) : file;
    },
    writeFile: async (path, bytes) => {
      written.set(path, bytes);
    },
    out: (text) => stdout.push(text),
    err: (text) => stderr.push(text),
    env: options.env ?? {},
    interactive: options.interactive ?? false,
    prompt: async (question) => {
      prompts.push(question);
      return options.answer ?? "";
    },
  };
  return { io, stdout, stderr, written, prompts };
}

const out = (h: Harness): string => h.stdout.join("\n");
const err = (h: Harness): string => h.stderr.join("\n");

// ---------------------------------------------------------------------------

describe("the command surface", () => {
  it("prints usage and fails when given nothing, so a bare invocation is not a success", async () => {
    const h = harness({});
    expect(await runCli([], h.io)).toBe(2);
    expect(out(h)).toContain("s0bundle");
  });

  it("prints usage and succeeds for an explicit help request", async () => {
    for (const flag of ["--help", "-h", "help"]) {
      const h = harness({});
      expect(await runCli([flag], h.io)).toBe(0);
      expect(out(h)).toBe(USAGE);
    }
  });

  it("rejects a command it does not have", async () => {
    const h = harness({});
    expect(await runCli(["explode"], h.io)).toBe(2);
    expect(err(h)).toContain("unknown command 'explode'");
  });

  it("reports a missing file as a message, not a stack trace", async () => {
    const h = harness({});
    expect(await runCli(["inspect", "nope.bin"], h.io)).toBe(1);
    expect(err(h)).toBe("no such file: nope.bin");
  });

  it("reports a non-Error throw as text", async () => {
    const h = harness({});
    const io: CliIO = {
      ...h.io,
      readFile: () => {
        // eslint-disable-next-line no-throw-literal
        throw "a string, not an Error";
      },
    };
    expect(await runCli(["inspect", "x.bin"], io)).toBe(1);
    expect(err(h)).toContain("a string, not an Error");
  });

  it("names the usage line for each command that needs a file", async () => {
    for (const [command, usage] of [
      ["inspect", "inspect <file>"],
      ["verify", "verify <file>"],
      ["stat", "stat <file>"],
      ["build", "build <dump.json>"],
      ["key", "key <display-string>"],
    ] as const) {
      const h = harness({});
      expect(await runCli([command], h.io)).toBe(1);
      expect(err(h)).toContain(usage);
    }
  });
});

// ---------------------------------------------------------------------------

describe("inspect", () => {
  it("prints the whole bundle as JSON", async () => {
    const { bytes } = await makeFixture();
    const h = harness({ "b.bin": bytes });

    expect(await runCli(["inspect", "b.bin"], h.io)).toBe(0);
    const dump = JSON.parse(out(h)) as BundleDump;
    expect(dump.format).toBe("socket0-bundle-dump");
    expect(dump.connections).toHaveLength(3);
    expect(dump.partial).toBe(false);
  });

  it("pages with --offset and --limit, in both flag spellings", async () => {
    const { bytes } = await makeFixture();

    const spaced = harness({ "b.bin": bytes });
    expect(await runCli(["inspect", "b.bin", "--offset", "1", "--limit", "1"], spaced.io)).toBe(0);
    const a = JSON.parse(out(spaced)) as BundleDump;

    const equals = harness({ "b.bin": bytes });
    expect(await runCli(["inspect", "b.bin", "--offset=1", "--limit=1"], equals.io)).toBe(0);
    const b = JSON.parse(out(equals)) as BundleDump;

    expect(a.connections).toHaveLength(1);
    expect(a.connections[0]?.connectionId).toBe(connectionId(0x00000009));
    expect(b).toEqual(a);
  });

  it("prints compact JSON when asked, and indented by default", async () => {
    const { bytes } = await makeFixture();
    const pretty = harness({ "b.bin": bytes });
    await runCli(["inspect", "b.bin"], pretty.io);
    const compact = harness({ "b.bin": bytes });
    await runCli(["inspect", "b.bin", "--compact"], compact.io);

    expect(out(pretty)).toContain("\n  ");
    expect(out(compact)).not.toContain("\n  ");
    expect(JSON.parse(out(compact))).toEqual(JSON.parse(out(pretty)));
  });

  it("rejects an offset or limit that is not a non-negative integer", async () => {
    const { bytes } = await makeFixture();
    for (const argv of [["--offset", "-1"], ["--limit", "1.5"], ["--offset", "abc"], ["--limit"]]) {
      const h = harness({ "b.bin": bytes });
      expect(await runCli(["inspect", "b.bin", ...argv], h.io)).toBe(1);
      expect(err(h)).toMatch(/must be a non-negative integer/);
    }
  });

  it("prints no plaintext without --open", async () => {
    const { bytes } = await makeFixture();
    const h = harness({ "b.bin": bytes });
    await runCli(["inspect", "b.bin"], h.io);
    expect(out(h)).not.toContain("sk_test_51H");
  });
});

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

describe("inspect --open", () => {
  /** A fixture plus the display string of a key that opens its first group. */
  async function openable(environment: "live" | "test" = "test") {
    const fixture = await makeFixture();
    const group = fixture.groups[0];
    if (group === undefined) throw new Error("no groups");
    const key = group.keys.find((k) => k.environment === environment);
    if (key === undefined) throw new Error(`fixture has no ${environment} key`);
    return { ...fixture, display: key.display };
  }

  it("needs both --api-key and --tenant", async () => {
    const { bytes, display } = await openable();
    for (const argv of [
      ["--open"],
      ["--open", "--api-key", display],
      ["--open", "--tenant", TENANT],
    ]) {
      const h = harness({ "b.bin": bytes }, { interactive: true, answer: REVEAL_PHRASE });
      expect(await runCli(["inspect", "b.bin", ...argv], h.io)).toBe(2);
      expect(err(h)).toContain("--open needs --api-key");
    }
  });

  it("rejects an --api-key that is not a well-formed key, before asking anything", async () => {
    const { bytes } = await openable();
    const h = harness({ "b.bin": bytes }, { interactive: true, answer: REVEAL_PHRASE });
    const code = await runCli(
      ["inspect", "b.bin", "--open", "--api-key", "sk0_live_nope", "--tenant", TENANT],
      h.io,
    );
    expect(code).toBe(2);
    expect(err(h)).toContain("--api-key is not a valid key");
    // The operator was never prompted: a malformed key is not a decision.
    expect(h.prompts).toEqual([]);
  });

  it("refuses a live key outright unless --allow-live is passed as well", async () => {
    const { bytes, display } = await openable("live");
    const h = harness({ "b.bin": bytes }, { interactive: true, answer: REVEAL_PHRASE });
    const argv = ["inspect", "b.bin", "--open", "--api-key", display, "--tenant", TENANT];

    expect(await runCli(argv, h.io)).toBe(3);
    expect(err(h)).toContain("refusing to decrypt with a live key");
    expect(h.prompts).toEqual([]);

    // Two separate flags, deliberately: nobody reaches production plaintext by
    // adding one word to a command they already ran against a test bundle.
    const allowed = harness({ "b.bin": bytes }, { interactive: true, answer: REVEAL_PHRASE });
    expect(await runCli([...argv, "--allow-live"], allowed.io)).toBe(0);
    expect(out(allowed)).toContain("sk_test_51H");
  });

  it("asks for a typed phrase at a terminal and stops when it is not typed", async () => {
    const { bytes, display } = await openable();
    const argv = ["inspect", "b.bin", "--open", "--api-key", display, "--tenant", TENANT];

    for (const answer of ["", "y", "yes", "REVEA"]) {
      const h = harness({ "b.bin": bytes }, { interactive: true, answer });
      expect(await runCli(argv, h.io)).toBe(3);
      expect(err(h)).toContain("not confirmed");
      expect(out(h)).toBe("");
    }
  });

  it("accepts the phrase in any case, with surrounding whitespace", async () => {
    const { bytes, display } = await openable();
    const h = harness({ "b.bin": bytes }, { interactive: true, answer: "  REVEAL \n" });
    const code = await runCli(
      ["inspect", "b.bin", "--open", "--api-key", display, "--tenant", TENANT],
      h.io,
    );
    expect(code).toBe(0);
    expect(h.prompts[0]).toContain(REVEAL_PHRASE);
  });

  it("refuses entirely without a terminal, unless the environment variable says otherwise", async () => {
    const { bytes, display } = await openable();
    const argv = ["inspect", "b.bin", "--open", "--api-key", display, "--tenant", TENANT];

    // A pipeline cannot stumble into this by inheriting a flag.
    const piped = harness({ "b.bin": bytes }, { interactive: false });
    expect(await runCli(argv, piped.io)).toBe(3);
    expect(err(piped)).toContain(`set ${PLAINTEXT_ENV_VAR}=1`);

    const wrongValue = harness(
      { "b.bin": bytes },
      { interactive: false, env: { [PLAINTEXT_ENV_VAR]: "true" } },
    );
    expect(await runCli(argv, wrongValue.io)).toBe(3);

    const overridden = harness(
      { "b.bin": bytes },
      { interactive: false, env: { [PLAINTEXT_ENV_VAR]: "1" } },
    );
    expect(await runCli(argv, overridden.io)).toBe(0);
    expect(err(overridden)).toContain("without confirmation");
  });

  it("prints the plaintext, marks every revealed field, and warns on stderr", async () => {
    const { bytes, display } = await openable();
    const h = harness({ "b.bin": bytes }, { interactive: true, answer: REVEAL_PHRASE });
    await runCli(["inspect", "b.bin", "--open", "--api-key", display, "--tenant", TENANT], h.io);

    const dump = JSON.parse(out(h)) as BundleDump;
    const password = dump.connections[0]?.sealed["password"];
    if (password === undefined || !("revealed" in password)) throw new Error("not revealed");
    expect(password.value).toBe("sk_test_51H");
    // The warning goes to stderr, so redirecting stdout to a file still shows it.
    expect(err(h)).toContain("plaintext credential(s)");
  });

  it("opens only the groups the key belongs to, and says which it could not", async () => {
    const { bytes, display } = await openable();
    const h = harness({ "b.bin": bytes }, { interactive: true, answer: REVEAL_PHRASE });
    await runCli(["inspect", "b.bin", "--open", "--api-key", display, "--tenant", TENANT], h.io);

    const dump = JSON.parse(out(h)) as BundleDump;
    // The fixture's third connection belongs to a second group this key is not
    // in; a partial reveal is the normal case, not a failure.
    expect("revealed" in (dump.connections[0]?.sealed["password"] ?? {})).toBe(true);
    expect("revealed" in (dump.connections[2]?.sealed["apiKey"] ?? {})).toBe(false);
    expect(err(h)).toContain("has no entry in the bucket");
  });

  it("fails when the key opens nothing at all, rather than printing an empty success", async () => {
    const { bytes } = await makeFixture();
    const stranger = generateApiKey("test");
    const h = harness({ "b.bin": bytes }, { interactive: true, answer: REVEAL_PHRASE });

    const code = await runCli(
      ["inspect", "b.bin", "--open", "--api-key", stranger.display, "--tenant", TENANT],
      h.io,
    );
    expect(code).toBe(1);
    expect(err(h)).toContain("opens no group in this bundle");
    expect(out(h)).toBe("");
  });

  it("fails for the right key under the wrong tenant", async () => {
    const { bytes, display } = await openable();
    const h = harness({ "b.bin": bytes }, { interactive: true, answer: REVEAL_PHRASE });
    const code = await runCli(
      ["inspect", "b.bin", "--open", "--api-key", display, "--tenant", "tnt_someone_else"],
      h.io,
    );
    expect(code).toBe(1);
    expect(err(h)).toContain("opens no group in this bundle");
  });

  it("reports a field it cannot open rather than aborting the whole dump", async () => {
    const { bytes, display } = await openable();
    // Corrupt one field's ciphertext in place, leaving everything else intact.
    const damaged = bytes.slice();
    const view = readBundle(damaged);
    const descriptor = view.lookup(connectionId(0x00000001))?.field("password");
    if (descriptor === undefined) throw new Error("no field");
    flipByte(damaged, descriptor.strsOffset + 40, 0xff);

    const h = harness({ "b.bin": damaged }, { interactive: true, answer: REVEAL_PHRASE });
    expect(
      await runCli(["inspect", "b.bin", "--open", "--api-key", display, "--tenant", TENANT], h.io),
    ).toBe(0);

    const dump = JSON.parse(out(h)) as BundleDump;
    expect(err(h)).toContain("did not open");
    // The other fields still came out, which is what makes the tool useful on a
    // bundle somebody is debugging precisely because part of it is broken.
    expect("revealed" in (dump.connections[0]?.sealed["username"] ?? {})).toBe(true);
  });

  it("reports a field already written back instead of trying to open it", async () => {
    const { bytes, groups } = await makeFixture();
    const view = readBundle(bytes);
    const descriptor = view.lookup(connectionId(0x00000001))?.field("password");
    if (descriptor === undefined) throw new Error("no field");
    view.writeBack(descriptor, utf8Encode("cached"));

    // This state cannot arrive through the CLI: `readBundle` refuses a buffer
    // whose fields are already open ("a freshly loaded bundle is entirely
    // sealed"), so only a live in-process view can hold one. `revealDump` is
    // still handed dumps by other callers, and must say so rather than throw.
    const key = groups[0]?.keys[0];
    if (key === undefined) throw new Error("no key");
    const result = await revealDump(inspectBundle(view), key.bytes, TENANT);

    expect(result.groupsOpened).toBe(1);
    expect(result.problems.join(" ")).toContain("no envelope to open");
    expect(result.revealed.has(revealKey(connectionId(0x00000001), "password"))).toBe(false);
  });
});

describe("revealDump against a damaged bucket", () => {
  it("reports an entry that names the key but does not open under it", async () => {
    const { bytes, groups } = await makeFixture();
    const group = groups[0];
    const key = group?.keys[0];
    if (group === undefined || key === undefined) throw new Error("no key");

    // Keep the key id, corrupt the wrapped private half. The bucket lookup
    // still matches — it matches on the id — and the unwrap then fails.
    const dump = inspectBundle(readBundle(bytes));
    const [first, ...rest] = dump.groups;
    if (first === undefined) throw new Error("no groups");
    const entry = first.bucket.find((e) => e.wrapped.length > 4);
    if (entry === undefined) throw new Error("no bucket entry");

    // The replacement has to differ from the character already there. Writing a
    // literal "A" corrupts nothing on the 1-in-64 run where the wrapped blob
    // already begins with one, and the entry then opens exactly as it should —
    // a test that passes because the fixture happened to cooperate. The leading
    // base64 character carries the top six bits of the first byte, so any other
    // symbol is a different byte and the GCM tag has to reject it.
    const damaged = `${entry.wrapped.startsWith("A") ? "B" : "A"}${entry.wrapped.slice(1)}`;
    const damagedGroup = {
      ...first,
      bucket: first.bucket.map((e) => (e === entry ? { ...e, wrapped: damaged } : e)),
    };
    const result = await revealDump(
      { ...dump, groups: [damagedGroup, ...rest] },
      key.bytes,
      TENANT,
    );

    expect(result.groupsOpened).toBe(0);
    expect(result.problems.join(" ")).toContain("the bucket entry did not open");
  });
});

// ---------------------------------------------------------------------------

describe("verify", () => {
  it("passes a good bundle", async () => {
    const { bytes } = await makeFixture();
    const h = harness({ "b.bin": bytes });
    expect(await runCli(["verify", "b.bin"], h.io)).toBe(0);
    expect(out(h)).toContain("checksum        ok");
    expect(out(h)).toContain("index resolved  3/3");
    expect(out(h)).toContain("result          ok");
  });

  it("fails a corrupted one and prints why", async () => {
    const { bytes } = await makeFixture();
    const corrupted = bytes.slice();
    flipByte(corrupted, corrupted.length - 1);

    const h = harness({ "b.bin": corrupted });
    expect(await runCli(["verify", "b.bin"], h.io)).toBe(1);
    expect(out(h)).toContain("checksum        MISMATCH");
    expect(err(h)).toContain("checksum does not match");
  });
});

describe("stat", () => {
  it("reports the totals without rendering a single record", async () => {
    const { bytes } = await makeFixture();
    const h = harness({ "b.bin": bytes });
    expect(await runCli(["stat", "b.bin"], h.io)).toBe(0);

    const text = out(h);
    expect(text).toContain("generation      47");
    expect(text).toContain("connections     3");
    expect(text).toContain("groups          2 (3 bucket entries)");
    expect(text).toContain("INDX");
    expect(text).toContain("STRS");
    // No connection was rendered, so no envelope reached the output.
    expect(text).not.toContain("x25519-hkdf-aesgcm");
  });
});

describe("build", () => {
  it("turns a dump back into the exact bytes it came from", async () => {
    const { bytes } = await makeFixture();
    const dump = JSON.stringify(inspectBundle(readBundle(bytes)));
    const h = harness({ "d.json": dump });

    expect(await runCli(["build", "d.json", "--out", "rebuilt.bin"], h.io)).toBe(0);
    expect(h.written.get("rebuilt.bin")).toEqual(bytes);
    expect(out(h)).toContain(`wrote ${bytes.length} bytes to rebuilt.bin`);
  });

  it("needs --out, with a value", async () => {
    const h = harness({ "d.json": "{}" });
    expect(await runCli(["build", "d.json"], h.io)).toBe(2);
    expect(err(h)).toContain("build needs --out");

    const empty = harness({ "d.json": "{}" });
    expect(await runCli(["build", "d.json", "--out"], empty.io)).toBe(2);
  });

  it("refuses a partial dump", async () => {
    const { bytes } = await makeFixture();
    const dump = JSON.stringify(inspectBundle(readBundle(bytes), { limit: 1 }));
    const h = harness({ "d.json": dump });

    expect(await runCli(["build", "d.json", "--out", "x.bin"], h.io)).toBe(1);
    expect(err(h)).toContain("cannot rebuild a partial dump");
    expect(h.written.size).toBe(0);
  });

  it("refuses a file that is not JSON, and one that is not a dump", async () => {
    const notJson = harness({ "d.json": "{oops" });
    expect(await runCli(["build", "d.json", "--out", "x.bin"], notJson.io)).toBe(1);

    const notDump = harness({ "d.json": '{"format":"something-else"}' });
    expect(await runCli(["build", "d.json", "--out", "x.bin"], notDump.io)).toBe(1);
    expect(err(notDump)).toContain("not a bundle dump");
  });

  it("round-trips through a real file the CLI wrote", async () => {
    const { bytes } = await makeFixture();
    const first = harness({ "b.bin": bytes });
    await runCli(["inspect", "b.bin", "--compact"], first.io);

    const second = harness({ "d.json": out(first) });
    expect(await runCli(["build", "d.json", "--out", "again.bin"], second.io)).toBe(0);

    const again = second.written.get("again.bin");
    expect(again).toEqual(bytes);
    // And the thing it wrote verifies, which is the property a vector needs.
    const third = harness({ "again.bin": again as Uint8Array });
    expect(await runCli(["verify", "again.bin"], third.io)).toBe(0);
  });
});

describe("key", () => {
  it("accepts a key it generated and reports its environment", async () => {
    const key = generateApiKey("test");
    const h = harness({});
    expect(await runCli(["key", key.display], h.io)).toBe(0);
    expect(out(h)).toContain("environment     test");
    expect(out(h)).toContain("display length  59");
  });

  it("says which way a key is wrong rather than just 'invalid'", async () => {
    const key = generateApiKey("live");
    // Flip one body character: the checksum, not the shape, is what catches it.
    const typo = `${key.display.slice(0, 12)}${key.display[12] === "a" ? "b" : "a"}${key.display.slice(13)}`;

    const h = harness({});
    expect(await runCli(["key", typo], h.io)).toBe(1);
    expect(err(h)).toMatch(/^invalid: \w/);
  });
});

describe("argument parsing", () => {
  it("treats a bare flag as present with an empty value, and does not eat the next flag", async () => {
    const { bytes } = await makeFixture();
    const h = harness({ "b.bin": bytes });
    // `--compact` takes no value; `b.bin` must still be found as the positional.
    expect(await runCli(["inspect", "--compact", "b.bin"], h.io)).toBe(0);
    expect(JSON.parse(out(h))).toBeTypeOf("object");
  });

  it("writes a dump the CLI can read back through its own encoder", async () => {
    const { bytes } = await makeFixture();
    const rebuilt = await writeBundleWithChecksum(
      (await import("../inspect.js")).bundleFromJSON(
        JSON.parse(
          utf8Decode(utf8Encode(JSON.stringify(inspectBundle(readBundle(bytes))))),
        ) as BundleDump,
      ),
    );
    expect(rebuilt).toEqual(bytes);
  });
});
