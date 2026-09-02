/**
 * `s0bundle` — the debugging tool `datamodel/bundle` said would exist.
 *
 * The whole command surface is one pure function over an injected `CliIO`. The
 * real `bin/s0bundle.js` is a dozen lines of `node:fs` and `node:readline` that
 * fills that port in; everything worth testing is here, which is why the tool
 * can be tested against a fake terminal instead of being the one part of the
 * package nobody exercises.
 *
 * Commands:
 *
 *   inspect <file>  — the bundle as JSON, paged with --offset/--limit
 *   verify  <file>  — checksum, plus the structural checks a checksum can't make
 *   stat    <file>  — where the bytes went, and how much cap is left
 *   build   <json>  — a dump back into a bundle (golden vectors, fuzz corpora)
 *   key     <key>   — parse an API key display string and say why it is wrong
 *
 * `inspect --open` is the one operation that can print a credential. It is
 * guarded three ways and none of them are advisory: a `live` key is refused
 * outright without `--allow-live`, an interactive run must type a confirmation
 * phrase, and a non-interactive run must set `S0_ALLOW_PLAINTEXT=1` — a pipeline
 * cannot stumble into it by inheriting a flag.
 */

import { parseApiKey } from "../api-key.js";
import { readBundle } from "../bundle/reader.js";
import { writeBundleWithChecksum } from "../bundle/writer.js";
import { utf8Decode, utf8Encode } from "../encoding.js";
import {
  type BundleDump,
  bundleFromJSON,
  type InspectOptions,
  inspectBundle,
  verifyBundle,
} from "../inspect.js";
import type { ApiKeyBytes } from "../types.js";
import { revealDump } from "./reveal.js";

/** Everything the CLI needs from the world, so tests can supply all of it. */
export interface CliIO {
  readFile: (path: string) => Promise<Uint8Array>;
  writeFile: (path: string, bytes: Uint8Array) => Promise<void>;
  out: (text: string) => void;
  err: (text: string) => void;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly interactive: boolean;
  /** Prompt, and resolve with what the operator typed. Only called when interactive. */
  prompt: (question: string) => Promise<string>;
}

/** The phrase an operator must type before plaintext is printed. */
export const REVEAL_PHRASE = "reveal";
/** The variable a non-interactive run must set instead of typing the phrase. */
export const PLAINTEXT_ENV_VAR = "S0_ALLOW_PLAINTEXT";

export const USAGE = `s0bundle — inspect and verify Socket0 bundles

  s0bundle inspect <file> [--offset N] [--limit N] [--compact]
                          [--open --api-key <key> --tenant <id> [--allow-live]]
  s0bundle verify  <file>
  s0bundle stat    <file>
  s0bundle build   <dump.json> --out <file>
  s0bundle key     <display-string>

--open decrypts and PRINTS CREDENTIALS. Local development only: it refuses a
live key without --allow-live, asks for confirmation at a terminal, and refuses
entirely when not a terminal unless ${PLAINTEXT_ENV_VAR}=1 is set.`;

/**
 * Run one command. Returns the process exit code; never throws for an operator
 * error, because a stack trace is not a diagnosis.
 */
export async function runCli(argv: readonly string[], io: CliIO): Promise<number> {
  const [command, ...rest] = argv;
  if (command === undefined || command === "--help" || command === "-h" || command === "help") {
    io.out(USAGE);
    return command === undefined ? 2 : 0;
  }

  try {
    switch (command) {
      case "inspect":
        return await inspectCommand(rest, io);
      case "verify":
        return await verifyCommand(rest, io);
      case "stat":
        return await statCommand(rest, io);
      case "build":
        return await buildCommand(rest, io);
      case "key":
        return keyCommand(rest, io);
      default:
        io.err(`unknown command '${command}'\n\n${USAGE}`);
        return 2;
    }
  } catch (cause) {
    io.err(cause instanceof Error ? cause.message : String(cause));
    return 1;
  }
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

async function inspectCommand(argv: readonly string[], io: CliIO): Promise<number> {
  const flags = parseFlags(argv);
  const path = requirePositional(flags, "inspect <file>");

  const view = readBundle(await io.readFile(path));
  const options: InspectOptions = {
    ...(flags.get("offset") === undefined
      ? {}
      : { offset: requireCount(flags.get("offset"), "--offset") }),
    ...(flags.get("limit") === undefined
      ? {}
      : { limit: requireCount(flags.get("limit"), "--limit") }),
  };

  let dump = inspectBundle(view, options);

  if (flags.has("open")) {
    const gate = await authoriseReveal(flags, io);
    if (gate.code !== 0) return gate.code;
    const result = await revealDump(dump, gate.apiKey, gate.tenantId);
    if (result.groupsOpened === 0) {
      io.err("that API key opens no group in this bundle; nothing was decrypted");
      for (const problem of result.problems) io.err(`  ${problem}`);
      return 1;
    }
    for (const problem of result.problems) io.err(`warning: ${problem}`);
    dump = inspectBundle(view, { ...options, revealed: result.revealed });
    io.err(`WARNING: the output below contains ${result.revealed.size} plaintext credential(s).`);
  }

  io.out(JSON.stringify(dump, null, flags.has("compact") ? undefined : 2));
  return 0;
}

async function verifyCommand(argv: readonly string[], io: CliIO): Promise<number> {
  const flags = parseFlags(argv);
  const path = requirePositional(flags, "verify <file>");
  const view = readBundle(await io.readFile(path));
  const report = await verifyBundle(view);

  io.out(`checksum        ${report.checksumValid ? "ok" : "MISMATCH"}`);
  io.out(`connections     ${report.connectionCount}`);
  io.out(`index resolved  ${report.indexResolved}/${report.connectionCount}`);
  if (report.ok) {
    io.out("result          ok");
    return 0;
  }
  io.out(`result          ${report.problems.length} problem(s)`);
  for (const problem of report.problems) io.err(`  ${problem}`);
  return 1;
}

async function statCommand(argv: readonly string[], io: CliIO): Promise<number> {
  const flags = parseFlags(argv);
  const path = requirePositional(flags, "stat <file>");
  const view = readBundle(await io.readFile(path));
  // Page to nothing: `stat` wants the totals, and rendering every connection to
  // throw it away would make the tool useless on the bundles it matters for.
  const dump = inspectBundle(view, { limit: 0 });
  const s = dump.stats;

  io.out(`generation      ${dump.header.generation}`);
  io.out(`built at        ${dump.header.builtAt}`);
  io.out(`total bytes     ${s.totalBytes}`);
  io.out(`cap remaining   ${s.capBytesRemaining}`);
  io.out(`connections     ${s.connectionCount}`);
  io.out(`groups          ${s.groupCount} (${s.bucketEntryCount} bucket entries)`);
  io.out(`filters         ${s.filterCount}`);
  io.out(`sealed fields   ${s.sealedFieldCount}`);
  io.out(`open fields     ${s.openFieldCount}`);
  io.out(`index slots     ${s.indexSlots} (load ${s.indexLoadFactor.toFixed(4)})`);
  for (const section of dump.sections) {
    io.out(`  ${section.kind}          ${section.length} bytes, ${section.count} records`);
  }
  return 0;
}

async function buildCommand(argv: readonly string[], io: CliIO): Promise<number> {
  const flags = parseFlags(argv);
  const path = requirePositional(flags, "build <dump.json> --out <file>");
  const out = flags.get("out");
  if (out === undefined || out === "") {
    io.err("build needs --out <file>");
    return 2;
  }

  const dump = JSON.parse(utf8Decode(await io.readFile(path))) as BundleDump;
  const bytes = await writeBundleWithChecksum(bundleFromJSON(dump));
  await io.writeFile(out, bytes);
  io.out(`wrote ${bytes.length} bytes to ${out}`);
  return 0;
}

function keyCommand(argv: readonly string[], io: CliIO): number {
  const flags = parseFlags(argv);
  const display = requirePositional(flags, "key <display-string>");
  const parsed = parseApiKey(display);
  if (!parsed.ok) {
    io.err(`invalid: ${parsed.reason} — ${parsed.message}`);
    return 1;
  }
  io.out(`valid           yes`);
  io.out(`environment     ${parsed.environment}`);
  io.out(`display length  ${parsed.display.length}`);
  return 0;
}

// ---------------------------------------------------------------------------
// the reveal gate
// ---------------------------------------------------------------------------

type RevealGate =
  | { readonly code: 0; readonly apiKey: ApiKeyBytes; readonly tenantId: string }
  | { readonly code: 2 | 3; readonly apiKey?: undefined; readonly tenantId?: undefined };

async function authoriseReveal(flags: ParsedArgs, io: CliIO): Promise<RevealGate> {
  const display = flags.get("api-key");
  const tenantId = flags.get("tenant");
  if (display === undefined || tenantId === undefined || tenantId === "") {
    io.err("--open needs --api-key <key> and --tenant <id>");
    return { code: 2 };
  }

  const parsed = parseApiKey(display);
  if (!parsed.ok) {
    io.err(`--api-key is not a valid key: ${parsed.reason} — ${parsed.message}`);
    return { code: 2 };
  }

  // A live key is the one that opens production credentials, so the flag that
  // permits it is separate from the flag that asks for decryption. Nobody
  // reaches production plaintext by adding one word to a command they already
  // ran against a test bundle.
  if (parsed.environment === "live" && !flags.has("allow-live")) {
    io.err(
      "refusing to decrypt with a live key; pass --allow-live if that is genuinely what you want",
    );
    return { code: 3 };
  }

  if (!io.interactive) {
    if (io.env[PLAINTEXT_ENV_VAR] !== "1") {
      io.err(
        `refusing to print plaintext without a terminal to confirm at; set ${PLAINTEXT_ENV_VAR}=1 to override`,
      );
      return { code: 3 };
    }
    io.err(`${PLAINTEXT_ENV_VAR}=1 is set; printing plaintext without confirmation.`);
    return { code: 0, apiKey: parsed.bytes, tenantId };
  }

  io.err(
    `About to DECRYPT AND PRINT credentials from this bundle using a ${parsed.environment} key.\n` +
      "This is a local development operation. The output will contain secrets in the clear.",
  );
  const answer = await io.prompt(`Type '${REVEAL_PHRASE}' to continue: `);
  if (answer.trim().toLowerCase() !== REVEAL_PHRASE) {
    io.err("not confirmed; nothing was decrypted");
    return { code: 3 };
  }
  return { code: 0, apiKey: parsed.bytes, tenantId };
}

// ---------------------------------------------------------------------------
// argument parsing
// ---------------------------------------------------------------------------

interface ParsedArgs {
  get: (name: string) => string | undefined;
  has: (name: string) => boolean;
  readonly positionals: readonly string[];
}

/**
 * The flags that take a value. Everything else is a boolean.
 *
 * This has to be declared rather than inferred: a parser that treats the token
 * after any flag as its value reads `--compact b.bin` as `compact="b.bin"` and
 * then reports no file, which is a confusing failure for a correct command.
 */
const VALUE_FLAGS = new Set(["offset", "limit", "api-key", "tenant", "out"]);

/**
 * `--flag value`, `--flag=value` and bare `--flag` (which is `""`), plus
 * positionals. Deliberately small: a dependency for this would be a dependency
 * in a package whose whole point is that it has none.
 */
function parseFlags(argv: readonly string[]): ParsedArgs {
  const values = new Map<string, string>();
  const positionals: string[] = [];

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i] as string;
    if (!token.startsWith("--")) {
      positionals.push(token);
      continue;
    }
    const body = token.slice(2);
    const eq = body.indexOf("=");
    if (eq !== -1) {
      values.set(body.slice(0, eq), body.slice(eq + 1));
      continue;
    }
    const next = argv[i + 1];
    if (!VALUE_FLAGS.has(body) || next === undefined || next.startsWith("--")) {
      values.set(body, "");
      continue;
    }
    values.set(body, next);
    i += 1;
  }

  return {
    get: (name) => values.get(name),
    has: (name) => values.has(name),
    positionals,
  };
}

function requirePositional(flags: ParsedArgs, usage: string): string {
  const first = flags.positionals[0];
  if (first === undefined) throw new Error(`usage: s0bundle ${usage}`);
  return first;
}

function requireCount(value: string | undefined, name: string): number {
  const parsed = Number(value);
  if (value === undefined || value === "" || !Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${name} must be a non-negative integer`);
  }
  return parsed;
}

/** Exported so `bin/s0bundle.js` can encode without importing a second encoder. */
export { utf8Encode };
