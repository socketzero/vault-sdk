#!/usr/bin/env node
/**
 * The `node:fs`/`node:readline` half of `s0bundle`.
 *
 * Everything decidable lives in `src/cli/run.ts` behind the `CliIO` port; this
 * file exists only to fill that port in with the real world, which is why it is
 * the one file in the package with no tests and nothing worth testing.
 */
import { readFile, writeFile } from "node:fs/promises";
import process from "node:process";
import { createInterface } from "node:readline/promises";
import { runCli } from "../dist/cli/run.js";

const io = {
  readFile: async (path) => new Uint8Array(await readFile(path)),
  writeFile: (path, bytes) => writeFile(path, bytes),
  out: (text) => process.stdout.write(`${text}\n`),
  err: (text) => process.stderr.write(`${text}\n`),
  env: process.env,
  interactive: process.stdin.isTTY === true && process.stderr.isTTY === true,
  prompt: async (question) => {
    // Prompt on stderr so `s0bundle inspect ... > out.json` still works.
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    try {
      return await rl.question(question);
    } finally {
      rl.close();
    }
  },
};

process.exitCode = await runCli(process.argv.slice(2), io);
