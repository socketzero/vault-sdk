/**
 * Lookup performance across a multi-tenant working set.
 *
 * The question this answers is narrow and deliberate: **does search degrade as
 * more tenant data goes resident?** `lookup` is advertised as one masked slot
 * read, a fingerprint compare and a full id verify — O(1) regardless of how many
 * connections a shard holds — and the whole latency budget rests on that.
 *
 * ## Why 10 / 20 / 30 MB is three bundles, not one
 *
 * `BUNDLE_MAX_BYTES` caps a single bundle at 10 MiB and the index tops out at
 * 65,536 connections, so a 20 MB or 30 MB *bundle* cannot be built — `writeBundle`
 * refuses it. A multi-tenant isolate reaches those figures by holding several
 * shards at once, so each scenario here is N shards of ~10 MiB, one tenant each.
 * That is also the more honest test: it puts real pressure on cache locality,
 * which is where an O(1) lookup quietly stops being O(1).
 *
 * ## Two kinds of measurement
 *
 * - **Probe distance** is structural and machine-independent: how far linear
 *   probing walks from a connection's home slot. A CI runner's noise cannot move
 *   it, so the regression gates are built on it.
 * - **Timings** are reported for humans and gated only as a *ratio* between
 *   scenarios, never as an absolute, because shared runners vary wildly.
 *
 * Bulk field envelopes are synthetic: the format only checks an envelope's
 * algorithm prefix, base64 and minimum length, and this benchmark measures the
 * index rather than the cipher. Key groups and buckets are real.
 */

import { writeFileSync } from "node:fs";
import {
  base64Encode,
  buildBucket,
  generateApiKey,
  generateGroup,
  layout,
  measureBundle,
  readBundle,
  SEAL_ALGORITHM,
  writeBundleWithChecksum,
} from "../dist/index.js";

const MIB = 1024 * 1024;
const SHARD_TARGET_BYTES = 10 * MIB - 64 * 1024; // just under the writer's cap
const SCENARIOS = [
  { label: "10 MB", shards: 1 },
  { label: "20 MB", shards: 2 },
  { label: "30 MB", shards: 3 },
];

/** Gates. Structural ones are hard; the timing one is a ratio, not an absolute. */
const LIMITS = {
  meanProbe: 1.5, // a 0.25 load factor should sit near 1.1
  maxProbe: 24,
  loadFactor: 0.25, // the format's own promise
  // O(1) means ~1.0. A breach only fails the build when it is monotonic — see
  // the note in `report` — so this can stay tight without being flaky.
  hitP99RatioVsSmallest: 2.5,
  missP99RatioVsSmallest: 2.5,
};

// ---------------------------------------------------------------------------
// Fixture generation
// ---------------------------------------------------------------------------

const SHARD_NAMES = ["shda", "shdb", "shdc", "shdd", "shde"];

/**
 * One envelope, reused for every bulk field.
 *
 * Field slots are placed rather than interned, so identical bytes still occupy
 * separate regions — the layout is exactly what distinct envelopes would produce.
 */
function syntheticEnvelope(plainBytes) {
  const payload = new Uint8Array(60 + plainBytes);
  crypto.getRandomValues(payload);
  return `${SEAL_ALGORITHM}:${base64Encode(payload)}`;
}

function connectionsFor(count, shard, groupId, envelope) {
  const connections = new Array(count);
  for (let i = 0; i < count; i += 1) {
    connections[i] = {
      connectionId: crypto.randomUUID(),
      groupId,
      // Varied so the arena cannot intern every record down to one region.
      target: `https://api.tenant-${shard}.example.com/service/${i}`,
      visible: { provider: `svc-${i % 97}`, tier: i % 5, live: (i & 1) === 0 },
      sealed: { token: envelope, secondary: envelope },
      filters: [],
      expiresAt: null,
    };
  }
  return connections;
}

/** Build one tenant shard sized as close under the cap as the format allows. */
async function buildShard(index) {
  const shard = SHARD_NAMES[index];
  const groupId = crypto.randomUUID();
  const pair = await generateGroup();
  const apiKey = generateApiKey("test");
  const bucket = await buildBucket(pair.privateKey, [apiKey.bytes], `tenant-${shard}`, groupId);
  const group = { groupId, publicKey: pair.publicKey, generation: 0, bucket };
  const envelope = syntheticEnvelope(48);

  const header = {
    version: 1,
    generation: BigInt(index + 1),
    builtAt: BigInt(Date.now()),
  };
  const plan = (count) => ({
    header,
    groups: [group],
    connections: connectionsFor(count, shard, groupId, envelope),
    filters: [],
  });

  // Estimate from a small sample, then close in. measureBundle plans without
  // emitting, so this costs a few plans rather than a few serialisations.
  const probeCount = 500;
  const probeBytes = measureBundle(plan(probeCount));
  let count = Math.floor((SHARD_TARGET_BYTES / probeBytes) * probeCount);

  for (let attempt = 0; attempt < 12; attempt += 1) {
    let bytes;
    try {
      bytes = measureBundle(plan(count));
    } catch {
      count = Math.floor(count * 0.9); // over a hard limit; step back
      continue;
    }
    if (bytes > SHARD_TARGET_BYTES) {
      count = Math.floor(count * (SHARD_TARGET_BYTES / bytes) * 0.995);
      continue;
    }
    if (bytes > SHARD_TARGET_BYTES * 0.97) break;
    count = Math.floor(count * (SHARD_TARGET_BYTES / bytes) * 0.995);
  }

  const input = plan(count);
  const built = await writeBundleWithChecksum(input);
  return {
    shard,
    bytes: built,
    connectionIds: input.connections.map((c) => c.connectionId),
  };
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

function percentile(sorted, p) {
  if (sorted.length === 0) return 0;
  const rank = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, rank)];
}

/**
 * Time an operation in rounds of `batch`, reporting nanoseconds per operation.
 *
 * Batching keeps the timer's own overhead — comparable to a lookup itself — from
 * dominating, and percentiles are taken over round means.
 */
function timePerOp(fn, { rounds = 150, batch = 200 } = {}) {
  for (let i = 0; i < batch * 5; i += 1) fn(i); // warm up JIT and caches
  const perOp = [];
  let sink = 0;
  for (let r = 0; r < rounds; r += 1) {
    const start = process.hrtime.bigint();
    for (let i = 0; i < batch; i += 1) sink += fn(r * batch + i) === undefined ? 0 : 1;
    const elapsed = Number(process.hrtime.bigint() - start);
    perOp.push(elapsed / batch);
  }
  if (sink === -1) throw new Error("unreachable");
  perOp.sort((a, b) => a - b);
  return {
    p50: percentile(perOp, 50),
    p95: percentile(perOp, 95),
    p99: percentile(perOp, 99),
    mean: perOp.reduce((a, b) => a + b, 0) / perOp.length,
  };
}

/**
 * How far linear probing walks from each connection's home slot.
 *
 * Read straight out of the emitted index, so it measures the structure rather
 * than the machine: if this rises, search really is degrading.
 */
function probeStats(view) {
  const indx = view.section("INDX");
  const slots = indx.length / layout.INDEX_SLOT_BYTES;
  const dv = new DataView(view.buffer.buffer, view.buffer.byteOffset, view.buffer.byteLength);

  let occupied = 0;
  let total = 0;
  let max = 0;
  for (let slot = 0; slot < slots; slot += 1) {
    const at = layout.indexSlotOffset(indx.offset, slot);
    const recordOffset = dv.getUint32(at + layout.INDEX_SLOT_OFFSET.CONN_OFFSET, true);
    if (recordOffset === layout.INDEX_EMPTY_SLOT) continue;
    occupied += 1;
    const id = view.connectionAt(recordOffset).idBytes();
    const home = layout.bucketOf(layout.uuidLow32(id), slots);
    const distance = (slot - home) & (slots - 1);
    total += distance;
    if (distance > max) max = distance;
  }
  return {
    slots,
    occupied,
    loadFactor: occupied / slots,
    meanProbe: occupied === 0 ? 0 : 1 + total / occupied,
    maxProbe: 1 + max,
  };
}

async function measureScenario(scenario, shards) {
  const used = shards.slice(0, scenario.shards);
  const views = used.map((s) => readBundle(s.bytes));

  const totalBytes = used.reduce((n, s) => n + s.bytes.byteLength, 0);
  const connectionCount = used.reduce((n, s) => n + s.connectionIds.length, 0);

  // Load: parse every shard from scratch.
  const loadStart = process.hrtime.bigint();
  for (const s of used) readBundle(s.bytes);
  const loadMs = Number(process.hrtime.bigint() - loadStart) / 1e6;

  const checksumStart = process.hrtime.bigint();
  for (const v of views) await v.verifyChecksum();
  const checksumMs = Number(process.hrtime.bigint() - checksumStart) / 1e6;

  // Hits: sample uniformly across every resident shard, so the working set —
  // not one hot bundle — is what is being searched.
  const hitIds = [];
  for (let i = 0; i < used.length; i += 1) {
    for (const id of used[i].connectionIds) hitIds.push([i, id]);
  }
  for (let i = hitIds.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [hitIds[i], hitIds[j]] = [hitIds[j], hitIds[i]];
  }

  const hit = timePerOp((n) => {
    const [shardIndex, id] = hitIds[n % hitIds.length];
    return views[shardIndex].lookup(id);
  });

  const missIds = used.map((s) => `${s.shard}_${crypto.randomUUID()}`);
  const miss = timePerOp((n) => {
    const shardIndex = n % views.length;
    return views[shardIndex].lookup(missIds[shardIndex]);
  });

  const probes = views.map(probeStats);
  const worst = probes.reduce((a, b) => (b.maxProbe > a.maxProbe ? b : a));
  const meanProbe = probes.reduce((n, p) => n + p.meanProbe, 0) / probes.length;
  const loadFactor = probes.reduce((n, p) => n + p.loadFactor, 0) / probes.length;

  return {
    label: scenario.label,
    shards: used.length,
    totalBytes,
    connectionCount,
    loadMs,
    checksumMs,
    hit,
    miss,
    meanProbe,
    maxProbe: worst.maxProbe,
    loadFactor,
    slots: probes.reduce((n, p) => n + p.slots, 0),
  };
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

const ns = (v) => (v >= 1000 ? `${(v / 1000).toFixed(2)} µs` : `${v.toFixed(0)} ns`);
const mb = (v) => `${(v / MIB).toFixed(2)} MiB`;

function report(results) {
  const base = results[0];
  const checks = [];

  for (const r of results) {
    checks.push({
      scenario: r.label,
      name: "mean probe distance",
      value: r.meanProbe.toFixed(3),
      limit: `≤ ${LIMITS.meanProbe}`,
      ok: r.meanProbe <= LIMITS.meanProbe,
    });
    checks.push({
      scenario: r.label,
      name: "max probe distance",
      value: String(r.maxProbe),
      limit: `≤ ${LIMITS.maxProbe}`,
      ok: r.maxProbe <= LIMITS.maxProbe,
    });
    checks.push({
      scenario: r.label,
      name: "index load factor",
      value: r.loadFactor.toFixed(3),
      limit: `≤ ${LIMITS.loadFactor}`,
      ok: r.loadFactor <= LIMITS.loadFactor + 1e-9,
    });
  }
  // A timing breach only counts when every larger scenario breaches too.
  //
  // Real degradation is monotonic: if search is getting worse with residency,
  // 30 MB cannot be healthy while 20 MB is not. A single scenario over the line
  // with a bigger one under it is a noisy neighbour on a shared runner, and
  // failing the build on it trains everyone to ignore the benchmark — which
  // costs more than the signal is worth. The structural gates above stay hard;
  // they are the ones a runner cannot move.
  const rest = results.slice(1);
  const ratios = rest.map((r) => ({
    r,
    hit: r.hit.p99 / base.hit.p99,
    miss: r.miss.p99 / base.miss.p99,
  }));
  const breachesFrom = (i, pick, limit) => ratios.slice(i).every((x) => pick(x) > limit);

  ratios.forEach((x, i) => {
    const hitBreach = x.hit > LIMITS.hitP99RatioVsSmallest;
    const missBreach = x.miss > LIMITS.missP99RatioVsSmallest;
    checks.push({
      scenario: `${x.r.label} vs ${base.label}`,
      name: "hit p99 scaling",
      value: `${x.hit.toFixed(2)}×${hitBreach && !breachesFrom(i, (y) => y.hit, LIMITS.hitP99RatioVsSmallest) ? " (isolated — larger scenario is clean)" : ""}`,
      limit: `≤ ${LIMITS.hitP99RatioVsSmallest}×`,
      ok: !breachesFrom(i, (y) => y.hit, LIMITS.hitP99RatioVsSmallest),
    });
    checks.push({
      scenario: `${x.r.label} vs ${base.label}`,
      name: "miss p99 scaling",
      value: `${x.miss.toFixed(2)}×${missBreach && !breachesFrom(i, (y) => y.miss, LIMITS.missP99RatioVsSmallest) ? " (isolated — larger scenario is clean)" : ""}`,
      limit: `≤ ${LIMITS.missP99RatioVsSmallest}×`,
      ok: !breachesFrom(i, (y) => y.miss, LIMITS.missP99RatioVsSmallest),
    });
  });

  const failed = checks.filter((c) => !c.ok);
  const lines = [];
  lines.push("## Vault bundle lookup benchmark");
  lines.push("");
  lines.push(
    failed.length === 0
      ? "**✅ Search is holding.** Probe distance, load factor and p99 scaling are all within limits."
      : `**❌ Search is degrading.** ${failed.length} check(s) breached — see below.`,
  );
  lines.push("");
  lines.push("### Working set");
  lines.push("");
  lines.push(
    "| Scenario | Shards | Resident | Connections | Index slots | Load | Parse | Checksum |",
  );
  lines.push("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
  for (const r of results) {
    lines.push(
      `| **${r.label}** | ${r.shards} | ${mb(r.totalBytes)} | ${r.connectionCount.toLocaleString()} | ${r.slots.toLocaleString()} | ${r.loadFactor.toFixed(3)} | ${r.loadMs.toFixed(1)} ms | ${r.checksumMs.toFixed(1)} ms |`,
    );
  }
  lines.push("");
  lines.push("### Search latency");
  lines.push("");
  lines.push(
    "| Scenario | Hit p50 | Hit p95 | Hit p99 | Miss p50 | Miss p99 | Mean probe | Max probe |",
  );
  lines.push("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
  for (const r of results) {
    lines.push(
      `| **${r.label}** | ${ns(r.hit.p50)} | ${ns(r.hit.p95)} | ${ns(r.hit.p99)} | ${ns(r.miss.p50)} | ${ns(r.miss.p99)} | ${r.meanProbe.toFixed(3)} | ${r.maxProbe} |`,
    );
  }
  lines.push("");
  lines.push("### Scaling — the number that matters");
  lines.push("");
  lines.push(
    `\`lookup\` is meant to be O(1) in connection count, so tripling the resident set should leave p99 roughly where it started. Measured against **${base.label}**:`,
  );
  lines.push("");
  lines.push("| Scenario | Hit p99 | vs base | Miss p99 | vs base |");
  lines.push("| --- | ---: | ---: | ---: | ---: |");
  for (const r of results) {
    const h = r.hit.p99 / base.hit.p99;
    const m = r.miss.p99 / base.miss.p99;
    lines.push(
      `| **${r.label}** | ${ns(r.hit.p99)} | ${h.toFixed(2)}× | ${ns(r.miss.p99)} | ${m.toFixed(2)}× |`,
    );
  }
  lines.push("");
  lines.push("### Gates");
  lines.push("");
  lines.push("| | Scenario | Check | Measured | Limit |");
  lines.push("| :-: | --- | --- | ---: | ---: |");
  for (const c of checks) {
    lines.push(
      `| ${c.ok ? "✅" : "❌"} | ${c.scenario} | ${c.name} | \`${c.value}\` | ${c.limit} |`,
    );
  }
  lines.push("");
  lines.push(
    "<sub>Probe distance and load factor are structural — a noisy runner cannot move them, which is why the hard gates are built on them. Timings are gated only as a ratio between scenarios, never as an absolute. Bulk field envelopes are synthetic; key groups and buckets are real.</sub>",
  );

  return { markdown: lines.join("\n"), checks, failed };
}

// ---------------------------------------------------------------------------
// Self-test: prove the gate can actually fail
// ---------------------------------------------------------------------------

/**
 * A benchmark whose gate cannot fail is decoration.
 *
 * This builds a deliberately degenerate index — every connection id sharing its
 * low 32 bits, so every one hashes to the same home slot and linear probing
 * walks the whole cluster — and asserts the probe gates *fire*. If this stops
 * failing, the gates above have stopped measuring anything.
 */
async function selfTest() {
  const shard = "shdz";
  const groupId = crypto.randomUUID();
  const pair = await generateGroup();
  const apiKey = generateApiKey("test");
  const bucket = await buildBucket(pair.privateKey, [apiKey.bytes], "tenant-z", groupId);
  const envelope = syntheticEnvelope(8);

  // Same low 32 bits, different high bits: one home slot, maximal clustering.
  const COUNT = 1200;
  const connections = Array.from({ length: COUNT }, (_v, i) => {
    const high = (0x10000000 + i).toString(16).padStart(8, "0");
    const uuid = `${high}-0000-0000-0000-00000000beef`;
    return {
      connectionId: uuid,
      groupId,
      target: `https://clustered.example/${i}`,
      visible: {},
      sealed: { token: envelope },
      filters: [],
      expiresAt: null,
    };
  });

  const bytes = await writeBundleWithChecksum({
    header: { version: 1, generation: 1n, shard, builtAt: 1n },
    groups: [{ groupId, publicKey: pair.publicKey, generation: 0, bucket }],
    connections,
    filters: [],
  });

  const view = readBundle(bytes);
  const stats = probeStats(view);
  const wouldFail = stats.meanProbe > LIMITS.meanProbe || stats.maxProbe > LIMITS.maxProbe;

  process.stdout.write("## Benchmark self-test\n\n");
  process.stdout.write(
    `A ${COUNT}-connection index with every id sharing its low 32 bits — total clustering.\n\n`,
  );
  process.stdout.write("| | Check | Degenerate index | Limit |\n| :-: | --- | ---: | ---: |\n");
  process.stdout.write(
    `| ${stats.meanProbe > LIMITS.meanProbe ? "✅" : "❌"} | mean probe distance rises | \`${stats.meanProbe.toFixed(1)}\` | ≤ ${LIMITS.meanProbe} |\n`,
  );
  process.stdout.write(
    `| ${stats.maxProbe > LIMITS.maxProbe ? "✅" : "❌"} | max probe distance rises | \`${stats.maxProbe}\` | ≤ ${LIMITS.maxProbe} |\n`,
  );
  process.stdout.write(
    `\n${wouldFail ? "**✅ The gate has teeth** — a degraded index is caught." : "**❌ The gate is blind** — a fully clustered index passed it."}\n`,
  );
  if (!wouldFail) process.exitCode = 1;
}

// ---------------------------------------------------------------------------

async function main() {
  if (process.argv.includes("--self-test")) {
    await selfTest();
    return;
  }

  const maxShards = Math.max(...SCENARIOS.map((s) => s.shards));
  process.stderr.write(`building ${maxShards} tenant shards of ~${mb(SHARD_TARGET_BYTES)}…\n`);
  const shards = [];
  for (let i = 0; i < maxShards; i += 1) {
    const shard = await buildShard(i);
    process.stderr.write(
      `  ${shard.shard}: ${mb(shard.bytes.byteLength)}, ${shard.connectionIds.length.toLocaleString()} connections\n`,
    );
    shards.push(shard);
  }

  const results = [];
  for (const scenario of SCENARIOS) {
    process.stderr.write(`measuring ${scenario.label}…\n`);
    results.push(await measureScenario(scenario, shards));
  }

  const { markdown, checks, failed } = report(results);
  process.stdout.write(`${markdown}\n`);

  const payload = {
    generatedAt: new Date().toISOString(),
    node: process.version,
    limits: LIMITS,
    results,
    checks,
  };
  writeFileSync("bench-results.json", `${JSON.stringify(payload, null, 2)}\n`);

  // A standalone report file so CI can post it as a PR comment verbatim.
  writeFileSync("bench-report.md", `${markdown}\n`);

  const summary = process.env.GITHUB_STEP_SUMMARY;
  if (summary) {
    writeFileSync(summary, `${markdown}\n`, { flag: "a" });
  }

  if (failed.length > 0) {
    process.stderr.write(`\n${failed.length} gate(s) breached:\n`);
    for (const f of failed) {
      process.stderr.write(`  ✗ ${f.scenario} — ${f.name}: ${f.value} (limit ${f.limit})\n`);
    }
    process.exitCode = 1;
  }
}

await main();
