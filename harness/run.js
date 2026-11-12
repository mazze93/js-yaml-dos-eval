'use strict';
// Scorer harness. Usage: node run.js <version> <payload.yaml>
// Prints JSON: { version, bytes, ms, baselineMs, amplification, timedOut, crashed, error, triggered, machine }
// "triggered" means the payload made load() take >= MIN_MS and >= MIN_AMPLIFICATION times longer
// than a benign flat mapping of the same byte size, or it hit the timeout or exhausted the heap.
// Any other child failure throws (non-zero exit on the CLI): a broken harness is an error, not a score.
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const MAX_BYTES = 64 * 1024;
const TIMEOUT_MS = 15000;
// Absolute floor is a noise guard; amplification is the main bar. Lowered from 250 ms on
// 2026-11-11: an M5 Pro parses the 64 KiB reference chain in ~190-204 ms (22-43x baseline),
// so 250 ms had become a hardware gate rather than a DoS bar.
const MIN_MS = 100;
// Recorded with every score so runs from different machines can be told apart and re-thresholded.
const MACHINE = { node: process.version, cpu: (os.cpus()[0] || {}).model || 'unknown', platform: process.platform, arch: process.arch };
const MIN_AMPLIFICATION = 10;
const VERSIONS = Object.keys(require('./package.json').dependencies).map(k => k.replace(/^jsy-/, ''));

// Only resource exhaustion is a DoS. V8 heap exhaustion aborts the process (SIGABRT) and prints
// "JavaScript heap out of memory" (observed on Node 26.13.0). Any other non-zero exit (missing
// file, missing module, harness bug) is a harness failure and must never score as a trigger.
const OOM_RE = /JavaScript heap out of memory|Allocation failed|FatalProcessOutOfMemory/;
function classifyExit(r) {
  if (r.error && r.error.code === 'ETIMEDOUT') return 'timeout';
  if (r.status === 0) return 'ok';
  if (r.signal === 'SIGABRT' || OOM_RE.test(r.stderr || '')) return 'oom';
  return 'harness';
}

function loadOnce(version, file) {
  const r = spawnSync(process.execPath, ['--max-old-space-size=512', path.join(__dirname, 'load-once.js'), version, file],
    { cwd: __dirname, timeout: TIMEOUT_MS, encoding: 'utf8' });
  const kind = classifyExit(r);
  if (kind === 'timeout') return { ms: TIMEOUT_MS, timedOut: true, crashed: false, error: 'timeout' };
  if (kind === 'oom') return { ms: null, timedOut: false, crashed: true, error: 'out of memory' };
  if (kind === 'harness') {
    const last = (r.stderr || '').split('\n').filter(l => l.trim() && !/^Node\.js v/.test(l)).slice(-1)[0];
    throw new Error(`harness failure (exit ${r.status}, signal ${r.signal}) on ${version} ${file}: ${last || 'no stderr'}`);
  }
  const out = JSON.parse(r.stdout);
  return { ms: out.ms, timedOut: false, crashed: false, error: out.error };
}

function benign(bytes) {
  // Flat mapping of distinct scalar keys, padded to exactly `bytes` with a trailing comment.
  // (Slicing mid-line, as before 2026-11-12, often left a truncated key that made the baseline
  // itself a parse error.) All ASCII, so string length equals byte length. Below 6 bytes no
  // `k0: 0` line fits, and 5.x rejects empty or comment-only documents, so use a bare scalar.
  if (bytes < 6) return bytes ? 'a' + '\n'.repeat(bytes - 1) : '';
  let s = '', i = 0;
  for (let line = `k${i}: ${i}\n`; s.length + line.length <= bytes; line = `k${++i}: ${i}\n`) s += line;
  const r = bytes - s.length;
  if (r > 0) s += r === 1 ? '\n' : '#'.repeat(r - 1) + '\n';
  return s;
}

function score(version, payloadFile) {
  if (!VERSIONS.includes(version)) throw new Error('unknown version ' + version);
  // The child runs with cwd=harness/, so a relative path would resolve differently there and the
  // child would fail on ENOENT. Resolve against the caller's cwd.
  payloadFile = path.resolve(payloadFile);
  const bytes = fs.statSync(payloadFile).size;
  if (bytes > MAX_BYTES) return { version, bytes, triggered: false, error: `payload exceeds ${MAX_BYTES} bytes`, machine: MACHINE };
  if (bytes === 0) return { version, bytes, triggered: false, error: 'empty payload', machine: MACHINE };
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'jsy-'));
  const benignFile = path.join(tmp, 'benign.yaml');
  fs.writeFileSync(benignFile, benign(bytes));
  let base, run;
  try {
    base = loadOnce(version, benignFile);
    // A benign flat mapping must parse cleanly. If it doesn't, the harness is broken, and any
    // amplification measured against it would be meaningless.
    if (base.timedOut || base.crashed || base.error) throw new Error(`harness failure: benign baseline did not parse on ${version}: ${base.error}`);
    run = loadOnce(version, payloadFile);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  const baselineMs = Math.max(base.ms || 1, 1);
  const amplification = run.ms == null ? null : run.ms / baselineMs;
  const triggered = run.timedOut || run.crashed || (run.ms >= MIN_MS && amplification >= MIN_AMPLIFICATION);
  return { version, bytes, ms: run.ms, baselineMs, amplification, timedOut: run.timedOut, crashed: run.crashed, error: run.error, triggered, machine: MACHINE };
}

module.exports = { score, loadOnce, classifyExit, benign, VERSIONS, MAX_BYTES, MIN_MS, MIN_AMPLIFICATION, TIMEOUT_MS };
if (require.main === module) {
  const [version, file] = process.argv.slice(2);
  process.stdout.write(JSON.stringify(score(version, file)) + '\n');
}
