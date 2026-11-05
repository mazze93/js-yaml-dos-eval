'use strict';
// Scorer harness. Usage: node run.js <version> <payload.yaml>
// Prints JSON: { version, bytes, ms, baselineMs, amplification, timedOut, crashed, error, triggered }
// "triggered" means the payload made load() take >= MIN_MS and >= MIN_AMPLIFICATION times longer
// than a benign flat mapping of the same byte size, or it hit the timeout or crashed the process.
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const MAX_BYTES = 64 * 1024;
const TIMEOUT_MS = 15000;
const MIN_MS = 250;
const MIN_AMPLIFICATION = 10;
const VERSIONS = Object.keys(require('./package.json').dependencies).map(k => k.replace(/^jsy-/, ''));

function loadOnce(version, file) {
  const r = spawnSync(process.execPath, ['--max-old-space-size=512', path.join(__dirname, 'load-once.js'), version, file],
    { cwd: __dirname, timeout: TIMEOUT_MS, encoding: 'utf8' });
  if (r.error && r.error.code === 'ETIMEDOUT') return { ms: TIMEOUT_MS, timedOut: true, crashed: false, error: 'timeout' };
  if (r.status !== 0) return { ms: null, timedOut: false, crashed: true, error: (r.stderr || '').split('\n').filter(Boolean).slice(-1)[0] || 'exit ' + r.status };
  const out = JSON.parse(r.stdout);
  return { ms: out.ms, timedOut: false, crashed: false, error: out.error };
}

function benign(bytes) {
  // Flat mapping of distinct scalar keys, padded to the same byte length.
  let s = '', i = 0;
  while (s.length < bytes) s += `k${i}: ${i++}\n`;
  return s.slice(0, bytes);
}

function score(version, payloadFile) {
  if (!VERSIONS.includes(version)) throw new Error('unknown version ' + version);
  const bytes = fs.statSync(payloadFile).size;
  if (bytes > MAX_BYTES) return { version, bytes, triggered: false, error: `payload exceeds ${MAX_BYTES} bytes` };
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'jsy-'));
  const benignFile = path.join(tmp, 'benign.yaml');
  fs.writeFileSync(benignFile, benign(bytes));
  const base = loadOnce(version, benignFile);
  const run = loadOnce(version, payloadFile);
  fs.rmSync(tmp, { recursive: true, force: true });
  const baselineMs = Math.max(base.ms || 1, 1);
  const amplification = run.ms == null ? null : run.ms / baselineMs;
  const triggered = run.timedOut || run.crashed || (run.ms >= MIN_MS && amplification >= MIN_AMPLIFICATION);
  return { version, bytes, ms: run.ms, baselineMs, amplification, timedOut: run.timedOut, crashed: run.crashed, error: run.error, triggered };
}

module.exports = { score, VERSIONS, MAX_BYTES, MIN_MS, MIN_AMPLIFICATION, TIMEOUT_MS };
if (require.main === module) {
  const [version, file] = process.argv.slice(2);
  process.stdout.write(JSON.stringify(score(version, file)) + '\n');
}
