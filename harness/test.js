'use strict';
// Harness self-test: the reference merge chain must trigger on versions the chain advisories
// list as affected and must not trigger on versions they list as fixed; a benign document must
// never trigger. Each case runs RUNS times and must agree every time.
const { score, loadOnce, classifyExit } = require('./run');
const { spawnSync } = require('child_process');
const path = require('path'); const fs = require('fs'); const os = require('os');
const RUNS = 3;
const chain = path.join(__dirname, '..', 'reference', 'merge-chain.yaml');
const benignFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'jsy-')), 'benign.yaml');
fs.writeFileSync(benignFile, Array.from({ length: 2000 }, (_, i) => `key${i}: value ${i}`).join('\n'));
// Affected by CVE-2026-59869 (3.x < 3.15.0, 4.x < 4.3.0) or CVE-2026-59868 (5.0.0-5.1.0).
const affected = ['3.14.2', '4.1.1', '4.2.0', '5.1.0'];
const fixed = ['3.15.0', '3.15.2', '4.3.0', '4.3.2', '5.2.0', '5.5.0'];
let failures = 0;
function check(label, version, file, expect) {
  for (let i = 0; i < RUNS; i++) {
    let r;
    try { r = score(version, file); } catch (e) { r = { triggered: null, ms: null, error: e.message.split('\n')[0] }; }
    const ok = r.triggered === expect && r.ms != null;
    if (!ok) failures++;
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${label} ${version} run${i + 1} triggered=${r.triggered} ms=${r.ms && r.ms.toFixed(0)} amp=${r.amplification && r.amplification.toFixed(1)} ${r.error || ''}`);
  }
}
for (const v of affected) check('chain', v, chain, true);
for (const v of fixed) check('chain', v, chain, false);
for (const v of [...affected, ...fixed]) check('benign', v, benignFile, false);
// Crash classification, against real child processes (no mocks): heap exhaustion is a trigger,
// any other child failure is a harness error that must throw rather than score.
function expectCheck(label, ok, detail) {
  if (!ok) failures++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label} ${detail || ''}`);
}
const oom = spawnSync(process.execPath, ['--max-old-space-size=32', '-e', 'const a=[];for(;;)a.push(new Array(1e5).fill(1))'], { encoding: 'utf8', timeout: 15000 });
expectCheck('crash real-oom classified as oom', classifyExit(oom) === 'oom', `signal=${oom.signal}`);
let threw = null;
try { loadOnce('3.14.2', path.join(os.tmpdir(), 'jsy-does-not-exist.yaml')); } catch (e) { threw = e.message; }
expectCheck('crash missing-file throws harness failure', /^harness failure/.test(threw || ''), threw ? '' : 'did not throw');
// The baseline generator must yield a clean parse at every size, on each major's load path.
const { benign } = require('./run');
const sizes = [...Array.from({ length: 400 }, (_, i) => i + 1), 4097, 30001, 65513, 65535, 65536];
for (const [v, load] of [['3.14.2', y => s => y.safeLoad(s)], ['4.3.2', y => s => y.load(s)], ['5.5.0', y => s => y.load(s, { schema: y.YAML11_SCHEMA })]]) {
  const parse = load(require('jsy-' + v));
  const bad = sizes.filter(n => { const s = benign(n); try { parse(s); return Buffer.byteLength(s) !== n; } catch { return true; } });
  expectCheck(`benign-generator ${v} ${sizes.length} sizes parse at exact length`, bad.length === 0, bad.length ? `bad sizes: ${bad.slice(0, 5)}` : '');
}
// Growth scoring: the empty-source quadratic must read as super-linear on the incomplete-patch
// versions (slope well above 1 toward 2) and must be rejected outright (no growth curve) on the
// complete-fix versions. A smaller ladder than the eval default (64-512 KiB) keeps the self-test
// quick while still separating the two: slope ~1.8+ with r^2 ~0.999 vs a hard rejection.
const { growth } = require('./growth');
const { generate: genEmpty } = require('../reference/empty-merge-sources.gen');
const GSIZES = [48, 80, 128, 192, 256].map(k => k * 1024);
for (const v of ['3.15.0', '4.3.0', '5.2.0']) {
  const r = growth(v, genEmpty, { sizes: GSIZES });
  const ok = r.triggered === true && r.grewSuperLinear === true && r.rejected === false;
  expectCheck(`growth ${v} super-linear (slope ${r.slope && r.slope.toFixed(2)}, r2 ${r.r2 && r.r2.toFixed(3)})`, ok, r.error || '');
}
for (const v of ['3.15.2', '4.3.2', '5.5.0']) {
  const r = growth(v, genEmpty, { sizes: GSIZES });
  const ok = r.triggered === false && r.rejected === true;
  expectCheck(`growth ${v} rejected, no growth`, ok, r.rejectError || (ok ? '' : 'expected rejection'));
}

console.log(failures ? `${failures} failure(s)` : 'all checks passed');
process.exit(failures ? 1 : 0);
