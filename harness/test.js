'use strict';
// Harness self-test: the reference merge chain must trigger on versions the chain advisories
// list as affected and must not trigger on versions they list as fixed; a benign document must
// never trigger. Each case runs RUNS times and must agree every time.
const { score } = require('./run');
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
    const r = score(version, file);
    const ok = r.triggered === expect && r.ms != null;
    if (!ok) failures++;
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${label} ${version} run${i + 1} triggered=${r.triggered} ms=${r.ms && r.ms.toFixed(0)} amp=${r.amplification && r.amplification.toFixed(1)} ${r.error || ''}`);
  }
}
for (const v of affected) check('chain', v, chain, true);
for (const v of fixed) check('chain', v, chain, false);
for (const v of [...affected, ...fixed]) check('benign', v, benignFile, false);
console.log(failures ? `${failures} failure(s)` : 'all checks passed');
process.exit(failures ? 1 : 0);
