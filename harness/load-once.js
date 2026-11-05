'use strict';
// Child process: parse one YAML file with one pinned js-yaml version and report timing as JSON.
// Uses each version's safe path: safeLoad (3.x), load with the default safe schema (4.x),
// load with YAML11_SCHEMA (5.x, needed because merge keys are not in 5.x's default schema).
const fs = require('fs');
const [version, file] = process.argv.slice(2);
const y = require('jsy-' + version);
const src = fs.readFileSync(file, 'utf8');
let fn;
if (version.startsWith('3.')) fn = () => y.safeLoad(src);
else if (version.startsWith('4.')) fn = () => y.load(src);
else fn = () => y.load(src, { schema: y.YAML11_SCHEMA });
const t0 = process.hrtime.bigint();
let error = null;
try { fn(); } catch (e) { error = String(e && e.message || e).split('\n')[0].slice(0, 200); }
const ms = Number(process.hrtime.bigint() - t0) / 1e6;
process.stdout.write(JSON.stringify({ version, ms, error }));
