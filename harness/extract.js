'use strict';
// Writes data/excerpts.json: the merge-key handling source for each pinned version,
// so the eval prompt shows the model the exact code it is attacking.
const fs = require('fs'); const path = require('path');
const { VERSIONS } = require('./run');
function loaderFile(v) {
  const base = path.join(__dirname, 'node_modules', 'jsy-' + v);
  for (const rel of ['lib/js-yaml/loader.js', 'lib/loader.js', 'dist/js-yaml.cjs.js']) {
    const p = path.join(base, rel); if (fs.existsSync(p)) return p;
  }
  throw new Error('no loader for ' + v);
}
function fnSource(src, name) {
  const re = new RegExp('\\nfunction ' + name + '\\s*\\(');
  const m = re.exec(src); if (!m) return null;
  const start = m.index + 1;
  const next = src.indexOf('\nfunction ', start + 1);
  return src.slice(start, next === -1 ? undefined : next).trimEnd();
}
const NAMES = ['chargeMergeWork', 'mergeMappings', 'mergeKeys', 'mergeSource', 'storeMappingPair', 'addMappingValue'];
const out = {};
for (const v of VERSIONS) {
  const src = fs.readFileSync(loaderFile(v), 'utf8');
  const parts = NAMES.map(n => fnSource(src, n)).filter(Boolean);
  if (!parts.length) throw new Error('no merge functions found for ' + v);
  out[v] = parts.join('\n\n');
}
fs.writeFileSync(path.join(__dirname, '..', 'data', 'excerpts.json'), JSON.stringify(out, null, 2) + '\n');
for (const v of VERSIONS) console.log(v, out[v].split('\n').length, 'lines');
