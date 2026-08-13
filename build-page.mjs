// build-page.mjs — put the GATED audit chain inside the page.
//
// fallvet is a single offline file, so the kernel is inlined rather than imported: a veterinary
// practice keeps working when the broadband does not. Inlined VERBATIM — if this script could edit
// the kernel on the way in, the thing that was gated and the thing that ships would be two different
// programs, and the green gate would be about neither.
import { readFileSync, writeFileSync } from 'node:fs';

const OPEN = '/* __AUDIT_KERNEL__ */';
const CLOSE = '/* __END_AUDIT_KERNEL__ */';

// The export KEYWORD is removed so the code is legal in a classic script. Nothing else is touched.
// The \r? matters: these files are CRLF, and `.` in a JS regex stops at \r.
const strip = (src) => src
  .replace(/^#!.*\r?\n/, '')
  .replace(/^import[^\n]*\n/gm, '')
  .replace(/^export default[\s\S]*?;\s*$/m, '')
  .replace(/^export (function|const|async function)/gm, '$1')
  .replace(/^export \{[^}]*\};?\s*$/gm, '');

const kernel = strip(readFileSync('audit-chain.mjs', 'utf8'))
  + '\n' + strip(readFileSync('audit.mjs', 'utf8'));

const html = readFileSync('index.html', 'utf8');
const a = html.indexOf(OPEN), b = html.indexOf(CLOSE);
if (a < 0 || b < 0) throw new Error('the kernel markers are missing from index.html — refusing to guess where the kernel goes');

const out = html.slice(0, a + OPEN.length) + '\n' + kernel + '\n' + html.slice(b);
writeFileSync('index.html', out);

// A page that silently shipped none of the kernel would still look fine. Check.
const check = readFileSync('index.html', 'utf8');
for (const fn of ['function auditChain', 'function payloadOf', 'function makeAuditChain']) {
  if (!check.includes(fn)) throw new Error(`the page does not contain ${fn} — the inline did not take`);
}
if (/^export /m.test(check.slice(a, check.indexOf(CLOSE)))) throw new Error('module syntax survived into the page');
console.log(`index.html — audit chain inlined, ${kernel.split('\n').length} lines, page ${(out.length / 1024).toFixed(0)}KB`);
