// audit-chain.test.mjs — PROOF-OF-PLAY for the log nine tools were writing and none were checking.
import { auditChain, GENESIS } from './audit-chain.mjs';

let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log((c ? '  ✓ ' : '  ✗ FAIL ') + m); };

// Deterministic stand-in for WebCrypto. A real SHA here would only prove Node's crypto works.
const sha = async (s) => 'h' + [...String(s)].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7).toString(16);
// One tool's layout. The point of the factory is that this is a parameter, not a constant.
const payloadOf = (prev, e, i) => prev + '|' + i + '|' + (e.ts ?? '') + '|' + (e.action ?? '') + '|' + JSON.stringify(e.payload ?? {});

const chain = auditChain({ sha256: sha, payloadOf });
const build = async (n) => {
  let log = [];
  for (let i = 0; i < n; i++) log = [...log, await chain.append(log, { id: 'a' + i, ts: 1000 + i, action: 'saved', payload: { i } })];
  return log;
};

console.log('\n=== §1 · ⚑ WRITER AND VERIFIER CANNOT DISAGREE ===');
{
  ok(typeof chain.append === 'function' && typeof chain.verify === 'function',
     'one call returns both halves, closing over the same layout');
  ok(chain.payloadOf === payloadOf, 'and the layout it signed with is the one it was handed');

  let threw = null;
  try { auditChain({ payloadOf }); } catch (e) { threw = e.message; }
  ok(/needs a sha256/.test(String(threw)), 'no hash function is refused loudly — never treated as a pass');
  threw = null;
  try { auditChain({ sha256: sha }); } catch (e) { threw = e.message; }
  ok(/needs a payloadOf/.test(String(threw)), '⚑ and no layout is refused too — signing unknown bytes proves nothing');
  // ⚑ ASSERT WHICH ERROR, NOT JUST THAT ONE HAPPENED. "something threw" passes even when the config
  // guard has collapsed and the real failure is a TypeError deep inside — the gate caught exactly
  // that, because typeof null is 'object' and a broken guard still crashes, just later and worse.
  for (const bad of [null, undefined, 'nope', 42, []]) {
    threw = null;
    try { auditChain(bad); } catch (e) { threw = e.message; }
    ok(/needs a sha256/.test(String(threw)),
       `a ${bad === null ? 'null' : typeof bad} config is refused with the RIGHT message, not a TypeError`);
  }
}

console.log('\n=== §2 · appending links to the end ===');
{
  const log = await build(3);
  ok(log.length === 3, 'three entries appended');
  ok(log[0].prevHash === GENESIS, 'the first links to genesis');
  ok(log[1].prevHash === log[0].docHash && log[2].prevHash === log[1].docHash, 'each links to the one before');
  ok(log[0].i === 0 && log[2].i === 2, 'the index travels on the entry');
  ok(chain.headOf(log) === log[2].docHash, 'the head is the last docHash');
  ok(chain.headOf([]) === GENESIS && chain.headOf(null) === GENESIS, 'an empty log heads at genesis');

  const input = { id: 'x', payload: { a: 1 } };
  const sealed = await chain.append([], input);
  ok(input.docHash === undefined && input.prevHash === undefined,
     '⚑ append does NOT mutate what it was given — a writer that edits its input is the first thing to distrust');
  ok(sealed.docHash && sealed.id === 'x', 'and the sealed copy carries both the original fields and the hash');

  // ⚑ A NON-OBJECT ENTRY CONTRIBUTES NOTHING. Spreading a string would scatter its characters across
  // the record as numeric keys — an audit entry made of {0:'x',1:'y'} that still hashes and still
  // links, so the log would look sound while carrying nonsense.
  const fromString = await chain.append([], 'oops');
  ok(Object.keys(fromString).sort().join(',') === 'docHash,i,prevHash',
     'appending a string yields only the chain fields, never its characters');
  const fromNumber = await chain.append([], 42);
  ok(Object.keys(fromNumber).sort().join(',') === 'docHash,i,prevHash', 'and neither does a number');
}

console.log('\n=== §3 · ⚑ WHAT IT MUST CATCH ===');
{
  ok((await chain.verify(await build(4))).ok === true, 'an untouched log verifies');

  const edited = await build(4); edited[2] = { ...edited[2], payload: { i: 'tampered' } };
  const e = await chain.verify(edited);
  ok(e.ok === false && e.brokeAt === 2 && e.id === 'a2', '⚑ an EDIT is caught, at the right entry');
  ok(/altered after it was written/.test(e.reason), 'with a reason a person can act on');

  const removed = await build(5); removed.splice(2, 1);
  const r = await chain.verify(removed);
  ok(r.ok === false && r.brokeAt === 2, '⚑ a DELETION from the middle is caught');

  const swapped = await build(4); [swapped[1], swapped[2]] = [swapped[2], swapped[1]];
  ok((await chain.verify(swapped)).ok === false, '⚑ REORDERING is caught');

  const inserted = await build(3);
  inserted.splice(1, 0, { id: 'fake', ts: 1, action: 'saved', payload: {}, prevHash: inserted[0].docHash, docHash: 'made-up' });
  ok((await chain.verify(inserted)).ok === false, '⚑ an INSERTED entry is caught');

  const unlinked = await build(3); unlinked[1] = { ...unlinked[1], prevHash: 'somewhere-else' };
  const u = await chain.verify(unlinked);
  ok(u.ok === false && u.brokeAt === 1 && /link/.test(u.reason), 'a broken link is caught and named as one');

  const twoBreaks = await build(5);
  twoBreaks[1] = { ...twoBreaks[1], payload: { i: 'x' } };
  twoBreaks[3] = { ...twoBreaks[3], payload: { i: 'y' } };
  ok((await chain.verify(twoBreaks)).brokeAt === 1,
     '⚑ the FIRST break is reported — the earliest one is when it happened, the rest are its wake');
}

console.log('\n=== §4 · ⚑ THE HOLE A CHAIN CANNOT CLOSE BY ITSELF ===');
{
  // Cut entries off the END and what is left is a perfectly valid chain. This is the one thing a
  // hash chain genuinely cannot detect, and the result says so rather than implying completeness.
  const full = await build(5);
  const truncated = full.slice(0, 3);
  const t = await chain.verify(truncated);
  ok(t.ok === true, 'a truncated log still verifies — every entry it kept is genuine');
  ok(t.tailProven === false, '⚑ but tailProven is FALSE');
  ok(/removed from the END/.test(t.reason), 'and the reason says plainly what it cannot prove');

  const withHead = await chain.verify(truncated, { expectHead: full[4].docHash });
  ok(withHead.ok === false && /ends earlier/.test(withHead.reason),
     '⚑ given the head it should have, truncation IS caught');
  const good = await chain.verify(full, { expectHead: full[4].docHash });
  ok(good.ok === true && good.tailProven === true, 'and a complete log against the right head proves its tail');

  const emptyChecked = await chain.verify([], { expectHead: GENESIS });
  ok(emptyChecked.ok === true, 'an empty log against genesis is complete');
  ok((await chain.verify([])).ok === true && /empty/.test((await chain.verify([])).reason), 'an empty log is honest about being empty');
}

console.log('\n=== §5 · the layout really is a parameter ===');
{
  // Two tools signing different fields must produce different chains, and neither must validate the
  // other — that is the whole reason the byte layout is injected instead of fixed.
  const otherLayout = (prev, e) => prev + '::' + (e.action ?? '');
  const other = auditChain({ sha256: sha, payloadOf: otherLayout });
  const mine = await build(3);
  ok((await other.verify(mine)).ok === false,
     "⚑ a chain built under one layout does NOT verify under another — otherwise the check means nothing");
  const theirs = [await other.append([], { id: 'z', action: 'saved' })];
  ok((await other.verify(theirs)).ok === true, 'and its own log verifies under its own layout');
}

console.log('\n=== §7 · ⚑ THE CHAIN FIELD IS NOT ALWAYS CALLED docHash ===');
{
  // One tool in this estate keeps TWO hashes: a docHash over the payload, and a separate `hash` that
  // is the actual link. Assuming the field name would have made its whole log unverifiable.
  const two = auditChain({ sha256: sha, payloadOf, hashField: 'hash' });
  let log = [];
  for (let i = 0; i < 3; i++) log = [...log, await two.append(log, { id: 'x' + i, ts: i, action: 'saved', payload: { i } })];
  ok(log[0].hash && log[0].docHash === undefined, '⚑ the digest lands on the field it was told to use, and only that one');
  ok(log[1].prevHash === log[0].hash, 'and the links are built from that field');
  ok(two.headOf(log) === log[2].hash, 'the head reads it too');
  ok((await two.verify(log)).ok === true, 'a log keyed on `hash` verifies');

  const t = [...log]; t[1] = { ...t[1], payload: { i: 'edited' } };
  ok((await two.verify(t)).ok === false, 'and tampering with it is still caught');

  // A chain told the wrong field name must NOT quietly pass.
  const wrongField = auditChain({ sha256: sha, payloadOf, hashField: 'docHash' });
  ok((await wrongField.verify(log)).ok === false,
     '⚑ reading the wrong field does not accidentally verify — it fails, loudly');

  ok(auditChain({ sha256: sha, payloadOf, hashField: '' }).headOf([{ docHash: 'd' }]) === 'd',
     'an empty field name falls back to the default rather than reading undefined');
  ok(auditChain({ sha256: sha, payloadOf, hashField: 7 }).headOf([{ docHash: 'd' }]) === 'd',
     'and so does a non-string');
}

console.log('\n=== §8 · ⚑ A LAYOUT MAY NEED TO HASH SOMETHING ITSELF ===');
{
  // fallpractice signs prevHash + sha256(payload) + ts + i — the layout has to await a digest before
  // it can say what the bytes are. A payloadOf that returns a promise must be awaited, or the chain
  // hashes the string "[object Promise]" for every entry and every log verifies against nonsense.
  const nested = async (prev, e, i) => prev + (await sha(JSON.stringify(e.payload ?? {}))) + (e.ts ?? '') + i;
  const c = auditChain({ sha256: sha, payloadOf: nested, hashField: 'hash' });
  let log = [];
  for (let i = 0; i < 3; i++) log = [...log, await c.append(log, { ts: 100 + i, payload: { i } })];
  ok(!String(log[0].hash).includes('Promise'), '⚑ the promise is awaited, not stringified');
  ok((await c.verify(log)).ok === true, 'an async layout round-trips');

  const t = [...log]; t[2] = { ...t[2], payload: { i: 99 } };
  const v = await c.verify(t);
  ok(v.ok === false && v.brokeAt === 2, 'and tampering under an async layout is caught at the right entry');
}

console.log('\n=== §9 · ⚑ NOT EVERY CHAIN STARTS AT THE EMPTY STRING ===');
{
  // One tool opens its log with 64 zeros. Assuming genesis would make its very first entry fail to
  // verify for ever — and the first entry is the one a regulator asks about.
  const ZEROS = '0'.repeat(64);
  const z = auditChain({ sha256: sha, payloadOf, genesis: ZEROS });
  ok(z.headOf([]) === ZEROS, '⚑ an empty log heads at the genesis it was given, not at ""');
  const first = await z.append([], { ts: 1, action: 'saved', payload: {} });
  ok(first.prevHash === ZEROS, 'and the first entry links to it');
  ok((await z.verify([first])).ok === true, 'a log opened at a custom genesis verifies');

  const dflt = auditChain({ sha256: sha, payloadOf });
  ok((await dflt.verify([first])).ok === false,
     '⚑ and a chain expecting the DEFAULT genesis rejects it — the opening value is part of the signature');
  ok(auditChain({ sha256: sha, payloadOf, genesis: 7 }).headOf([]) === GENESIS,
     'a non-string genesis falls back to the default rather than becoming the number 7');
}

console.log('\n=== §10 · ⚑ THE CALLER\'S NUMBERING IS NOT OVERWRITTEN ===');
{
  // Every trade tool here numbers entries from 1 and SIGNS that number. A kernel that replaced it
  // with a zero-based position would renumber every new entry and change what gets hashed.
  const c = auditChain({ sha256: sha, payloadOf });
  const one = await c.append([], { i: 1, ts: 1, action: 'saved', payload: {} });
  ok(one.i === 1, '⚑ an entry that arrives numbered 1 stays numbered 1');
  const two = await c.append([one], { i: 2, ts: 2, action: 'saved', payload: {} });
  ok(two.i === 2, 'and the next stays 2, not 1');
  ok((await c.verify([one, two])).ok === true, 'a one-based log verifies');

  const auto = await c.append([], { ts: 1, action: 'saved', payload: {} });
  ok(auto.i === 0, 'with no number given it still falls back to the position in the log');
  const auto2 = await c.append([auto], { ts: 2, action: 'saved', payload: {} });
  ok(auto2.i === 1, 'and keeps counting');
  const junkNum = await c.append([], { i: 'three', ts: 1, payload: {} });
  ok(junkNum.i === 0, 'a number that is not a number is ignored rather than signed as text');
}

console.log('\n=== §6 · pure under garbage ===');
{
  const junk = [null, undefined, '', 0, [], {}, NaN, [null], [{}], 'x'];
  let threw = null;
  for (const j of junk) {
    try { await chain.verify(j); await chain.verify(j, j); chain.headOf(j); await chain.append(j, j); }
    catch (e) { threw = `${JSON.stringify(j)} → ${e.message}`; }
  }
  ok(threw === null, 'no input throws' + (threw ? ' — ' + threw : ''));
  ok((await chain.verify([null, null])).ok === false, 'a log of nulls does not pass as valid');
}

console.log(`\n${fail === 0 ? '✓ ALL PASS' : '✗ FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
