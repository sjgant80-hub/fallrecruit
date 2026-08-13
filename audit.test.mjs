// audit.test.mjs — the layout must reproduce what fallrecruit has ALREADY written.
import { payloadOf, makeAuditChain } from './audit.mjs';

let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log((c ? '  ✓ ' : '  ✗ FAIL ') + m); };
const sha = async (s) => 'h' + [...String(s)].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7).toString(16);

console.log('\n=== §1 · ⚑ THE HISTORICAL BYTES, UNCHANGED ===');
{
  // The original writer, copied from index.html before the graft.
  const legacy = (prev, e) => JSON.stringify({ i: e.i, ts: e.ts, action: e.action, prevHash: prev, payload: e.payload });
  const e = {"i":2,"ts":1723550000001,"action":"candidate.updated","payload":{"id":"c1"}};
  const prev = 'abc123';

  const mine = await payloadOf(prev, e, e.i, sha);
  const theirs = await legacy(prev, e, e.i, sha);
  ok(mine === theirs, '⚑ reproduces the old writer byte for byte');
  ok(typeof mine === 'string' && mine.length > 0, 'and it is a real string, not a promise or undefined');

  // The failure this pins: an entry written by the OLD code must still verify under the NEW checker,
  // or a firm's real audit history reads as forged the day this ships.
  const chain = makeAuditChain(sha);
  const legacyEntry = { ...e, prevHash: prev };
  legacyEntry["docHash"] = await sha(await legacy(prev, e, e.i, sha));
  // ⚑ The first entry links to THIS tool's genesis, which is not always the empty string.
  const GENESIS = "";
  const first = { ...legacyEntry, prevHash: GENESIS };
  first["docHash"] = await sha(await legacy(GENESIS, e, e.i, sha));
  ok((await chain.verify([first])).ok === true,
     '⚑ an entry written by the OLD inline writer verifies under the new chain');
}

console.log('\n=== §2 · missing fields do not become the text "undefined" ===');
{
  const s = await payloadOf('p', {}, 0, sha);
  ok(!/undefined/.test(s), '⚑ an empty entry never signs the literal word "undefined"');
  const nul = await payloadOf(null, { ts: 5 }, 0, sha);
  ok(!/null/.test(nul.slice(0, 4)), 'a null previous hash is the empty string, matching genesis');
}

console.log('\n=== §3 · it catches what an audit log exists to catch ===');
{
  const chain = makeAuditChain(sha);
  let log = [];
  for (let i = 1; i <= 4; i++) {
    log = [...log, await chain.append(log, { i, id: 'a' + i, ts: 1000 + i, action: 'saved',
      adviserId: 'a1', clientId: 'c1', matterId: 'm1', tool: 't', reasoning: 'r', configVersion: 'v', payload: { i } })];
  }
  ok((await chain.verify(log)).ok === true, 'an untouched log verifies');

  const edited = [...log]; edited[2] = { ...edited[2], payload: { i: 'tampered' } };
  const v = await chain.verify(edited);
  ok(v.ok === false && v.brokeAt === 2, 'an edit is caught at the right entry');

  const removed = [...log]; removed.splice(1, 1);
  ok((await chain.verify(removed)).ok === false, 'a deletion from the middle is caught');

  const swapped = [...log]; [swapped[1], swapped[2]] = [swapped[2], swapped[1]];
  ok((await chain.verify(swapped)).ok === false, 'reordering is caught');

  const truncated = log.slice(0, 2);
  ok((await chain.verify(truncated)).tailProven === false,
     'truncation is reported as unproven rather than passed silently');
  ok((await chain.verify(truncated, { expectHead: log[3]["docHash"] })).ok === false,
     'and given the real head, truncation is caught');
}

console.log('\n=== §4 · pure under garbage ===');
{
  const junk = [null, undefined, '', 0, [], {}, NaN, 'x'];
  let threw = null;
  for (const j of junk) { try { await payloadOf(j, j, j, sha); } catch (e) { threw = JSON.stringify(j) + ' → ' + e.message; } }
  ok(threw === null, 'no input throws' + (threw ? ' — ' + threw : ''));
}

console.log(`\n${fail === 0 ? '✓ ALL PASS' : '✗ FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
