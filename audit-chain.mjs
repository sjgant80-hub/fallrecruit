// audit-chain.mjs — a tamper-evident log that can actually be checked.
//
// ⚑ WHY THIS EXISTS. Nine tools in this estate write a hash-linked audit log — clinic, vet, HR,
// recruitment, claims, legal, insurance, books, practice — and not one of them ever re-walked it.
// prevHash and docHash were written on every action and never read back, so the tamper-evidence was
// a claim about the data rather than a property of it. A regulator asking "prove this was not edited"
// would have been handed a log that could not answer.
//
// ⚑ AND WHY IT IS A FACTORY. The bug underneath the bug is that a writer and a verifier can disagree
// about WHICH BYTES were signed, and then a check passes that should not — or fails when nothing is
// wrong. Here both come out of one call and close over the same `payloadOf`, so they cannot drift.
// You cannot construct a verifier for one layout and a writer for another by accident.
//
// The byte layout itself is deliberately NOT fixed: the nine tools each sign different fields, and
// forcing one shape would either break their existing logs or quietly re-define what was signed.

/** The hash a chain starts from. An empty string, so the first entry has nothing behind it. */
export const GENESIS = '';

const isFn = (f) => typeof f === 'function';

/**
 * Build a chain that can write and check its own entries.
 *
 * @param opts.sha256    async (string) => hex digest. Injected so this stays pure and testable.
 * @param opts.payloadOf (prevHash, entry, index) => string — exactly the bytes that get signed.
 *                   May return a promise: one tool in this estate hashes the payload first and signs
 *                   THAT, so the layout itself needs to await a digest.
 * @param opts.hashField which field on an entry holds the chain hash. Default "docHash". One tool
 *                   keeps two hashes — a docHash over the payload and a separate `hash` for the
 *                   link — so the field cannot be assumed.
 */
export function auditChain(opts) {
  // A default parameter does not fire on an explicit null, and null is what a caller reading a
  // missing config hands you. Normalise, then read.
  const o = (opts && typeof opts === 'object') ? opts : {};
  const sha256 = o.sha256;
  const payloadOf = o.payloadOf;
  const hashField = (typeof o.hashField === 'string' && o.hashField) ? o.hashField : 'docHash';
  // ⚑ NOT EVERY CHAIN STARTS AT THE EMPTY STRING. One tool in this estate opens its log with 64
  // zeros. Assuming genesis would make its very first entry fail to verify, for ever.
  const genesis = (typeof o.genesis === 'string') ? o.genesis : GENESIS;
  if (!isFn(sha256)) throw new Error('auditChain needs a sha256(string) function');
  if (!isFn(payloadOf)) throw new Error('auditChain needs a payloadOf(prevHash, entry, index) function');

  /**
   * The hash the next entry must link to.
   *
   * The last row is read defensively because a corrupt log is exactly when this gets called: a null
   * or non-object at the end used to throw here, which turned "your audit log has a bad row" into
   * "the app crashed while trying to write an audit entry".
   */
  function headOf(entries) {
    const log = Array.isArray(entries) ? entries : [];
    if (!log.length) return genesis;
    const last = log[log.length - 1];
    if (!last || typeof last !== 'object') return genesis;
    return String(last[hashField] ?? '');
  }

  /**
   * Seal an entry onto the end of the log. Returns a NEW entry carrying prevHash and docHash —
   * it does not mutate what it was given, because an audit writer that edits its input is the
   * first thing anyone should distrust.
   */
  async function append(entries, entry) {
    const log = Array.isArray(entries) ? entries : [];
    const prevHash = headOf(log);
    // ⚑ RESPECT THE CALLER'S NUMBERING. These tools number entries from 1 and SIGN that number.
    // Overwriting it with a zero-based position would renumber every new entry and quietly change
    // what gets hashed.
    const given = (entry && typeof entry === 'object') ? entry.i : undefined;
    const i = Number.isFinite(given) ? given : log.length;
    const base = { ...(entry && typeof entry === 'object' ? entry : {}), i, prevHash };
    // ⚑ THE THIRD ARGUMENT IS THE POSITION IN THE LOG, NOT THE ENTRY'S OWN NUMBER. verify() walks the
    // array and passes the array index, so append must pass the same thing or a one-based log signs
    // one value and verifies against another — every entry written would fail its own check.
    // A layout that wants the entry's number reads it off the entry, where it lives.
    const pos = log.length;
    // await, because a layout may itself need to hash something before it can say what is signed.
    const digest = await sha256(await payloadOf(prevHash, base, pos));
    return { ...base, [hashField]: digest };
  }

  /**
   * Walk the log and report the FIRST entry that does not reproduce. The earliest break is when the
   * tampering happened; everything after it is just that break's wake, so reporting later ones would
   * bury the answer.
   *
   * `expectHead` is optional and closes the one hole a chain cannot close on its own — see below.
   */
  async function verify(entries, checkOpts) {
    const log = Array.isArray(entries) ? entries : [];
    const c = (checkOpts && typeof checkOpts === 'object') ? checkOpts : {};
    let prev = genesis;

    for (let i = 0; i < log.length; i++) {
      const e = (log[i] && typeof log[i] === 'object') ? log[i] : {};
      if (String(e.prevHash ?? '') !== prev) {
        return { ok: false, brokeAt: i, id: e.id ?? null, entries: log.length,
                 reason: 'this entry does not link to the one before it — something was inserted, removed or reordered' };
      }
      const expected = await sha256(await payloadOf(prev, e, i));
      if (expected !== e[hashField]) {
        return { ok: false, brokeAt: i, id: e.id ?? null, entries: log.length,
                 reason: 'this entry was altered after it was written' };
      }
      prev = e[hashField];
    }

    // ⚑ THE HONEST BOUND. A chain proves nothing was changed or removed from the MIDDLE. Delete the
    // last few entries and what remains is a perfectly valid chain — the log simply looks shorter.
    // The only defence is knowing what the head should be, from somewhere the editor could not reach.
    // Without expectHead this returns ok:true and SAYS the tail is unproven, rather than implying a
    // completeness it cannot demonstrate.
    if (c.expectHead != null) {
      if (String(c.expectHead) !== prev) {
        return { ok: false, brokeAt: log.length, id: null, entries: log.length,
                 reason: 'the log ends earlier than it should — entries were removed from the end' };
      }
      return { ok: true, entries: log.length, tailProven: true,
               reason: 'every entry reproduces its own hash, and the log ends where it was expected to' };
    }

    return {
      ok: true, entries: log.length, tailProven: false,
      reason: log.length
        ? 'every entry reproduces its own hash — but nothing here can prove entries were not removed from the END; keep the head hash somewhere separate to close that'
        : 'the log is empty',
    };
  }

  return { append, verify, headOf, payloadOf };
}

export default { auditChain, GENESIS };
