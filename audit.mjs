// audit.mjs — fallrecruit's audit layout, and the chain built from it.
//
// ⚑ THE BYTES MUST NOT CHANGE. There are logs in the wild signed by the old inline writer. If this
// layout differs by one character, every entry a firm has already written stops reproducing and the
// verifier reports its whole history as tampered. Making a real audit trail look forged is a worse
// outcome than not checking it at all, so this is a faithful copy and audit.test.mjs pins it against
// the original formula.
//
// The chain semantics live in the shared, separately-gated audit-chain kernel. Only the byte layout
// is this repo's business.
import { auditChain } from './audit-chain.mjs';

export function payloadOf(prevHash, entry, index) {
  const e = (entry && typeof entry === 'object') ? entry : {};
  return JSON.stringify({ i: e.i, ts: e.ts, action: e.action, prevHash: String(prevHash == null ? '' : prevHash), payload: e.payload ?? {} });
}

/** The writer and the checker, from one call, over one layout — so they cannot drift apart. */
export function makeAuditChain(sha256) {
  return auditChain({
    sha256,
    payloadOf: payloadOf,
    hashField: "docHash",
  });
}

export default { payloadOf, makeAuditChain };
