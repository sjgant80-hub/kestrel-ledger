// kestrelledger.mjs — KESTREL-LEDGER. IndexedDB is the physical manifestation of the Shadow Fold (ρ).
//
// When the tab closes, the lit surface (ψ) dissolves and RAM is flushed — the traditional web app dies. KESTREL does not.
// The intelligence has already EXHALED into the local metal: not as a JSON database, but as a BINARY APPEND-ONLY LEDGER of
// raw 6-byte Primorial-Fold packets, each signed with Ed25519. Reopening the tab does not ping a cloud server. wakeKestrelNode
// opens the DB, reads the immutable DNA (genome_core), replays the microscopic binary ledger — 6-byte packets, so 10,000 past
// actions fast-forward in milliseconds — and reconstructs the EXACT state the node was in the moment the window closed. The
// intelligence resumes mid-thought.
//
// REUSE, NOT RE-INVENT: the 6-byte codec, the κ-witness fold, the Ed25519 verify-before-parse gate, and the bounded replay
// store are SENTINEL's live, mutation-gated kernel (sentinel.mjs, vendored verbatim — https://github.com/sjgant80-hub/sentinel).
// The primorial-fold codec is Thomas Frumkin's Konomi architecture / LIGHT (used with permission). This kernel is the LEDGER:
// the node's state machine (applyPrimorialFold), the inhale (reconstruct / verifyReplay), and the durable home for SENTINEL's
// bounded replay window (rehydrateReplay). The IndexedDB IO lives in kestrel-db.mjs; this kernel is PURE so the tests and the
// mutation gate prove the same bytes. Crypto is injected (ctx.verify), never imported here.
//
// Pure and total: every reader returns a value or a no-op on garbage, never throws. An off-κ or forged packet NEVER becomes a
// mutation — a poisoned ledger cannot corrupt the node.

import {
  pack, unpack, foldWitness, check, fingerprint, replayStore, rng,
  WIRE, PAYLOAD, SIG, OPCODES, RESOURCES,
} from './sentinel.mjs';

export {
  pack, unpack, foldWitness, check, fingerprint, replayStore,
  WIRE, PAYLOAD, SIG, OPCODES, RESOURCES,
};

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const int = (v) => (Number.isInteger(v) ? v : 0);

// the three sovereign object stores of the Shadow Fold (DB: KESTREL_OS).
export const DB_NAME = 'KESTREL_OS';
export const DB_VERSION = 1;
export const STORES = Object.freeze({ GENOME: 'genome_core', WALLET: 'crypto_wallet', MUTATIONS: 'state_mutations' });
export const GENOME_KEY = 'v1';

// opcode → name, for the human display boundary and the JSON baseline (never stored; the ledger stores six bytes).
export const OPNAME = Object.freeze({ 0: 'noop', 1: 'read', 2: 'write', 3: 'grant', 4: 'revoke', 5: 'couple', 6: 'heal', 7: 'quarantine' });
export function resourceNames(mask) {
  const m = int(mask), out = [];               // the loop bound (not a mask) is what confines bits to the 8 resources
  for (let i = 0; i < RESOURCES.length; i++) if (m & (1 << i)) out.push(RESOURCES[i]);
  return out;
}

// ── genome_core: the immutable DNA ('v1') ─────────────────────────────────────────────────────────────────────────────
// the Konomi/LIGHT compressed recipe — the shared node index, the structural laws, the base state the ledger folds onto.
// Immutable: it is written once and only read. A fresh baseState every call (no shared refs across nodes).
export function baseState() {
  return { level: 0, xp: 0, reads: 0, writes: 0, heals: 0, couples: 0, grants: {}, budgetSpent: 0, revoked: [], quarantined: [], seq: 0, fold: 0 };
}
export function genome() {
  return { v: GENOME_KEY, node: 'kestrel', law: 'konomi-light-primorial-fold', baseState: baseState() };
}
// a deep, independent copy of a state (the exhale/inhale must never share refs with the live surface).
export function cloneState(s) {
  const x = isObj(s) ? s : baseState();
  return {
    level: int(x.level), xp: int(x.xp), reads: int(x.reads), writes: int(x.writes), heals: int(x.heals), couples: int(x.couples),
    grants: isObj(x.grants) ? { ...x.grants } : {}, budgetSpent: int(x.budgetSpent),
    revoked: Array.isArray(x.revoked) ? x.revoked.slice() : [], quarantined: Array.isArray(x.quarantined) ? x.quarantined.slice() : [],
    seq: int(x.seq), fold: int(x.fold) >>> 0,
  };
}
// the level ladder (egg → bigger node): deterministic, monotonic in xp.
export function levelFor(xp) { return Math.floor(Math.sqrt(Math.max(0, int(xp)))); }

// ── applyPrimorialFold: the state machine (Simon's spec, verbatim name) ────────────────────────────────────────────────
// currentState = applyPrimorialFold(currentState, mutationPacket). mutationPacket is the raw 6-byte Primorial-Fold packet.
// A packet that does not fold to its κ-witness (a tampered payload) is OFF-κ: it returns the state UNCHANGED — the mutation
// never happens, so a codec-level tamper is a no-op, not a corruption. Pure: returns a new state, mutates nothing.
export function applyPrimorialFold(state, mutationPacket) {
  const s = cloneState(state);
  const u = unpack(mutationPacket instanceof Uint8Array ? mutationPacket : new Uint8Array(0));
  if (!u.ok) return s;                                   // off-κ / bad-length — the packet is not a mutation
  const c = u.command;
  const n = s;
  n.seq = s.seq + 1;
  n.fold = (Math.imul(s.fold, 31) + foldWitness(mutationPacket)) >>> 0; // rolling integrity digest over applied packets
  switch (c.opcode) {
    case OPCODES.READ: n.reads = s.reads + 1; break;
    case OPCODES.WRITE: n.writes = s.writes + 1; n.xp = s.xp + 1; break;
    case OPCODES.GRANT: n.grants[c.target] = (int(n.grants[c.target]) | c.resources) & 0xFF; n.budgetSpent = s.budgetSpent + c.budget; n.xp = s.xp + 2; break;
    case OPCODES.REVOKE: n.grants[c.target] = 0; n.revoked = s.revoked.concat(c.target); break;
    case OPCODES.COUPLE: n.couples = s.couples + 1; n.xp = s.xp + 3; break;
    case OPCODES.HEAL: n.heals = s.heals + 1; break;
    case OPCODES.QUARANTINE: n.quarantined = s.quarantined.concat(c.target); break;
    default: break;                                      // NOOP and unknown opcodes advance seq + fold only
  }
  n.level = levelFor(n.xp);
  return n;
}

// ── canonicalState: the bytes the crash-safety claim compares ──────────────────────────────────────────────────────────
// a stable, key-ordered serialization. Two states are byte-identical iff this string is equal. Grant targets are numerically
// sorted so {1,2} and {2,1} serialize the same. This is what the sealed reconstruction claim measures.
export function canonicalState(state) {
  const s = cloneState(state);
  const grants = Object.keys(s.grants).map(Number).filter((k) => !Number.isNaN(k)).sort((a, b) => a - b).map((k) => [k, int(s.grants[k])]);
  return JSON.stringify({
    level: s.level, xp: s.xp, seq: s.seq, fold: s.fold >>> 0,
    reads: s.reads, writes: s.writes, heals: s.heals, couples: s.couples, budgetSpent: s.budgetSpent,
    grants, revoked: s.revoked, quarantined: s.quarantined,
  });
}

// ── the Inhale: germination on boot ────────────────────────────────────────────────────────────────────────────────────
// reconstruct(genome, payloads): fast-forward the raw 6-byte ledger onto the DNA's baseState. No gate (used where the ledger
// is trusted local bytes). Returns the exact state the node was in the moment the window closed, plus how many packets were
// real mutations vs off-κ no-ops.
export function reconstruct(genomeObj, payloads) {
  const g = isObj(genomeObj) ? genomeObj : genome();
  let state = isObj(g.baseState) ? cloneState(g.baseState) : baseState();
  const list = Array.isArray(payloads) ? payloads : [];
  let applied = 0, skipped = 0;
  for (const p of list) {
    const before = state.seq;
    state = applyPrimorialFold(state, p);
    if (state.seq > before) applied += 1; else skipped += 1;
  }
  return { state, applied, skipped, total: list.length };
}

// verifyReplay(genome, frames, ctx): the GATED inhale. Each frame is a 71-byte signed wire buffer. SENTINEL's check verifies
// the Ed25519 signature BEFORE the six bytes are parsed, within budget, at κ, unseen. Only a verified frame becomes a mutation,
// so a forged, tampered, over-budget or replayed frame in the ledger NEVER corrupts the reconstructed node. ctx carries
// { keys, lattice, seen, verify } exactly as SENTINEL's gate expects; seen (a replayStore) makes in-ledger replays catchable.
export function verifyReplay(genomeObj, frames, ctx) {
  const g = isObj(genomeObj) ? genomeObj : genome();
  let state = isObj(g.baseState) ? cloneState(g.baseState) : baseState();
  const list = Array.isArray(frames) ? frames : [];
  let applied = 0;
  const rejected = {};
  for (const raw of list) {
    const v = check(raw, ctx);
    if (v.ok) { state = applyPrimorialFold(state, raw.subarray(1, 1 + PAYLOAD)); applied += 1; }
    else { rejected[v.reason] = (int(rejected[v.reason]) || 0) + 1; }
  }
  const rejectedTotal = Object.values(rejected).reduce((a, b) => a + b, 0);
  return { state, applied, rejected, rejectedTotal };
}

// ── the durable home for SENTINEL's bounded replay window (closes SENTINEL v2 flag #1) ─────────────────────────────────
// SENTINEL's replayStore is a sliding window held in RAM: after a reboot it is empty, so a replay of a recent packet would
// pass (the window was forgotten). The ledger IS that window's durable home. rehydrateReplay rebuilds the bounded store from
// the ledger on inhale: because the store is FIFO-capped, feeding it every nonce leaves exactly the last `cap` nonces — the
// window the node held the instant it closed — so an in-window replay is still caught after a power death.
export function rehydrateReplay(frames, cap) {
  const store = replayStore(cap);
  const list = Array.isArray(frames) ? frames : [];
  for (const raw of list) { const n = fingerprint(raw); if (n) store.add(n); }
  return store;
}

// ── deterministic measurement fixtures (shared by scripts/measure.mjs and the page's self-check) ───────────────────────
// a seeded stream of commands, so the whole measurement re-derives byte-identically on CI.
export function syntheticCommands(seed, n) {
  const r = rng(int(seed) >>> 0);
  const ops = [OPCODES.NOOP, OPCODES.READ, OPCODES.WRITE, OPCODES.GRANT, OPCODES.REVOKE, OPCODES.COUPLE, OPCODES.HEAL, OPCODES.QUARANTINE];
  const count = Number.isInteger(n) ? Math.max(0, n) : 0;
  const out = [];
  for (let i = 0; i < count; i++) {
    out.push({
      opcode: ops[(r() * ops.length) | 0],
      source: (r() * 16) | 0,
      target: (r() * 16) | 0,
      resources: (r() * 256) | 0,
      budget: (r() * 1000) | 0,                         // under the lattice maxBudget so valid packets pass the gate
    });
  }
  return out;
}
export function packAll(cmds) { return (Array.isArray(cmds) ? cmds : []).map(pack).filter((p) => p instanceof Uint8Array); }

// the self-describing JSON a traditional IndexedDB app would append per state transition (the legacy-debt baseline). Fixed
// sample ts/field-order so the byte count is reproducible. withSig adds the base64 Ed25519 field the honest baseline carries.
const utf8len = (s) => (typeof s === 'string' ? new TextEncoder().encode(s).length : 0);
export function mutationJson(cmd, i) {
  if (!isObj(cmd)) return '';
  return JSON.stringify({
    id: int(i), type: OPNAME[cmd.opcode] || ('op_' + int(cmd.opcode)),
    source: 'node-' + String(int(cmd.source) & 0xF).padStart(2, '0'),
    target: 'node-' + String(int(cmd.target) & 0xF).padStart(2, '0'),
    resources: resourceNames(cmd.resources), budget: int(cmd.budget),
    ts: '2026-10-05T12:00:00.000Z',
  });
}
const B64_SIG = 88; // 64-byte Ed25519 signature, base64 = 88 chars (what a signed JSON row must also carry)
export function withSig(json) { return typeof json === 'string' && json.length ? json.slice(0, -1) + ',"sig":"' + 'A'.repeat(B64_SIG) + '"}' : json; }
const round2 = (x) => Math.round(x * 100) / 100;

// measureLedger(seed, N): the deterministic core of the sealed claims — reconstruction (byte-identical) and storage ratio.
// Timing and the signed tamper/replay battery live in scripts/measure.mjs (they need node:crypto); this stays pure.
export function measureLedger(seed, N) {
  const cmds = syntheticCommands(seed, N);
  const payloads = packAll(cmds);
  const g = genome();
  // the LIVE surface: fold each mutation on as it happens (the exhale path, state held in RAM)
  let live = cloneState(g.baseState);
  for (const p of payloads) live = applyPrimorialFold(live, p);
  // ABRUPT CLOSE: the live state is dropped. Only the ledger of packets survived. INHALE: reconstruct from it alone.
  const recon = reconstruct(g, payloads);
  const liveCanon = canonicalState(live), reconCanon = canonicalState(recon.state);
  const byteIdentical = liveCanon === reconCanon;
  // storage: the raw ledger vs the same mutations as traditional JSON objects
  const ledgerPayloadBytes = payloads.length * PAYLOAD;   // 6 bytes/mutation (coordinate ledger, signature amortised)
  const ledgerSignedBytes = payloads.length * WIRE;       // 71 bytes/mutation (6 packet + 1 id + 64 sig, stored per spec)
  let jsonBytes = 0, jsonSignedBytes = 0;
  for (const [i, c] of cmds.entries()) { const j = mutationJson(c, i); jsonBytes += utf8len(j); jsonSignedBytes += utf8len(withSig(j)); }
  return {
    seed: int(seed), N: int(N), packed: payloads.length,
    byteIdentical, fold: recon.state.fold >>> 0, applied: recon.applied, skipped: recon.skipped,
    canonLen: reconCanon.length,
    ledgerPayloadBytes, ledgerSignedBytes, jsonBytes, jsonSignedBytes,
    ratioPayloadVsJson: round2(jsonBytes / ledgerPayloadBytes),
    ratioSignedVsJsonSigned: round2(jsonSignedBytes / ledgerSignedBytes),
  };
}

export default {
  DB_NAME, DB_VERSION, STORES, GENOME_KEY, OPNAME, resourceNames,
  baseState, genome, cloneState, levelFor, applyPrimorialFold, canonicalState,
  reconstruct, verifyReplay, rehydrateReplay,
  syntheticCommands, packAll, mutationJson, withSig, measureLedger,
  pack, unpack, foldWitness, check, fingerprint, replayStore, WIRE, PAYLOAD, SIG, OPCODES, RESOURCES,
};
