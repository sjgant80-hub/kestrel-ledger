// kestrelledger.test.mjs — the proof the mutation gate runs against. Real Ed25519 (node:crypto) drives SENTINEL's
// verify-before-parse gate on the inhale; the ledger state machine is checked exact, total (garbage never throws), and
// crash-identical (reconstruct == live apply, byte-for-byte).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from 'node:crypto';
import {
  baseState, genome, cloneState, levelFor, applyPrimorialFold, canonicalState,
  reconstruct, verifyReplay, rehydrateReplay, syntheticCommands, packAll, measureLedger,
  mutationJson, withSig, resourceNames,
  pack, unpack, foldWitness, fingerprint, replayStore, OPCODES, RESOURCES, WIRE, PAYLOAD, SIG,
} from './kestrelledger.mjs';

// ── a deterministic Ed25519 keypair from a fixed 32-byte seed (reproducible on CI) ─────────────────────────────────────
function keypairFromSeed(seed32) {
  const header = Buffer.from('302e020100300506032b657004220420', 'hex'); // PKCS8 Ed25519 prefix
  const privateKey = createPrivateKey({ key: Buffer.concat([header, Buffer.from(seed32)]), format: 'der', type: 'pkcs8' });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}
const SEED = new Uint8Array(32); for (let i = 0; i < 32; i++) SEED[i] = (i * 7 + 3) & 0xFF;
const { privateKey, publicKey } = keypairFromSeed(SEED);
const verify = (key, msg, sig) => edVerify(null, Buffer.from(msg), key, Buffer.from(sig));
const signMsg = (sourceId, payload) => { const m = new Uint8Array(1 + PAYLOAD); m[0] = sourceId & 0xFF; m.set(payload, 1); return new Uint8Array(edSign(null, Buffer.from(m), privateKey)); };
const frameOf = (sourceId, payload, sig) => { const raw = new Uint8Array(WIRE); raw[0] = sourceId & 0xFF; raw.set(payload, 1); raw.set(sig, 1 + PAYLOAD); return raw; };
const signFrame = (sourceId, cmd) => { const p = pack({ ...cmd, source: sourceId & 0xF }); return frameOf(sourceId, p, signMsg(sourceId, p)); };
const SRC = 9;
const ctxOf = (maxBudget, resources, seen) => ({ keys: { [SRC]: publicKey }, lattice: { [SRC]: { maxBudget, resources } }, seen: seen || replayStore(4096), verify });

// ── genome / baseState ─────────────────────────────────────────────────────────────────────────────────────────────────
test('genome carries the v1 DNA and a fresh, independent baseState', () => {
  const g = genome();
  assert.equal(g.v, 'v1');
  const a = baseState(), b = baseState();
  a.reads = 5; assert.equal(b.reads, 0); // no shared refs
  assert.deepEqual(g.baseState, baseState());
});

test('cloneState is a deep, independent copy', () => {
  const s = baseState(); s.grants = { 2: 3 }; s.revoked = [1];
  const c = cloneState(s); c.grants[2] = 99; c.revoked.push(7);
  assert.equal(s.grants[2], 3); assert.equal(s.revoked.length, 1);
});

test('levelFor is monotonic and floor(sqrt(xp))', () => {
  assert.equal(levelFor(0), 0); assert.equal(levelFor(1), 1); assert.equal(levelFor(3), 1); assert.equal(levelFor(4), 2); assert.equal(levelFor(9), 3);
  assert.ok(levelFor(100) >= levelFor(99));
});

// ── applyPrimorialFold: each opcode mutates exactly its field ───────────────────────────────────────────────────────────
test('a valid packet advances seq and folds its witness', () => {
  const p = pack({ opcode: OPCODES.READ, source: 1, target: 2, resources: 0, budget: 0 });
  const s = applyPrimorialFold(baseState(), p);
  assert.equal(s.seq, 1);
  assert.notEqual(s.fold, 0);
});

test('OFF-κ packet is a no-op — a tampered payload never becomes a mutation', () => {
  const p = pack({ opcode: OPCODES.WRITE, source: 1, target: 2, resources: 0, budget: 10 });
  const tampered = p.slice(); tampered[0] = (tampered[0] + 1) & 0xFF; // break the fold without fixing byte 5
  assert.equal(unpack(tampered).ok, false);
  const before = applyPrimorialFold(baseState(), p);           // valid applies
  const after = applyPrimorialFold(before, tampered);          // tampered must NOT change anything
  assert.equal(canonicalState(after), canonicalState(before));
  assert.equal(after.seq, before.seq);
});

test('each opcode mutates exactly its own field', () => {
  const ap = (op, extra = {}) => applyPrimorialFold(baseState(), pack({ opcode: op, source: 1, target: 2, resources: 0, budget: 0, ...extra }));
  assert.equal(ap(OPCODES.READ).reads, 1);
  const w = ap(OPCODES.WRITE); assert.equal(w.writes, 1); assert.equal(w.xp, 1);
  const g = ap(OPCODES.GRANT, { resources: 5, budget: 100 }); assert.equal(g.grants[2], 5); assert.equal(g.budgetSpent, 100); assert.equal(g.xp, 2);
  const r = applyPrimorialFold(g, pack({ opcode: OPCODES.REVOKE, source: 1, target: 2, resources: 0, budget: 0 })); assert.equal(r.grants[2], 0); assert.deepEqual(r.revoked, [2]);
  const c = ap(OPCODES.COUPLE); assert.equal(c.couples, 1); assert.equal(c.xp, 3);
  assert.equal(ap(OPCODES.HEAL).heals, 1);
  assert.deepEqual(ap(OPCODES.QUARANTINE).quarantined, [2]);
  const noop = ap(OPCODES.NOOP); assert.equal(noop.seq, 1); assert.equal(noop.reads, 0); assert.equal(noop.writes, 0); // NOOP advances seq only
});

test('GRANT ORs resources and accumulates budget across packets', () => {
  let s = baseState();
  s = applyPrimorialFold(s, pack({ opcode: OPCODES.GRANT, source: 1, target: 3, resources: 0b0001, budget: 50 }));
  s = applyPrimorialFold(s, pack({ opcode: OPCODES.GRANT, source: 1, target: 3, resources: 0b0100, budget: 70 }));
  assert.equal(s.grants[3], 0b0101);
  assert.equal(s.budgetSpent, 120);
});

test('level climbs with xp', () => {
  let s = baseState();
  for (let i = 0; i < 5; i++) s = applyPrimorialFold(s, pack({ opcode: OPCODES.COUPLE, source: 1, target: 1, resources: 0, budget: 0 }));
  assert.equal(s.xp, 15); assert.equal(s.level, levelFor(15)); assert.ok(s.level > 0);
});

test('applyPrimorialFold is total — garbage never throws', () => {
  assert.doesNotThrow(() => applyPrimorialFold(null, null));
  assert.doesNotThrow(() => applyPrimorialFold(undefined, new Uint8Array(3)));
  assert.doesNotThrow(() => applyPrimorialFold({}, 'nope'));
  assert.equal(applyPrimorialFold(null, new Uint8Array(0)).seq, 0);
});

// ── canonicalState ─────────────────────────────────────────────────────────────────────────────────────────────────────
test('canonicalState is order-independent for grants and equal for equal states', () => {
  const a = baseState(); a.grants = { 2: 1, 5: 2 };
  const b = baseState(); b.grants = { 5: 2, 2: 1 };
  assert.equal(canonicalState(a), canonicalState(b));
  const c = baseState(); c.grants = { 2: 1, 5: 3 };
  assert.notEqual(canonicalState(a), canonicalState(c));
});

test('fold distinguishes two ledgers that differ in any packet', () => {
  const a = reconstruct(genome(), packAll(syntheticCommands(1, 50))).state;
  const b = reconstruct(genome(), packAll(syntheticCommands(2, 50))).state;
  assert.notEqual(a.fold, b.fold);
  assert.notEqual(canonicalState(a), canonicalState(b));
});

// ── THE HEADLINE: byte-identical reconstruction after an abrupt close ───────────────────────────────────────────────────
test('reconstruct == live apply, byte-for-byte (crash-safety), N=2000', () => {
  const payloads = packAll(syntheticCommands(1234, 2000));
  let live = cloneState(genome().baseState);
  for (const p of payloads) live = applyPrimorialFold(live, p);     // the surface, folded as actions happen
  const recon = reconstruct(genome(), payloads).state;             // RAM dropped, rebuilt from the ledger alone
  assert.equal(canonicalState(recon), canonicalState(live));
});

test('reconstruct counts real mutations vs off-κ no-ops', () => {
  const payloads = packAll(syntheticCommands(7, 100));
  const r = reconstruct(genome(), payloads);
  assert.equal(r.total, 100);
  assert.equal(r.applied + r.skipped, 100);
  assert.equal(r.applied, 100); // every packed packet is valid, so all apply
});

// ── THE GATED INHALE: a poisoned ledger cannot corrupt the node ─────────────────────────────────────────────────────────
test('verifyReplay applies valid signed frames and rejects a forged one — state uncorrupted', () => {
  const clean = [
    signFrame(SRC, { opcode: OPCODES.WRITE, target: 1, resources: 0, budget: 0 }),
    signFrame(SRC, { opcode: OPCODES.GRANT, target: 2, resources: 1, budget: 100 }),
  ];
  const cleanState = verifyReplay(genome(), clean, ctxOf(1000, 0xFF)).state;

  // inject a FORGED frame (random signature that will not map) into the ledger
  const payload = pack({ opcode: OPCODES.GRANT, source: SRC, target: 3, resources: 0xFF, budget: 999 });
  const forged = frameOf(SRC, payload, (() => { const s = new Uint8Array(SIG); for (let i = 0; i < SIG; i++) s[i] = (i * 13 + 1) & 0xFF; return s; })());
  const poisoned = [clean[0], forged, clean[1]];
  const r = verifyReplay(genome(), poisoned, ctxOf(1000, 0xFF));
  assert.equal(r.applied, 2);                 // only the two valid frames applied
  assert.ok(r.rejected.forged >= 1);          // the forgery was rejected
  assert.equal(canonicalState(r.state), canonicalState(cleanState)); // the poison changed nothing
});

test('verifyReplay rejects tampered-payload, over-budget, and replayed frames', () => {
  const good = signFrame(SRC, { opcode: OPCODES.GRANT, target: 2, resources: 1, budget: 100 });
  // tamper a payload byte after signing → signature no longer maps → 'forged' before parse
  const tampered = good.slice(); tampered[1] = (tampered[1] + 1) & 0xFF;
  assert.equal(verifyReplay(genome(), [tampered], ctxOf(1000, 0xFF)).rejected.forged, 1);
  // over-budget: a validly-signed frame whose budget exceeds the lattice
  const big = signFrame(SRC, { opcode: OPCODES.GRANT, target: 2, resources: 1, budget: 900 });
  assert.equal(verifyReplay(genome(), [big], ctxOf(100, 0xFF)).rejected['budget-exceeded'], 1);
  // replay: the same signed frame twice, one seen store
  const seen = replayStore(4096);
  const r = verifyReplay(genome(), [good, good], ctxOf(1000, 0xFF, seen));
  assert.equal(r.applied, 1); assert.equal(r.rejected.replay, 1);
});

// ── THE DURABLE BOUNDED-REPLAY HOME (closes SENTINEL v2 flag #1) ────────────────────────────────────────────────────────
test('rehydrateReplay rebuilds the bounded window from the ledger so an in-window replay survives a reboot', () => {
  const frames = []; for (let i = 0; i < 10; i++) frames.push(signFrame(SRC, { opcode: OPCODES.READ, target: i & 0xF, resources: i & 0xFF, budget: i }));
  const recent = frames[frames.length - 1];
  // after a reboot a FRESH store is empty — the replay would pass (the hole SENTINEL flagged)
  assert.equal(replayStore(4096).has(fingerprint(recent)), false);
  // rehydrated from the ledger, the window is restored — the replay is caught
  const store = rehydrateReplay(frames, 4096);
  assert.equal(store.has(fingerprint(recent)), true);
});

test('rehydrateReplay respects the cap (sliding window, oldest-first)', () => {
  const frames = []; for (let i = 0; i < 50; i++) frames.push(signFrame(SRC, { opcode: OPCODES.READ, target: i & 0xF, resources: i & 0xFF, budget: i }));
  const store = rehydrateReplay(frames, 10);
  assert.equal(store.size, 10);
  assert.equal(store.has(fingerprint(frames[49])), true);   // newest kept
  assert.equal(store.has(fingerprint(frames[0])), false);   // oldest evicted
});

// ── measurement fixtures are deterministic ─────────────────────────────────────────────────────────────────────────────
test('measureLedger is deterministic, reconstructs byte-identically, and beats JSON', () => {
  const a = measureLedger(42, 1000), b = measureLedger(42, 1000);
  assert.deepEqual(a, b);                        // same seed → identical record (CI can re-derive)
  assert.equal(a.byteIdentical, true);
  assert.ok(a.ratioPayloadVsJson > 10);         // 6-byte coordinate ledger vs traditional JSON
  assert.ok(a.ratioSignedVsJsonSigned > 1);     // even the fully-signed durable ledger beats signed JSON
  assert.equal(a.ledgerPayloadBytes, a.packed * PAYLOAD);
  assert.equal(a.ledgerSignedBytes, a.packed * WIRE);
});

test('mutationJson / withSig produce the JSON baselines', () => {
  const j = mutationJson({ opcode: OPCODES.GRANT, source: 1, target: 2, resources: 5, budget: 100 }, 0);
  assert.ok(j.includes('"type":"grant"'));
  assert.ok(withSig(j).includes('"sig":"'));
  assert.ok(withSig(j).length > j.length);
});

test('resourceNames maps the bitmask to names — the loop bound confines to the 8 resources', () => {
  assert.deepEqual(resourceNames(0), []);
  assert.deepEqual(resourceNames(1), [RESOURCES[0]]);
  assert.equal(resourceNames(0xFF).length, RESOURCES.length);
  assert.deepEqual(resourceNames(256), []);                 // bit 8 has no resource — the loop bound (not a mask) drops it
  assert.equal(resourceNames(0x1FF).length, RESOURCES.length); // bits 0-7 set + bit 8 ignored
});

// ── mutation-killers: the branches the gate found uncovered ──────────────────────────────────────────────────────────────
test('reconstruct counts off-κ packets as skipped, not applied (the skip branch)', () => {
  const valid = packAll(syntheticCommands(3, 6));
  const bad = valid[0].slice(); bad[0] = (bad[0] + 1) & 0xFF; // break the fold → off-κ → a no-op on replay
  assert.equal(unpack(bad).ok, false);
  const ledger = [valid[0], bad, valid[1], bad, valid[2]];   // 3 valid, 2 off-κ
  const r = reconstruct(genome(), ledger);
  assert.equal(r.total, 5);
  assert.equal(r.applied, 3);
  assert.equal(r.skipped, 2);
});

test('withSig leaves an empty string empty (only a non-empty JSON row gets a sig field)', () => {
  assert.equal(withSig(''), '');
  assert.equal(withSig('{"a":1}').endsWith('"}'), true);
  assert.ok(withSig('{"a":1}').includes(',"sig":"'));
});

test('verifyReplay tallies repeated rejection reasons (two forgeries count as two)', () => {
  const mk = (salt) => { const p = pack({ opcode: OPCODES.GRANT, source: SRC, target: 3, resources: 1, budget: 10 }); const s = new Uint8Array(SIG); for (let i = 0; i < SIG; i++) s[i] = (i + salt) & 0xFF; return frameOf(SRC, p, s); };
  const r = verifyReplay(genome(), [mk(1), mk(99)], ctxOf(1000, 0xFF));
  assert.equal(r.applied, 0);
  assert.equal(r.rejected.forged, 2);   // the tally must accumulate, not stick at 1
});

test('syntheticCommands honours the count and rejects non-positive / non-integer n', () => {
  assert.equal(syntheticCommands(1, 5).length, 5);
  assert.equal(syntheticCommands(1, 0).length, 0);
  assert.equal(syntheticCommands(1, -2).length, 0);
  assert.equal(syntheticCommands(1, 3.5).length, 0);
});
