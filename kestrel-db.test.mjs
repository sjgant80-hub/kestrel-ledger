// kestrel-db.test.mjs — the IndexedDB round-trip, proven. Exhale signed 6-byte frames into state_mutations, drop the in-RAM
// surface entirely (an abrupt close), then wakeKestrelNode from the DB alone and confirm the reconstructed state is
// byte-identical to the pre-close surface. The same assertions a real browser IndexedDB satisfies — here against a tiny
// in-memory mock so CI stays dependency-free.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from 'node:crypto';
import { createMockIndexedDB } from './idb-mock.mjs';
import {
  openKestrelDB, putGenome, getGenome, putWallet, getWallet, exhale, exhaleAll, getLedger, ledgerCount, wakeKestrelNode,
} from './kestrel-db.mjs';
import {
  genome, baseState, cloneState, applyPrimorialFold, canonicalState, pack, replayStore,
  OPCODES, WIRE, PAYLOAD, SIG,
} from './kestrelledger.mjs';

function keypairFromSeed(seed32) {
  const header = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privateKey = createPrivateKey({ key: Buffer.concat([header, Buffer.from(seed32)]), format: 'der', type: 'pkcs8' });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}
const SEED = new Uint8Array(32); for (let i = 0; i < 32; i++) SEED[i] = (i * 5 + 1) & 0xFF;
const { privateKey, publicKey } = keypairFromSeed(SEED);
const verify = (key, msg, sig) => edVerify(null, Buffer.from(msg), key, Buffer.from(sig));
const SRC = 4;
const signMsg = (payload) => { const m = new Uint8Array(1 + PAYLOAD); m[0] = SRC; m.set(payload, 1); return new Uint8Array(edSign(null, Buffer.from(m), privateKey)); };
const frameOf = (payload, sig) => { const raw = new Uint8Array(WIRE); raw[0] = SRC; raw.set(payload, 1); raw.set(sig, 1 + PAYLOAD); return raw; };
const signFrame = (cmd) => { const p = pack({ ...cmd, source: SRC }); return frameOf(p, signMsg(p)); };
const ctxOf = (seen) => ({ keys: { [SRC]: publicKey }, lattice: { [SRC]: { maxBudget: 10000, resources: 0xFF } }, seen: seen || replayStore(4096), verify });

test('open creates the three sovereign stores', async () => {
  const idb = createMockIndexedDB();
  const db = await openKestrelDB(idb, 'KESTREL_OS');
  assert.ok(db.objectStoreNames.contains('genome_core'));
  assert.ok(db.objectStoreNames.contains('crypto_wallet'));
  assert.ok(db.objectStoreNames.contains('state_mutations'));
});

test('genome_core and crypto_wallet round-trip', async () => {
  const idb = createMockIndexedDB();
  const db = await openKestrelDB(idb, 'G');
  await putGenome(db, genome());
  assert.equal((await getGenome(db)).v, 'v1');
  await putWallet(db, { source: SRC, budget: 500, pub: 'raw-bytes' });
  assert.equal((await getWallet(db)).budget, 500);
});

test('EXHALE → abrupt close → INHALE reconstructs byte-identically', async () => {
  const idb = createMockIndexedDB();
  let db = await openKestrelDB(idb, 'KESTREL_OS');
  await putGenome(db, genome());

  // the live surface + the exhale, in lock-step: fold each mutation, then fire the signed frame into the ledger
  let live = cloneState(genome().baseState);
  const cmds = [
    { opcode: OPCODES.WRITE, target: 1, resources: 0, budget: 0 },
    { opcode: OPCODES.GRANT, target: 2, resources: 0b0011, budget: 250 },
    { opcode: OPCODES.COUPLE, target: 3, resources: 0, budget: 0 },
    { opcode: OPCODES.HEAL, target: 1, resources: 0, budget: 0 },
    { opcode: OPCODES.GRANT, target: 2, resources: 0b0100, budget: 90 },
  ];
  for (const c of cmds) {
    const f = signFrame(c);
    live = applyPrimorialFold(live, f.subarray(1, 1 + PAYLOAD)); // repaint the surface
    await exhale(db, f);                                         // ...but the coordinate is committed first
  }
  const preClose = canonicalState(live);
  assert.equal(await ledgerCount(db), 5);

  // ABRUPT CLOSE: the tab dies. `live` and the db handle are gone. Only the shadow fold on disk survived.
  db.close(); live = null;

  // INHALE on reopen — no cloud ping, just the DB. Gated: every frame re-verified on the way in.
  db = await openKestrelDB(idb, 'KESTREL_OS');
  const woke = await wakeKestrelNode(db, ctxOf());
  assert.equal(woke.frames, 5);
  assert.equal(woke.applied, 5);
  assert.equal(woke.rejectedTotal, 0);
  assert.equal(canonicalState(woke.state), preClose);  // resumed in the exact state it closed in
});

test('a crash mid-burst loses nothing committed before the crash', async () => {
  const idb = createMockIndexedDB();
  let db = await openKestrelDB(idb, 'CRASH');
  await putGenome(db, genome());
  const frames = [];
  for (let i = 0; i < 20; i++) frames.push(signFrame({ opcode: OPCODES.WRITE, target: i & 0xF, resources: 0, budget: 0 }));
  // commit the first 13, then "crash" before the rest and before any aggregate state was ever written
  for (let i = 0; i < 13; i++) await exhale(db, frames[i]);
  db.close();
  db = await openKestrelDB(idb, 'CRASH');
  const woke = await wakeKestrelNode(db, ctxOf());
  assert.equal(woke.applied, 13);           // exactly what was committed, not a byte less or more
  assert.equal(woke.state.writes, 13);
});

test('INHALE drops a forged frame sitting in the ledger — the node wakes uncorrupted', async () => {
  const idb = createMockIndexedDB();
  let db = await openKestrelDB(idb, 'POISON');
  await putGenome(db, genome());
  const good1 = signFrame({ opcode: OPCODES.WRITE, target: 1, resources: 0, budget: 0 });
  const good2 = signFrame({ opcode: OPCODES.GRANT, target: 2, resources: 1, budget: 100 });
  const forgedPayload = pack({ opcode: OPCODES.GRANT, source: SRC, target: 7, resources: 0xFF, budget: 9999 });
  const forged = frameOf(forgedPayload, (() => { const s = new Uint8Array(SIG); for (let i = 0; i < SIG; i++) s[i] = (i * 17 + 2) & 0xFF; return s; })());
  await exhaleAll(db, [good1, forged, good2]);
  db.close();

  db = await openKestrelDB(idb, 'POISON');
  const woke = await wakeKestrelNode(db, ctxOf());
  assert.equal(woke.applied, 2);
  assert.ok(woke.rejected.forged >= 1);
  // the forged GRANT to node 7 never happened
  assert.equal(woke.state.grants[7], undefined);
  assert.equal(woke.state.budgetSpent, 100);
});

test('bulk exhale stores raw binary frames (ArrayBuffers), not JSON objects', async () => {
  const idb = createMockIndexedDB();
  const db = await openKestrelDB(idb, 'BIN');
  const frames = [signFrame({ opcode: OPCODES.READ, target: 1, resources: 0, budget: 0 })];
  await exhaleAll(db, frames);
  const back = await getLedger(db);
  assert.equal(back.length, 1);
  assert.ok(back[0] instanceof Uint8Array);
  assert.equal(back[0].length, WIRE);
  assert.deepEqual(Array.from(back[0]), Array.from(frames[0]));
});

test('untrusted inhale (no verify) still reconstructs from the raw ledger', async () => {
  const idb = createMockIndexedDB();
  let db = await openKestrelDB(idb, 'TRUST');
  await putGenome(db, genome());
  await exhaleAll(db, [signFrame({ opcode: OPCODES.WRITE, target: 1, resources: 0, budget: 0 }), signFrame({ opcode: OPCODES.WRITE, target: 2, resources: 0, budget: 0 })]);
  db.close();
  db = await openKestrelDB(idb, 'TRUST');
  const woke = await wakeKestrelNode(db); // no ctx → trusted local replay
  assert.equal(woke.gated, false);
  assert.equal(woke.state.writes, 2);
});
