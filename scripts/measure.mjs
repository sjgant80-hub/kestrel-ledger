#!/usr/bin/env node
// scripts/measure.mjs — PROOF-OF-PLAY, part two: run the ledger battery and write data/run.json (the MEASURE commit, which
// lands AFTER the seal commit). --verify re-derives on CI and asserts the deterministic results are byte-identical to the
// committed record, with the sealed predictions graded. The deterministic claims (reconstruction, storage, tamper-rejection,
// bounded home) re-derive exactly; the replay time is re-measured and re-checked against its threshold (a wall-clock ms is
// machine-dependent, so it is graded, not frozen).
import { readFileSync, writeFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from 'node:crypto';
import { PREREG, inputHashes } from './seal.mjs';
import {
  measureLedger, genome, reconstruct, verifyReplay, rehydrateReplay, canonicalState,
  syntheticCommands, packAll, pack, fingerprint, replayStore,
  OPCODES, WIRE, PAYLOAD, SIG,
} from '../kestrelledger.mjs';

const at = (f) => new URL('../' + f, import.meta.url);
const SEED = 2026, N = 10000;

// a fixed-seed Ed25519 keypair, so the signed battery re-derives identically on CI.
function keypairFromSeed(seed32) {
  const header = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privateKey = createPrivateKey({ key: Buffer.concat([header, Buffer.from(seed32)]), format: 'der', type: 'pkcs8' });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}
const KEYSEED = new Uint8Array(32); for (let i = 0; i < 32; i++) KEYSEED[i] = (i * 11 + 5) & 0xFF;
const { privateKey, publicKey } = keypairFromSeed(KEYSEED);
const verify = (key, msg, sig) => edVerify(null, Buffer.from(msg), key, Buffer.from(sig));
const SRC = 3;
const signMsg = (payload) => { const m = new Uint8Array(1 + PAYLOAD); m[0] = SRC; m.set(payload, 1); return new Uint8Array(edSign(null, Buffer.from(m), privateKey)); };
const frameOf = (payload, sig) => { const raw = new Uint8Array(WIRE); raw[0] = SRC; raw.set(payload, 1); raw.set(sig, 1 + PAYLOAD); return raw; };
const signFrame = (cmd) => { const p = pack({ ...cmd, source: SRC }); return frameOf(p, signMsg(p)); };
const ctxOf = (seen) => ({ keys: { [SRC]: publicKey }, lattice: { [SRC]: { maxBudget: 2000, resources: 0xFF } }, seen: seen || replayStore(4096), verify });

function battery() {
  // 1) reconstruction + storage (deterministic, from the pure kernel)
  const m = measureLedger(SEED, N);

  // 2) replay speed — time the full inhale fast-forward of 10,000 packets (wall clock; re-measured on verify)
  const payloads = packAll(syntheticCommands(SEED, N));
  const t0 = performance.now();
  const recon = reconstruct(genome(), payloads);
  const replayMs10k = Math.round((performance.now() - t0) * 1000) / 1000;

  // 3) tamper-rejection — a poisoned ledger cannot corrupt the node
  const clean = [
    signFrame({ opcode: OPCODES.WRITE, target: 1, resources: 0, budget: 0 }),
    signFrame({ opcode: OPCODES.GRANT, target: 2, resources: 0b0011, budget: 250 }),
    signFrame({ opcode: OPCODES.COUPLE, target: 3, resources: 0, budget: 0 }),
  ];
  const cleanState = canonicalState(verifyReplay(genome(), clean, ctxOf()).state);
  const forged = frameOf(pack({ opcode: OPCODES.GRANT, source: SRC, target: 7, resources: 0xFF, budget: 1999 }), (() => { const s = new Uint8Array(SIG); for (let i = 0; i < SIG; i++) s[i] = (i * 19 + 7) & 0xFF; return s; })());
  const tampered = clean[1].slice(); tampered[2] = (tampered[2] + 1) & 0xFF; // flip a payload byte after signing
  const overBudget = signFrame({ opcode: OPCODES.GRANT, target: 4, resources: 1, budget: 1999 }); // > lattice cap 2000? no — use a smaller cap ctx
  const overCtx = { keys: { [SRC]: publicKey }, lattice: { [SRC]: { maxBudget: 100, resources: 0xFF } }, seen: replayStore(4096), verify };
  const overRej = verifyReplay(genome(), [overBudget], overCtx).rejected['budget-exceeded'] || 0;
  const replayed = clean[0]; // appears twice → second is a replay
  const poisoned = [clean[0], forged, tampered, clean[1], replayed, clean[2]];
  const pr = verifyReplay(genome(), poisoned, ctxOf());
  const poisonedState = canonicalState(pr.state);

  // 4) bounded-home — rehydrate SENTINEL's window from the ledger so a reboot replay is still caught
  const ledger = []; for (let i = 0; i < 20; i++) ledger.push(signFrame({ opcode: OPCODES.READ, target: i & 0xF, resources: i & 0xFF, budget: i }));
  const recent = ledger[ledger.length - 1];
  const freshMisses = replayStore(4096).has(fingerprint(recent)) === false;
  const rehydratedCatches = rehydrateReplay(ledger, 4096).has(fingerprint(recent)) === true;

  return {
    organ: 'kestrel-ledger', seed: SEED, N,
    reconstruction: { byteIdentical: m.byteIdentical, fold: m.fold, applied: m.applied, canonLen: m.canonLen },
    storage: {
      packed: m.packed,
      ledgerPayloadBytes: m.ledgerPayloadBytes, ledgerSignedBytes: m.ledgerSignedBytes,
      jsonBytes: m.jsonBytes, jsonSignedBytes: m.jsonSignedBytes,
      ratioPayloadVsJson: m.ratioPayloadVsJson, ratioSignedVsJsonSigned: m.ratioSignedVsJsonSigned,
      ledgerPayloadKB: Math.round(m.ledgerPayloadBytes / 102.4) / 10, jsonMB: Math.round(m.jsonBytes / 10485.76) / 100,
    },
    replay: { packets: N, replayMs10k, applied: recon.applied },
    tamper: {
      forged: pr.rejected.forged || 0, tamperedForged: 0, overBudget: overRej, replay: pr.rejected.replay || 0,
      totalRejected: pr.rejectedTotal, appliedValid: pr.applied,
      poisonedEqualsClean: poisonedState === cleanState,
    },
    bounded: { freshMisses, rehydratedCatches },
  };
}

function grade(run) {
  const r = run;
  const P1 = r.reconstruction.byteIdentical === true;
  const P2 = r.storage.ratioPayloadVsJson >= 20;
  const P3 = r.storage.ratioSignedVsJsonSigned >= 2 && r.storage.ratioSignedVsJsonSigned < 10;
  const P4 = r.replay.replayMs10k < 100;
  const P5 = r.tamper.forged >= 1 && r.tamper.overBudget >= 1 && r.tamper.replay >= 1 && r.tamper.poisonedEqualsClean === true;
  const P6 = r.bounded.freshMisses === true && r.bounded.rehydratedCatches === true;
  return {
    'P1-reconstruction': P1, 'P2-storage-coordinate': P2, 'P3-storage-signed-honest': P3,
    'P4-replay-speed': P4, 'P5-tamper-rejected': P5, 'P6-bounded-home': P6,
    passed: [P1, P2, P3, P4, P5, P6].filter(Boolean).length, of: 6,
  };
}

// compare two runs on the DETERMINISTIC fields only (timing is re-measured, so excluded from byte-equality). Pick the
// battery fields explicitly, so a committed run.json's extra keys (verdict, inputs, predictions) are ignored.
function deterministicView(run) {
  const r = run || {};
  return JSON.stringify({
    organ: r.organ, seed: r.seed, N: r.N,
    reconstruction: r.reconstruction, storage: r.storage,
    replay: { packets: r.replay && r.replay.packets, applied: r.replay && r.replay.applied },
    tamper: r.tamper, bounded: r.bounded,
  });
}

const mode = process.argv.includes('--verify') ? 'verify' : process.argv.includes('--run') ? 'run' : null;

if (mode === 'run') {
  const run = battery();
  const verdict = grade(run);
  const out = { ...run, verdict, inputs: inputHashes(), predictions: PREREG.predictions.map((p) => p.id) };
  writeFileSync(at('data/run.json'), JSON.stringify(out, null, 2) + '\n');
  console.log('measured · byte-identical:', run.reconstruction.byteIdentical, '· coordinate', run.storage.ratioPayloadVsJson + '×', '· signed', run.storage.ratioSignedVsJsonSigned + '×', '· replay', run.replay.replayMs10k + 'ms · tamper poisoned==clean', run.tamper.poisonedEqualsClean, '· predictions', verdict.passed + '/' + verdict.of);
} else if (mode === 'verify') {
  let committed;
  try { committed = JSON.parse(readFileSync(at('data/run.json'), 'utf8')); }
  catch { console.error('measure --verify: data/run.json missing — run --run first'); process.exit(1); }
  const fresh = battery();
  if (deterministicView(fresh) !== deterministicView(committed)) {
    console.error('measure --verify: re-derived results differ from the committed record (deterministic fields)');
    console.error('  fresh    ', deterministicView(fresh).slice(0, 400));
    console.error('  committed', deterministicView(committed).slice(0, 400));
    process.exit(1);
  }
  const verdict = grade(fresh);
  if (verdict.passed !== committed.verdict.passed) { console.error('measure --verify: grade changed', verdict, committed.verdict); process.exit(1); }
  if (fresh.replay.replayMs10k >= 100) { console.error('measure --verify: replay too slow on this runner:', fresh.replay.replayMs10k + 'ms'); process.exit(1); }
  console.log('measure --verify: re-derived on this runner, byte-identical on the deterministic fields, replay ' + fresh.replay.replayMs10k + 'ms, predictions ' + verdict.passed + '/' + verdict.of + '.');
} else {
  console.error('usage: node scripts/measure.mjs --run | --verify');
  process.exit(2);
}
