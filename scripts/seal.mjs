#!/usr/bin/env node
// scripts/seal.mjs — PROOF-OF-PLAY, part one: pin the predictions AND the sha256 of every input BEFORE the measurement,
// as its OWN pushed commit. The ledger claims (byte-identical reconstruction, storage ratio, replay ms, tamper-rejection)
// are a CLAIM until the record proves the predictions predated the result. So the seal is a separate commit: data/prereg.json
// carries the predictions and the hashes of the codec (sentinel.mjs), the ledger kernel (kestrelledger.mjs) and the
// measurement method (scripts/measure.mjs). CI goes green on THIS commit (seal --check) BEFORE run.json lands. Then
// measure.mjs --verify re-derives the deterministic results on GitHub's runner from exactly these inputs.
//
//   node scripts/seal.mjs --seal    write data/prereg.json (predictions + input hashes)
//   node scripts/seal.mjs --check   verify the inputs still hash to what the seal pinned (exit 1 on drift)
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const at = (f) => new URL('../' + f, import.meta.url);
const bytes = (f) => readFileSync(at(f));
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

// everything that determines the measured results: the codec, the ledger state machine + fixtures, the measurement battery.
export const INPUTS = ['sentinel.mjs', 'kestrelledger.mjs', 'scripts/measure.mjs'];

export const PREREG = {
  organ: 'kestrel-ledger',
  what: 'IndexedDB as the Shadow Fold (rho): a binary append-only ledger of signed 6-byte Primorial-Fold packets. Exhale on every state transition; inhale on boot by replaying the ledger onto the immutable DNA. Predictions + input hashes committed as their OWN commit BEFORE the measurement commit (seal-before-measure, provable on the public record); re-derived on CI from the sealed inputs.',
  sealed: '2026-10-05',
  codec: 'SENTINEL (vendored, mutation-gated) — Thomas Frumkin\'s Konomi / LIGHT primorial-fold codec, used with permission',
  predictions: [
    { id: 'P1-reconstruction', claim: 'Exhaling N=10,000 state mutations as 6-byte packets, then dropping the in-RAM surface (an abrupt close) and inhaling by replaying the ledger onto the DNA, reconstructs a state that is BYTE-IDENTICAL to the pre-close surface (canonicalState equal). This is the headline: the node resumes in the exact state it closed in.', pass_if: 'measureLedger(seed,10000).byteIdentical === true' },
    { id: 'P2-storage-coordinate', claim: 'The raw 6-byte-packet ledger beats the same mutations stored as traditional JSON objects by at least 20x (kilobytes, not megabytes). We predict ~20-25x, not a bigger headline, because our canonical mutation JSON is lean.', pass_if: 'ratioPayloadVsJson >= 20' },
    { id: 'P3-storage-signed-honest', claim: 'Stored fully signed per the spec (6-byte packet + 64-byte Ed25519 signature = 71 bytes/row), the durable ledger still beats signed JSON, but only by ~2-4x: the 64-byte signature is irreducible and dominates per row. This is the honest limit — the big ratio is the coordinate, not the signature.', pass_if: 'ratioSignedVsJsonSigned >= 2 && ratioSignedVsJsonSigned < 10' },
    { id: 'P4-replay-speed', claim: 'Replaying 10,000 6-byte packets (the full inhale fast-forward) reconstructs the node in milliseconds — under 100ms on a CI runner.', pass_if: 'replayMs10k < 100' },
    { id: 'P5-tamper-rejected', claim: 'A forged packet (random signature), a tampered-payload packet, an over-budget packet and a replayed packet, all sitting in the ledger, are REJECTED on inhale by SENTINEL\'s verify-before-parse Ed25519 gate — so a poisoned ledger reconstructs to the SAME state as the clean ledger. A corrupt shadow fold cannot corrupt the node.', pass_if: 'forged+tampered+overBudget+replay all rejected AND poisonedState === cleanState' },
    { id: 'P6-bounded-home', claim: 'SENTINEL\'s bounded replay window is RAM-only, so after a reboot it is empty and a recent replay would pass (SENTINEL v2 flag #1). Rehydrating the window from the ledger on inhale restores it: an in-window replay that a fresh store would miss is caught. The ledger is the durable home for the bounded store.', pass_if: 'freshStore misses recent replay AND rehydrated store catches it' },
  ],
};

export function inputHashes() {
  const out = {};
  for (const f of INPUTS) out[f] = sha256(bytes(f));
  return out;
}

const isMain = import.meta.url === pathToFileURL(process.argv[1] || '').href;
const mode = isMain ? (process.argv.includes('--check') ? 'check' : process.argv.includes('--seal') ? 'seal' : null) : 'skip';

if (mode === 'skip') {
  // imported as a library
} else if (mode === 'seal') {
  const prereg = { ...PREREG, inputs: inputHashes() };
  writeFileSync(at('data/prereg.json'), JSON.stringify(prereg, null, 2) + '\n');
  console.log('sealed · inputs pinned:');
  for (const [f, h] of Object.entries(prereg.inputs)) console.log('  ' + f + '  ' + h);
} else if (mode === 'check') {
  let prereg;
  try { prereg = JSON.parse(readFileSync(at('data/prereg.json'), 'utf8')); }
  catch { console.error('seal --check: data/prereg.json missing or unreadable — not sealed'); process.exit(1); }
  if (!prereg.inputs) { console.error('seal --check: prereg has no input hashes — re-seal'); process.exit(1); }
  const now = inputHashes();
  let drift = 0;
  for (const f of INPUTS) {
    if (prereg.inputs[f] !== now[f]) { console.error('DRIFT  ' + f + '\n  sealed ' + prereg.inputs[f] + '\n  now    ' + now[f]); drift++; }
    else console.log('in step  ' + f);
  }
  if (drift) { console.error('seal --check: ' + drift + ' input(s) changed since the seal'); process.exit(1); }
  console.log('seal --check: all inputs match the sealed hashes');
} else {
  console.error('usage: node scripts/seal.mjs --seal | --check');
  process.exit(2);
}
