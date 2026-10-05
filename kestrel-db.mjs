// kestrel-db.mjs — the IndexedDB IO for the Shadow Fold. Thin on purpose: all state semantics live in the PURE kernel
// (kestrelledger.mjs); this file only moves bytes in and out of the three sovereign object stores. The IndexedDB factory is
// INJECTED (browser: globalThis.indexedDB; node test: a tiny in-memory shim or fake-indexeddb), so the adapter runs the same
// code in both and the kernel stays environment-free.
//
// THE LEDGER IS BINARY AND APPEND-ONLY. state_mutations rows are raw ArrayBuffers — the 71-byte signed wire frame
// [sourceId:1][packet:6][signature:64] exactly as SENTINEL frames it — not JSON objects. Entire histories are kilobytes, and
// the store is unreadable to standard browser scraping: a local cryptographic cipher, as the spec requires.

import { DB_NAME, DB_VERSION, STORES, GENOME_KEY, WIRE, PAYLOAD, SIG, genome, reconstruct, verifyReplay } from './kestrelledger.mjs';

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
// wrap an IDBRequest in a promise
const req = (r) => new Promise((resolve, reject) => { r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error || new Error('idb-request-failed')); });
// wrap a transaction's completion
const done = (tx) => new Promise((resolve, reject) => { tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error || new Error('idb-tx-failed')); tx.onabort = () => reject(tx.error || new Error('idb-tx-abort')); });

// open (or create) KESTREL_OS with the three sovereign stores. idbFactory defaults to the ambient indexedDB (browser).
export function openKestrelDB(idbFactory, name) {
  const idb = idbFactory || (typeof indexedDB !== 'undefined' ? indexedDB : (typeof globalThis !== 'undefined' ? globalThis.indexedDB : null));
  if (!idb) return Promise.reject(new Error('no IndexedDB available'));
  return new Promise((resolve, reject) => {
    const open = idb.open(name || DB_NAME, DB_VERSION);
    open.onupgradeneeded = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains(STORES.GENOME)) db.createObjectStore(STORES.GENOME);                       // keyed by 'v1'
      if (!db.objectStoreNames.contains(STORES.WALLET)) db.createObjectStore(STORES.WALLET);                       // keyed by name
      if (!db.objectStoreNames.contains(STORES.MUTATIONS)) db.createObjectStore(STORES.MUTATIONS, { autoIncrement: true }); // append-only
    };
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error || new Error('idb-open-failed'));
    open.onblocked = () => reject(new Error('idb-open-blocked'));
  });
}

// genome_core — written once (the immutable DNA), only read thereafter.
export async function putGenome(db, genomeObj) {
  const tx = db.transaction(STORES.GENOME, 'readwrite');
  tx.objectStore(STORES.GENOME).put(isObj(genomeObj) ? genomeObj : genome(), GENOME_KEY);
  await done(tx);
}
export async function getGenome(db) {
  const tx = db.transaction(STORES.GENOME, 'readonly');
  const g = await req(tx.objectStore(STORES.GENOME).get(GENOME_KEY));
  return g || null;
}

// crypto_wallet — the local Ed25519 keypair + the current capability budget (the physical gate).
export async function putWallet(db, wallet) {
  const tx = db.transaction(STORES.WALLET, 'readwrite');
  tx.objectStore(STORES.WALLET).put(isObj(wallet) ? wallet : {}, 'self');
  await done(tx);
}
export async function getWallet(db) {
  const tx = db.transaction(STORES.WALLET, 'readonly');
  const w = await req(tx.objectStore(STORES.WALLET).get('self'));
  return w || null;
}

// THE EXHALE — fold the state. On a state transition, before the UI repaints, fire the signed 6-byte packet into
// state_mutations. The row is the raw 71-byte frame as an ArrayBuffer. Crash / power death / abrupt close after this line
// loses nothing: the mathematical coordinate is already committed to the shadow fold.
export async function exhale(db, frame) {
  if (!(frame instanceof Uint8Array) || frame.length !== WIRE) throw new Error('exhale wants a ' + WIRE + '-byte signed frame');
  const tx = db.transaction(STORES.MUTATIONS, 'readwrite');
  // store a standalone copy of the bytes (an ArrayBuffer), never a view onto a shared buffer
  tx.objectStore(STORES.MUTATIONS).add(frame.slice().buffer);
  await done(tx);
}
// append many frames in one transaction (bulk exhale, e.g. a burst of actions).
export async function exhaleAll(db, frames) {
  const list = (Array.isArray(frames) ? frames : []).filter((f) => f instanceof Uint8Array && f.length === WIRE);
  const tx = db.transaction(STORES.MUTATIONS, 'readwrite');
  const store = tx.objectStore(STORES.MUTATIONS);
  for (const f of list) store.add(f.slice().buffer);
  await done(tx);
  return list.length;
}

// read the whole binary ledger back as 71-byte frames, in append order.
export async function getLedger(db) {
  const tx = db.transaction(STORES.MUTATIONS, 'readonly');
  const rows = await req(tx.objectStore(STORES.MUTATIONS).getAll());
  return (Array.isArray(rows) ? rows : []).map((r) => new Uint8Array(r instanceof ArrayBuffer ? r : (r && r.buffer ? r.buffer : r)));
}
export async function ledgerCount(db) {
  const tx = db.transaction(STORES.MUTATIONS, 'readonly');
  return req(tx.objectStore(STORES.MUTATIONS).count());
}

// THE INHALE — germination on boot. Does NOT ping a cloud server. Open the DB, read the DNA, getAll the ledger, fast-forward.
// If ctx (with verify) is given, every frame passes SENTINEL's verify-before-parse gate on the way in, so a poisoned ledger
// cannot corrupt the node; otherwise the local bytes are replayed trusted. Returns the exact state the node closed in.
export async function wakeKestrelNode(db, ctx) {
  const g = (await getGenome(db)) || genome();
  const frames = await getLedger(db);
  if (ctx && typeof ctx.verify === 'function') {
    const r = verifyReplay(g, frames, ctx);
    return { state: r.state, frames: frames.length, applied: r.applied, rejected: r.rejected, rejectedTotal: r.rejectedTotal, gated: true };
  }
  // trusted local replay: strip the 6-byte payload out of each 71-byte frame
  const payloads = frames.map((f) => f.subarray(1, 1 + PAYLOAD));
  const r = reconstruct(g, payloads);
  return { state: r.state, frames: frames.length, applied: r.applied, skipped: r.skipped, gated: false };
}

export default { openKestrelDB, putGenome, getGenome, putWallet, getWallet, exhale, exhaleAll, getLedger, ledgerCount, wakeKestrelNode };
