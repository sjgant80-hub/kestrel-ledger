// idb-mock.mjs — a tiny, dependency-free in-memory IndexedDB, just the subset kestrel-db.mjs uses (open/upgrade,
// createObjectStore, transaction, put/add/get/getAll/count). It mimics IndexedDB's async callback timing (requests settle
// on a microtask, the transaction completes once its requests have) and clones stored values with structuredClone exactly as
// IndexedDB does — so the adapter runs the same code here as against a real browser IndexedDB, with no npm dependency.
// This is a TEST HELPER, not part of the kernel or the shipped page.

export function createMockIndexedDB() {
  const dbs = new Map(); // name -> { version, stores: Map<name, { data:Map, autoInc:number, opts }> }

  function makeStore(rec, storeName, tx, maybeComplete) {
    const store = rec.stores.get(storeName);
    const request = (fn) => {
      const r = { onsuccess: null, onerror: null, result: undefined, error: null };
      if (tx) tx._pending += 1;
      queueMicrotask(() => {
        try { r.result = fn(); if (r.onsuccess) r.onsuccess({ target: r }); }
        catch (e) { r.error = e; if (r.onerror) r.onerror({ target: r }); }
        finally { if (tx) { tx._pending -= 1; maybeComplete(); } }
      });
      return r;
    };
    return {
      put(value, key) { return request(() => { store.data.set(key, structuredClone(value)); return key; }); },
      add(value, key) { return request(() => { const k = key !== undefined ? key : (store.autoInc += 1); store.data.set(k, structuredClone(value)); return k; }); },
      get(key) { return request(() => store.data.get(key)); },
      getAll() { return request(() => Array.from(store.data.values())); },
      count() { return request(() => store.data.size); },
    };
  }

  function makeTx(rec, storeNames) {
    const tx = { oncomplete: null, onerror: null, onabort: null, error: null, _pending: 0, _settled: false };
    const maybeComplete = () => {
      if (tx._pending === 0 && !tx._settled) { tx._settled = true; queueMicrotask(() => { if (tx.oncomplete) tx.oncomplete({ target: tx }); }); }
    };
    tx.objectStore = (n) => makeStore(rec, n, tx, maybeComplete);
    queueMicrotask(maybeComplete); // a transaction with no requests still completes
    return tx;
  }

  function makeDB(name, rec) {
    return {
      name, get version() { return rec.version; },
      objectStoreNames: { contains: (n) => rec.stores.has(n) },
      createObjectStore(n, opts) { rec.stores.set(n, { data: new Map(), autoInc: 0, opts: opts || {} }); return makeStore(rec, n, null, () => {}); },
      transaction(storeNames) { return makeTx(rec, storeNames); },
      close() {},
    };
  }

  return {
    open(name, version) {
      const r = { onsuccess: null, onerror: null, onupgradeneeded: null, onblocked: null, result: null, error: null };
      queueMicrotask(() => {
        let rec = dbs.get(name);
        if (!rec) { rec = { version: 0, stores: new Map() }; dbs.set(name, rec); }
        const db = makeDB(name, rec);
        r.result = db;
        if ((version || 1) > rec.version) {
          rec.version = version || 1;
          if (r.onupgradeneeded) r.onupgradeneeded({ target: r });
        }
        queueMicrotask(() => { if (r.onsuccess) r.onsuccess({ target: r }); });
      });
      return r;
    },
    // test-only: wipe a db so a "reboot with fresh RAM but same disk" and a clean slate can both be simulated
    _drop(name) { dbs.delete(name); },
    _snapshot() { return dbs; },
  };
}

export default { createMockIndexedDB };
