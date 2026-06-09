import { StorageFacade } from '../facade';
import { MemoryBackend } from '../backends/memory';
import { OkintSyncStore } from '../sync/sync-store';
import { MemorySyncPersistence } from '../sync/persistence';
import type { SyncPersistence } from '../types';
import { OkintStorageError } from '../errors';

function asyncStore() {
  return new StorageFacade(new MemoryBackend('memory'));
}
async function syncStore() {
  const s = new OkintSyncStore('memory', new MemorySyncPersistence());
  await s.load();
  return s;
}

describe('audit: value validation (async facade)', () => {
  const s = asyncStore();

  it('rejects NaN/Infinity in setNumber', async () => {
    await expect(s.setNumber('n', NaN)).rejects.toBeInstanceOf(OkintStorageError);
    await expect(s.setNumber('n', Infinity)).rejects.toBeInstanceOf(OkintStorageError);
  });

  it('rejects non-serializable setItem', async () => {
    await expect(s.setItem('x', undefined)).rejects.toBeInstanceOf(OkintStorageError);
    await expect(s.setItem('x', () => {})).rejects.toBeInstanceOf(OkintStorageError);
  });

  it('getBoolean is strict (non-canonical → null, not false)', async () => {
    await s.setString('b', '1');
    expect(await s.getBoolean('b')).toBeNull();
    await s.setBoolean('b', false);
    expect(await s.getBoolean('b')).toBe(false);
  });

  it('rejects invalid keys', async () => {
    await expect(s.getString('')).rejects.toBeInstanceOf(OkintStorageError);
  });
});

describe('audit: value validation (sync store)', () => {
  it('rejects NaN/Infinity and non-serializable values', async () => {
    const s = await syncStore();
    expect(() => s.setNumber('n', NaN)).toThrow(OkintStorageError);
    expect(() => s.setItem('x', undefined)).toThrow(OkintStorageError);
    expect(() => s.getString('')).toThrow(OkintStorageError);
  });

  it('getBoolean is strict', async () => {
    const s = await syncStore();
    s.setString('b', 'yes');
    expect(s.getBoolean('b')).toBeNull();
  });
});

describe('audit: multiGet/multiSet/multiRemove (async)', () => {
  it('round-trips a batch', async () => {
    const s = asyncStore();
    await s.multiSet({ a: '1', b: '2', c: '3' });
    expect(await s.multiGet(['a', 'b', 'missing'])).toEqual({ a: '1', b: '2', missing: null });
    await s.multiRemove(['a', 'b']);
    expect(await s.multiGet(['a', 'b'])).toEqual({ a: null, b: null });
  });

  it('rejects non-string multiSet values', async () => {
    const s = asyncStore();
    await expect(s.multiSet({ a: 5 as unknown as string })).rejects.toBeInstanceOf(OkintStorageError);
  });
});

describe('audit: multi* (sync)', () => {
  it('round-trips a batch synchronously', async () => {
    const s = await syncStore();
    s.multiSet({ a: '1', b: '2' });
    expect(s.multiGet(['a', 'b', 'x'])).toEqual({ a: '1', b: '2', x: null });
    s.multiRemove(['a']);
    expect(s.has('a')).toBe(false);
  });
});

describe('audit: __proto__ as a key round-trips through multiGet (null-proto result)', () => {
  it('async facade: a key named __proto__ is returned, not swallowed', async () => {
    const s = asyncStore();
    await s.setString('__proto__', 'v');
    const out = await s.multiGet(['__proto__', 'constructor']);
    expect(out['__proto__']).toBe('v');
    expect(out['constructor']).toBeNull();
    // result has no inherited Object.prototype members masquerading as entries
    expect(Object.getPrototypeOf(out)).toBeNull();
  });

  it('sync store: a key named __proto__ is returned, not swallowed', async () => {
    const s = await syncStore();
    s.setString('__proto__', 'v');
    expect(s.multiGet(['__proto__'])['__proto__']).toBe('v');
  });
});

describe('audit: drain() partial-batch durability (no tail loss; failed key retried)', () => {
  it('a mid-batch persist failure does not drop the other keys and is retried later', async () => {
    let failKey: string | null = 'b';
    const persisted = new Map<string, string | null>();
    const persistence: SyncPersistence = {
      loadAll: async () => ({}),
      persist: async (k, v) => {
        if (k === failKey) throw new Error('boom');
        persisted.set(k, v);
      },
      clearAll: async () => {},
    };
    const errs: unknown[] = [];
    const s = new OkintSyncStore('fast', persistence, (e) => errs.push(e));
    await s.load();

    s.setString('a', '1');
    s.setString('b', '2'); // will fail this round
    s.setString('c', '3');

    // First flush: a and c persist even though b fails; flush surfaces the error.
    await expect(s.flush()).rejects.toBeInstanceOf(OkintStorageError);
    expect(persisted.get('a')).toBe('1');
    expect(persisted.get('c')).toBe('3'); // tail NOT lost despite b failing mid-batch
    expect(persisted.has('b')).toBe(false);
    expect(errs.length).toBeGreaterThan(0);

    // b is retained for retry; once the backend recovers, a flush persists it.
    failKey = null;
    await s.flush();
    expect(persisted.get('b')).toBe('2');
  });

  it('a clear() racing in during a failing persist does NOT resurrect the cleared key', async () => {
    // Regression: the failed-write requeue must be suppressed when a clear() was
    // armed during the drain, else the cleared key is re-persisted and reappears.
    let releasePersist: (() => void) | undefined;
    const gate = new Promise<void>((res) => {
      releasePersist = res;
    });
    let firstPersist = true;
    const persisted = new Map<string, string | null>();
    const persistence: SyncPersistence = {
      loadAll: async () => ({}),
      persist: async (k, v) => {
        if (firstPersist) {
          firstPersist = false;
          await gate; // hold the first persist open...
          throw new Error('boom'); // ...then fail it
        }
        persisted.set(k, v);
      },
      clearAll: async () => {
        persisted.clear();
      },
    };
    const s = new OkintSyncStore('fast', persistence, () => {});
    await s.load();

    s.setString('k', 'v'); // schedules drain; persist('k','v') starts and blocks on the gate
    await Promise.resolve(); // let the drain begin the persist
    s.clear(); // clear races in while the persist is in flight
    releasePersist?.(); // now the in-flight persist throws
    await s.flush().catch(() => {});

    expect(s.has('k')).toBe(false); // gone from memory
    expect(persisted.has('k')).toBe(false); // and NOT resurrected on disk
  });

  it('a throwing console.warn does NOT poison the persistence chain (no total data loss)', async () => {
    // Regression: recordPersistError runs inside drain(); if its error sink
    // (here console.warn) throws, the rejection must not kill the persist chain.
    const origWarn = console.warn;
    console.warn = () => {
      throw new Error('console polyfill throws');
    };
    try {
      let fail = true;
      const persisted = new Map<string, string | null>();
      const persistence: SyncPersistence = {
        loadAll: async () => ({}),
        persist: async (k, v) => {
          if (fail) {
            fail = false;
            throw new Error('boom');
          }
          persisted.set(k, v);
        },
        clearAll: async () => {},
      };
      const s = new OkintSyncStore('fast', persistence); // no onPersistError → console.warn path
      await s.load();

      s.setString('a', '1'); // first persist fails → recordPersistError → console.warn throws
      await s.flush().catch(() => {});
      s.setString('b', '2'); // chain must still be alive
      await s.flush();
      expect(persisted.get('b')).toBe('2');
    } finally {
      console.warn = origWarn;
    }
  });

  it('a newer queued value wins over a re-enqueued failed write', async () => {
    let failNext = true;
    const persisted = new Map<string, string | null>();
    const persistence: SyncPersistence = {
      loadAll: async () => ({}),
      persist: async (k, v) => {
        if (failNext) {
          failNext = false;
          throw new Error('boom-once');
        }
        persisted.set(k, v);
      },
      clearAll: async () => {},
    };
    const s = new OkintSyncStore('fast', persistence, () => {});
    await s.load();

    s.setString('k', 'old'); // first persist throws, 'old' re-enqueued
    await s.flush().catch(() => {});
    s.setString('k', 'new'); // newer value must not be clobbered by the requeue
    await s.flush();
    expect(persisted.get('k')).toBe('new');
  });
});

describe('audit: sync write coalescing', () => {
  function counting() {
    const state = { persistCalls: 0, lastValue: new Map<string, string | null>() };
    const persistence: SyncPersistence = {
      loadAll: async () => ({}),
      persist: async (k, v) => {
        state.persistCalls += 1;
        state.lastValue.set(k, v);
      },
      clearAll: async () => {},
    };
    return { state, persistence };
  }

  it('coalesces a burst of writes to the same key into ONE persist', async () => {
    const { state, persistence } = counting();
    const s = new OkintSyncStore('fast', persistence);
    await s.load();

    for (let i = 0; i < 100; i++) s.setString('k', String(i));
    await s.flush();

    expect(state.persistCalls).toBe(1); // 100 writes → 1 persist
    expect(state.lastValue.get('k')).toBe('99'); // latest value wins
  });

  it('persists one op per distinct dirty key', async () => {
    const { state, persistence } = counting();
    const s = new OkintSyncStore('fast', persistence);
    await s.load();

    for (let i = 0; i < 50; i++) {
      s.setString('a', String(i));
      s.setString('b', String(i));
    }
    await s.flush();

    expect(state.persistCalls).toBe(2); // 100 writes across 2 keys → 2 persists
  });
});

describe('audit: sync load is idempotent', () => {
  it('a second load() does not wipe in-memory writes', async () => {
    const s = await syncStore();
    s.setString('k', 'v');
    await s.load(); // should be a no-op
    expect(s.getString('k')).toBe('v');
  });
});

describe('audit: zero-load sync hydration (loadSync)', () => {
  it('hydrates synchronously and serves reads with no await', () => {
    const s = new OkintSyncStore('fast', new MemorySyncPersistence());
    s.loadSync({ theme: 'dark', n: '42' });
    expect(s.getString('theme')).toBe('dark');
    expect(s.getNumber('n')).toBe(42);
  });

  it('loadSync is idempotent (a second call does not clobber writes)', () => {
    const s = new OkintSyncStore('memory', new MemorySyncPersistence());
    s.loadSync({ a: '1' });
    s.setString('a', '2');
    s.loadSync({ a: '1' }); // no-op
    expect(s.getString('a')).toBe('2');
  });
});
