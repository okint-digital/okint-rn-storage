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
