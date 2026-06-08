import { OkintSyncStore } from '../sync/sync-store';
import { MemorySyncPersistence, BackendSyncPersistence } from '../sync/persistence';
import { MemoryBackend } from '../backends/memory';
import { OkintStorageError } from '../errors';

describe('OkintSyncStore (memory)', () => {
  async function make() {
    const s = new OkintSyncStore('memory', new MemorySyncPersistence());
    await s.load();
    return s;
  }

  it('reads and writes synchronously after load', async () => {
    const s = await make();
    expect(s.getString('k')).toBeNull();
    s.setString('k', 'v'); // no await
    expect(s.getString('k')).toBe('v'); // immediately visible
    expect(s.backend).toBe('memory');
  });

  it('supports JSON / number / boolean synchronously', async () => {
    const s = await make();
    s.setItem('obj', { a: 1 });
    s.setNumber('n', 7);
    s.setBoolean('b', true);
    expect(s.getItem<{ a: number }>('obj')).toEqual({ a: 1 });
    expect(s.getNumber('n')).toBe(7);
    expect(s.getBoolean('b')).toBe(true);
  });

  it('has / remove / clear / keys', async () => {
    const s = await make();
    s.setString('a', '1');
    s.setString('b', '2');
    expect(s.has('a')).toBe(true);
    expect(s.keys().sort()).toEqual(['a', 'b']);
    s.remove('a');
    expect(s.has('a')).toBe(false);
    s.clear();
    expect(s.keys()).toEqual([]);
  });

  it('throws PARSE_ERROR / INVALID_VALUE like the async facade', async () => {
    const s = await make();
    s.setString('bad', '{nope');
    expect(() => s.getItem('bad')).toThrow(OkintStorageError);
    expect(() => s.setString('x', 5 as unknown as string)).toThrow(OkintStorageError);
  });
});

describe('OkintSyncStore (fast, persistence-backed)', () => {
  it('hydrates synchronously from the backing store', async () => {
    const backing = new MemoryBackend('async'); // stands in for the native plain store
    await backing.setString('theme', 'dark');
    await backing.setString('onboarded', 'true');

    const s = new OkintSyncStore('fast', new BackendSyncPersistence(backing));
    await s.load();

    expect(s.getString('theme')).toBe('dark'); // sync, no await
    expect(s.getBoolean('onboarded')).toBe(true);
  });

  it('persists writes through to the backing store after flush', async () => {
    const backing = new MemoryBackend('async');
    const s = new OkintSyncStore('fast', new BackendSyncPersistence(backing));
    await s.load();

    s.setString('token', 'abc'); // sync
    s.setNumber('count', 3);
    await s.flush(); // durability barrier

    expect(await backing.getString('token')).toBe('abc');
    expect(await backing.getString('count')).toBe('3');
  });

  it('propagates deletes and clear to the backing store', async () => {
    const backing = new MemoryBackend('async');
    await backing.setString('a', '1');
    const s = new OkintSyncStore('fast', new BackendSyncPersistence(backing));
    await s.load();

    s.remove('a');
    await s.flush();
    expect(await backing.getString('a')).toBeNull();

    s.setString('b', '2');
    s.clear();
    await s.flush();
    expect(await backing.keys()).toEqual([]);
  });

  it('flush() rejects when a background persist fails', async () => {
    const flaky = {
      kind: 'async' as const,
      getString: async () => null,
      setString: async () => {
        throw new Error('disk full');
      },
      remove: async () => {},
      clear: async () => {},
      keys: async () => [],
    };
    const s = new OkintSyncStore('fast', new BackendSyncPersistence(flaky));
    await s.load();
    s.setString('k', 'v'); // sync ok, background persist will fail
    await expect(s.flush()).rejects.toMatchObject({ name: 'OkintStorageError', code: 'NATIVE_ERROR' });
  });
});
