import { NativeBackend } from '../backends/native-backend';
import type { NativeOkintStorage, NativeStoreKind } from '../types';

/** Fake native module that records (service, store) and stores per (service, store). */
function makeFakeNative() {
  const stores = new Map<string, Map<string, string>>();
  const calls: Array<{ op: string; service: string; store: NativeStoreKind; key?: string; requireAuth?: boolean }> = [];
  const bucket = (service: string, store: NativeStoreKind) => {
    const id = `${store}:${service}`;
    let m = stores.get(id);
    if (!m) {
      m = new Map();
      stores.set(id, m);
    }
    return m;
  };
  const native: NativeOkintStorage = {
    async setItem(service, key, value, store, requireAuth) {
      calls.push({ op: 'setItem', service, store, key, requireAuth });
      bucket(service, store).set(key, value);
    },
    async getItem(service, key, store, requireAuth) {
      calls.push({ op: 'getItem', service, store, key, requireAuth });
      return bucket(service, store).get(key) ?? null;
    },
    async removeItem(service, key, store) {
      calls.push({ op: 'removeItem', service, store, key });
      bucket(service, store).delete(key);
    },
    async clear(service, store) {
      calls.push({ op: 'clear', service, store });
      bucket(service, store).clear();
    },
    async getAllKeys(service, store) {
      calls.push({ op: 'getAllKeys', service, store });
      return [...bucket(service, store).keys()];
    },
    getEntriesSync(service, store) {
      calls.push({ op: 'getEntriesSync', service, store });
      return Object.fromEntries(bucket(service, store));
    },
    installJSI: () => false,
  };
  return { native, calls, stores };
}

describe('NativeBackend', () => {
  it('forwards service + store kind for a secure backend', async () => {
    const { native, calls } = makeFakeNative();
    const b = new NativeBackend(native, 'auth', 'secure');

    await b.setString('refreshToken', 'abc');
    expect(await b.getString('refreshToken')).toBe('abc');

    expect(calls[0]).toEqual({ op: 'setItem', service: 'auth', store: 'secure', key: 'refreshToken', requireAuth: false });
    expect(b.kind).toBe('secure');
  });

  it('forwards requireAuth=true to native get/set when gated', async () => {
    const { native, calls } = makeFakeNative();
    const b = new NativeBackend(native, 'auth', 'secure', true);
    await b.setString('token', 'abc');
    await b.getString('token');
    expect(calls.find((c) => c.op === 'setItem')?.requireAuth).toBe(true);
    expect(calls.find((c) => c.op === 'getItem')?.requireAuth).toBe(true);
  });

  it('defaults requireAuth to false when not gated', async () => {
    const { native, calls } = makeFakeNative();
    const b = new NativeBackend(native, 'auth', 'secure');
    await b.setString('token', 'abc');
    expect(calls.find((c) => c.op === 'setItem')?.requireAuth).toBe(false);
  });

  it('forwards the right store kind for async/encrypted/sqlite', async () => {
    const { native, calls } = makeFakeNative();
    for (const kind of ['async', 'encrypted', 'sqlite'] as const) {
      const b = new NativeBackend(native, 'svc', kind);
      await b.setString('k', 'v');
      expect(b.kind).toBe(kind);
    }
    expect(calls.map((c) => c.store)).toEqual(['async', 'encrypted', 'sqlite']);
  });

  it('partitions by (service, store) so stores never collide', async () => {
    const { native } = makeFakeNative();
    const secure = new NativeBackend(native, 'app', 'secure');
    const encrypted = new NativeBackend(native, 'app', 'encrypted');
    await secure.setString('k', 'secret');
    expect(await encrypted.getString('k')).toBeNull(); // same service, different store
  });

  it('clear() and keys() operate on the right store', async () => {
    const { native } = makeFakeNative();
    const b = new NativeBackend(native, 'auth', 'sqlite');
    await b.setString('a', '1');
    await b.setString('b', '2');
    expect((await b.keys()).sort()).toEqual(['a', 'b']);
    await b.clear();
    expect(await b.keys()).toEqual([]);
  });

  it('wraps native failures in OkintStorageError(NATIVE_ERROR)', async () => {
    const failing: NativeOkintStorage = {
      setItem: () => Promise.reject(new Error('keystore boom')),
      getItem: () => Promise.reject(new Error('boom')),
      removeItem: () => Promise.resolve(),
      clear: () => Promise.resolve(),
      getAllKeys: () => Promise.resolve([]),
      getEntriesSync: () => ({}),
      installJSI: () => false,
    };
    const b = new NativeBackend(failing, 'auth', 'secure');
    await expect(b.setString('k', 'v')).rejects.toMatchObject({
      name: 'OkintStorageError',
      code: 'NATIVE_ERROR',
    });
  });
});
