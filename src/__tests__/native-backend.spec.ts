import { NativeBackend } from '../backends/native-backend';
import type { NativeOkintStorage } from '../types';

/** Fake native module that records (service, secure) and stores per-service. */
function makeFakeNative() {
  const stores = new Map<string, Map<string, string>>();
  const calls: Array<{ op: string; service: string; secure: boolean; key?: string }> = [];
  const store = (service: string) => {
    let m = stores.get(service);
    if (!m) {
      m = new Map();
      stores.set(service, m);
    }
    return m;
  };
  const native: NativeOkintStorage = {
    async setItem(service, key, value, secure) {
      calls.push({ op: 'setItem', service, secure, key });
      store(service).set(key, value);
    },
    async getItem(service, key, secure) {
      calls.push({ op: 'getItem', service, secure, key });
      return store(service).get(key) ?? null;
    },
    async removeItem(service, key, secure) {
      calls.push({ op: 'removeItem', service, secure, key });
      store(service).delete(key);
    },
    async clear(service, secure) {
      calls.push({ op: 'clear', service, secure });
      store(service).clear();
    },
    async getAllKeys(service, secure) {
      calls.push({ op: 'getAllKeys', service, secure });
      return [...store(service).keys()];
    },
  };
  return { native, calls, stores };
}

describe('NativeBackend', () => {
  it('forwards the service + secure flag for a secure backend', async () => {
    const { native, calls } = makeFakeNative();
    const b = new NativeBackend(native, 'auth', true, 'secure');

    await b.setString('refreshToken', 'abc');
    expect(await b.getString('refreshToken')).toBe('abc');

    expect(calls[0]).toEqual({ op: 'setItem', service: 'auth', secure: true, key: 'refreshToken' });
    expect(b.kind).toBe('secure');
  });

  it('uses secure=false for the async backend', async () => {
    const { native, calls } = makeFakeNative();
    const b = new NativeBackend(native, 'cache', false, 'async');
    await b.setString('k', 'v');
    expect(calls[0]?.secure).toBe(false);
    expect(b.kind).toBe('async');
  });

  it('partitions by service across backends', async () => {
    const { native } = makeFakeNative();
    const auth = new NativeBackend(native, 'auth', true, 'secure');
    const cache = new NativeBackend(native, 'cache', false, 'async');
    await auth.setString('k', 'secret');
    expect(await cache.getString('k')).toBeNull();
  });

  it('clear() and keys() operate on the right service', async () => {
    const { native } = makeFakeNative();
    const b = new NativeBackend(native, 'auth', true, 'secure');
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
    };
    const b = new NativeBackend(failing, 'auth', true, 'secure');
    await expect(b.setString('k', 'v')).rejects.toMatchObject({
      name: 'OkintStorageError',
      code: 'NATIVE_ERROR',
    });
  });
});
