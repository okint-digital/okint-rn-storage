import { JSISyncStore } from '../sync/jsi-store';
import { getJSIStore } from '../native/jsi';
import type { JSIStore, NativeOkintStorage } from '../types';
import { OkintStorageError } from '../errors';

/** In-memory fake of the C++ JSI HostObject. */
function fakeJSIStore(): JSIStore {
  const m = new Map<string, string>();
  return {
    getString: (k) => (m.has(k) ? (m.get(k) as string) : null),
    setString: (k, v) => void m.set(k, v),
    remove: (k) => void m.delete(k),
    clear: () => m.clear(),
    contains: (k) => m.has(k),
    getAllKeys: () => [...m.keys()],
  };
}

describe('JSISyncStore', () => {
  it('round-trips strings/json/number/boolean synchronously', () => {
    const s = new JSISyncStore(fakeJSIStore());
    expect(s.backend).toBe('fast');
    s.setString('a', '1');
    s.setItem('o', { x: 1 });
    s.setNumber('n', 7);
    s.setBoolean('b', true);
    expect(s.getString('a')).toBe('1');
    expect(s.getItem<{ x: number }>('o')).toEqual({ x: 1 });
    expect(s.getNumber('n')).toBe(7);
    expect(s.getBoolean('b')).toBe(true);
  });

  it('has/remove/clear/keys + multi*', () => {
    const s = new JSISyncStore(fakeJSIStore());
    s.multiSet({ a: '1', b: '2' });
    expect(s.has('a')).toBe(true);
    expect(s.multiGet(['a', 'b', 'z'])).toEqual({ a: '1', b: '2', z: null });
    s.multiRemove(['a']);
    expect(s.has('a')).toBe(false);
    s.clear();
    expect(s.keys()).toEqual([]);
  });

  it('validates keys and values', () => {
    const s = new JSISyncStore(fakeJSIStore());
    expect(() => s.getString('')).toThrow(OkintStorageError);
    expect(() => s.setNumber('n', NaN)).toThrow(OkintStorageError);
    expect(() => s.setItem('x', undefined)).toThrow(OkintStorageError);
  });

  it('flush() resolves (writes already persisted by the engine)', async () => {
    const s = new JSISyncStore(fakeJSIStore());
    await expect(s.flush()).resolves.toBeUndefined();
  });
});

describe('getJSIStore', () => {
  const g = globalThis as Record<string, unknown>;
  afterEach(() => {
    delete g.__okintCreateJSI;
  });

  it('installs the engine on first use, then returns a store', () => {
    let installs = 0;
    const native = {
      installJSI: () => {
        installs += 1;
        g.__okintCreateJSI = () => fakeJSIStore();
        return true;
      },
    } as unknown as NativeOkintStorage;

    const store = getJSIStore(native, 'app');
    store.setString('k', 'v');
    expect(store.getString('k')).toBe('v');
    expect(installs).toBe(1);
  });

  it('throws a clear error when the engine cannot be installed', () => {
    const native = { installJSI: () => false } as unknown as NativeOkintStorage;
    expect(() => getJSIStore(native, 'app')).toThrow(/NATIVE_MODULE_MISSING|JSI engine/i);
  });
});
