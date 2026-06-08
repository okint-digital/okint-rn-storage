// The package index imports the native bridge (which imports 'react-native').
// Mock it so the factory wiring is testable in plain Node. The memory backends
// never touch NativeModules, so an empty mock is sufficient.
jest.mock('react-native', () => ({ NativeModules: {} }), { virtual: true });

import { createStorage, createSyncStorage, createSyncStorageSync, OkintStorageError } from '../index';

describe('createStorage (memory)', () => {
  it('builds a working async store', async () => {
    const s = createStorage({ backend: 'memory', namespace: 'app' });
    expect(s.backend).toBe('memory');
    await s.setString('k', 'v');
    expect(await s.getString('k')).toBe('v');
  });

  it('validates the namespace (filename-injection guard)', () => {
    expect(() => createStorage({ backend: 'memory', namespace: '../evil' })).toThrow(OkintStorageError);
    expect(() => createStorage({ backend: 'memory', namespace: 'a/b' })).toThrow(OkintStorageError);
  });

  it('wires encrypted/sqlite to the native module (missing here -> clear error)', () => {
    // With the native module mocked away these surface NATIVE_MODULE_MISSING
    // rather than BACKEND_NOT_IMPLEMENTED — they are implemented backends that
    // simply require the native module to be present.
    expect(() => createStorage({ backend: 'encrypted' })).toThrow(/NATIVE_MODULE_MISSING|native module/i);
    expect(() => createStorage({ backend: 'sqlite' })).toThrow(OkintStorageError);
  });
});

describe('createSyncStorage (memory) — singleton per namespace', () => {
  it('returns the SAME instance for the same (backend, namespace)', async () => {
    const a = await createSyncStorage({ backend: 'memory', namespace: 'shared' });
    const b = await createSyncStorage({ backend: 'memory', namespace: 'shared' });
    expect(a).toBe(b); // interned → snapshots can't diverge
  });

  it('returns DIFFERENT instances for different namespaces', async () => {
    const a = await createSyncStorage({ backend: 'memory', namespace: 'ns1' });
    const b = await createSyncStorage({ backend: 'memory', namespace: 'ns2' });
    expect(a).not.toBe(b);
  });

  it('validates namespace', async () => {
    await expect(createSyncStorage({ backend: 'memory', namespace: 'a/b' })).rejects.toBeInstanceOf(
      OkintStorageError,
    );
  });
});

describe('createSyncStorageSync (zero-load, memory)', () => {
  it('returns a usable store synchronously (no await)', () => {
    const s = createSyncStorageSync({ backend: 'memory', namespace: 'app' });
    expect(s.backend).toBe('memory');
    s.setString('k', 'v');
    expect(s.getString('k')).toBe('v');
  });

  it('is interned per namespace', () => {
    const a = createSyncStorageSync({ backend: 'memory', namespace: 'sync1' });
    const b = createSyncStorageSync({ backend: 'memory', namespace: 'sync1' });
    expect(a).toBe(b);
  });

  it('validates namespace (throws synchronously)', () => {
    expect(() => createSyncStorageSync({ backend: 'memory', namespace: 'a/b' })).toThrow(OkintStorageError);
  });
});
