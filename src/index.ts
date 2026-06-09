import type {
  OkintStorage,
  OkintStorageOptions,
  StorageBackend,
  BackendKind,
  OkintSyncStorage,
  OkintSyncStorageOptions,
  SyncPersistence,
} from './types';
import { StorageFacade } from './facade';
import { MemoryBackend } from './backends/memory';
import { NativeBackend } from './backends/native-backend';
import { OkintSyncStore } from './sync/sync-store';
import { JSISyncStore } from './sync/jsi-store';
import { MemorySyncPersistence, BackendSyncPersistence } from './sync/persistence';
import { getNativeModule } from './native/bridge';
import { getJSIStore } from './native/jsi';
import { OkintStorageError } from './errors';
import { normalizeNamespace } from './validate';

const DEFAULT_NAMESPACE = 'okint';

/**
 * Create a storage instance bound to a backend + namespace.
 *
 * @example
 *   const secure = createStorage({ backend: 'secure', namespace: 'auth' });
 *   await secure.setString('refreshToken', token);   // hardware-encrypted
 *
 *   const cache = createStorage({ backend: 'memory' });
 *   await cache.setItem('campaigns', list);
 */
export function createStorage(options: OkintStorageOptions): OkintStorage {
  const namespace = normalizeNamespace(options.namespace, DEFAULT_NAMESPACE);
  return new StorageFacade(resolveBackend(options.backend, namespace, options.requireAuth === true));
}

function resolveBackend(kind: BackendKind, namespace: string, requireAuth: boolean): StorageBackend {
  switch (kind) {
    case 'memory':
      return new MemoryBackend('memory');
    case 'secure':
      // `requireAuth` only gates the secure store (hardware-key crypto).
      return new NativeBackend(getNativeModule(), namespace, kind, requireAuth);
    case 'async':
    case 'encrypted':
    case 'sqlite':
      return new NativeBackend(getNativeModule(), namespace, kind);
    default:
      throw new OkintStorageError('UNKNOWN_BACKEND', `Unknown storage backend "${String(kind)}".`);
  }
}

/**
 * Create a SYNCHRONOUS storage instance. Resolves once the snapshot is loaded;
 * thereafter all get/set are synchronous. This is the MMKV-style store — use it
 * for state persistence/rehydration, feature flags, and hot-path UI state.
 *
 * @example
 *   const fast = await createSyncStorage({ backend: 'fast', namespace: 'app' });
 *   fast.setBoolean('onboarded', true);          // sync write (persists in bg)
 *   const onboarded = fast.getBoolean('onboarded'); // sync read
 *   await fast.flush();                           // ensure durability (e.g. on background)
 */
// Sync stores are interned per (backend, namespace): two callers asking for the
// same fast store get the SAME instance, so their in-memory snapshots can't
// diverge and silently overwrite each other. The cached promise is evicted on
// load failure so a later call can retry.
const syncRegistry = new Map<string, Promise<OkintSyncStorage>>();

export function createSyncStorage(options: OkintSyncStorageOptions): Promise<OkintSyncStorage> {
  // Promise-returning factory → surface validation as a rejection, not a sync throw.
  let namespace: string;
  try {
    namespace = normalizeNamespace(options.namespace, DEFAULT_NAMESPACE);
  } catch (e) {
    return Promise.reject(e);
  }
  const registryKey = `${options.backend}:${namespace}`;

  const existing = syncRegistry.get(registryKey);
  if (existing) return existing;

  const built = buildSyncStore(options.backend, namespace);
  syncRegistry.set(registryKey, built);
  built.catch(() => syncRegistry.delete(registryKey));
  return built;
}

// Synchronous, zero-load sync stores: hydrated in one blocking native call at
// construction, then pure in-JS reads (maximum read performance). Interned per
// (backend, namespace) like the async variant.
const syncRegistrySync = new Map<string, OkintSyncStorage>();

/**
 * Create a synchronous storage instance WITHOUT an async load step. Hydrates the
 * snapshot in a single blocking native bulk-read, then all get/set are
 * synchronous in-JS-memory ops (writes persist in the background). Use this when
 * you need state available immediately at startup (e.g. before first render).
 *
 * @example
 *   const fast = createSyncStorageSync({ backend: 'fast', namespace: 'app' });
 *   const onboarded = fast.getBoolean('onboarded'); // sync, zero-load
 */
export function createSyncStorageSync(options: OkintSyncStorageOptions): OkintSyncStorage {
  const namespace = normalizeNamespace(options.namespace, DEFAULT_NAMESPACE);
  const registryKey = `${options.backend}:${namespace}`;
  const existing = syncRegistrySync.get(registryKey);
  if (existing) return existing;

  let store: OkintSyncStore;
  switch (options.backend) {
    case 'memory':
      store = new OkintSyncStore('memory', new MemorySyncPersistence());
      store.loadSync({});
      break;
    case 'fast': {
      const native = getNativeModule();
      const entries = native.getEntriesSync(namespace, 'async');
      store = new OkintSyncStore('fast', new BackendSyncPersistence(new NativeBackend(native, namespace, 'async')));
      store.loadSync(entries);
      break;
    }
    default:
      throw new OkintStorageError('UNKNOWN_BACKEND', `Unknown sync backend "${String(options.backend)}".`);
  }
  syncRegistrySync.set(registryKey, store);
  return store;
}

// JSI stores are interned per namespace (one HostObject per logical store).
const jsiRegistry = new Map<string, OkintSyncStorage>();

/**
 * Create a synchronous store backed by the C++/JSI engine — get/set go straight
 * into C++ with no bridge serialization and no snapshot (maximum performance,
 * zero JS memory overhead). Installs the native engine on first use; throws if
 * the JSI runtime is unreachable (e.g. remote JS debugging) — fall back to
 * `createSyncStorageSync` there.
 *
 * @example
 *   const kv = createJSIStorage({ namespace: 'app' });
 *   kv.setString('theme', 'dark');           // sync, in C++
 *   const theme = kv.getString('theme');     // sync, in C++
 */
export function createJSIStorage(options: { namespace?: string } = {}): OkintSyncStorage {
  const namespace = normalizeNamespace(options.namespace, DEFAULT_NAMESPACE);
  const existing = jsiRegistry.get(namespace);
  if (existing) return existing;
  const store = new JSISyncStore(getJSIStore(getNativeModule(), namespace));
  jsiRegistry.set(namespace, store);
  return store;
}

async function buildSyncStore(
  backend: OkintSyncStorageOptions['backend'],
  namespace: string,
): Promise<OkintSyncStorage> {
  let persistence: SyncPersistence;
  switch (backend) {
    case 'memory':
      persistence = new MemorySyncPersistence();
      break;
    case 'fast':
      persistence = new BackendSyncPersistence(
        new NativeBackend(getNativeModule(), namespace, 'async'),
      );
      break;
    default:
      throw new OkintStorageError('UNKNOWN_BACKEND', `Unknown sync backend "${String(backend)}".`);
  }
  const store = new OkintSyncStore(backend, persistence);
  await store.load();
  return store;
}

export { StorageFacade } from './facade';
export { MemoryBackend } from './backends/memory';
export { NativeBackend } from './backends/native-backend';
export { OkintSyncStore } from './sync/sync-store';
export { JSISyncStore } from './sync/jsi-store';
export { MemorySyncPersistence, BackendSyncPersistence } from './sync/persistence';
export { OkintStorageError } from './errors';
export type { OkintStorageErrorCode } from './errors';
export type {
  OkintStorage,
  OkintStorageOptions,
  StorageBackend,
  BackendKind,
  NativeOkintStorage,
  JSIStore,
  OkintSyncStorage,
  OkintSyncStorageOptions,
  SyncBackendKind,
  SyncPersistence,
} from './types';
