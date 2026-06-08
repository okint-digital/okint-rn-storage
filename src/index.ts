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
import { MemorySyncPersistence, BackendSyncPersistence } from './sync/persistence';
import { getNativeModule } from './native/bridge';
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
  return new StorageFacade(resolveBackend(options.backend, namespace));
}

function resolveBackend(kind: BackendKind, namespace: string): StorageBackend {
  switch (kind) {
    case 'memory':
      return new MemoryBackend('memory');
    case 'secure':
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
export { MemorySyncPersistence, BackendSyncPersistence } from './sync/persistence';
export { OkintStorageError } from './errors';
export type { OkintStorageErrorCode } from './errors';
export type {
  OkintStorage,
  OkintStorageOptions,
  StorageBackend,
  BackendKind,
  NativeOkintStorage,
  OkintSyncStorage,
  OkintSyncStorageOptions,
  SyncBackendKind,
  SyncPersistence,
} from './types';
