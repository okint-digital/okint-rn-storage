import type { JSIStore, NativeOkintStorage } from '../types';
import { OkintStorageError } from '../errors';

const GLOBAL_FACTORY = '__okintCreateJSI';

function factory(): ((namespace: string) => JSIStore) | undefined {
  const g = globalThis as Record<string, unknown>;
  const f = g[GLOBAL_FACTORY];
  return typeof f === 'function' ? (f as (namespace: string) => JSIStore) : undefined;
}

let installed = false;

/**
 * Resolve a JSI HostObject store for `namespace`, installing the native C++
 * engine on first use. Throws a clear error if the JSI runtime is unreachable
 * (e.g. remote JS debugging) — callers should fall back to `createSyncStorageSync`.
 */
export function getJSIStore(native: NativeOkintStorage, namespace: string): JSIStore {
  if (!installed && factory() === undefined) {
    try {
      native.installJSI();
    } catch {
      // fall through to the missing-engine error below
    }
  }
  const create = factory();
  if (create === undefined) {
    throw new OkintStorageError(
      'NATIVE_MODULE_MISSING',
      'okint JSI engine is unavailable (remote JS debugging or unsupported runtime). ' +
        'Use createSyncStorageSync for synchronous access instead.',
    );
  }
  installed = true;
  return create(namespace);
}
