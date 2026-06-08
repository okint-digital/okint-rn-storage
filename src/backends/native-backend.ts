import type { BackendKind, NativeOkintStorage, StorageBackend } from '../types';
import { OkintStorageError } from '../errors';

/**
 * Backend that delegates to the native module. Used for both:
 *   - `secure` (secure=true)  → hardware Keystore / Keychain
 *   - `async`  (secure=false) → SharedPreferences / UserDefaults
 *
 * The native module is injected (not imported here) so this file stays free of
 * `react-native` and is unit-testable under plain Node with a fake bridge.
 */
export class NativeBackend implements StorageBackend {
  constructor(
    private readonly native: NativeOkintStorage,
    private readonly service: string,
    private readonly secure: boolean,
    readonly kind: BackendKind,
  ) {}

  async getString(key: string): Promise<string | null> {
    try {
      const v = await this.native.getItem(this.service, key, this.secure);
      return v ?? null;
    } catch (e) {
      throw wrap(e, `get "${key}"`);
    }
  }

  async setString(key: string, value: string): Promise<void> {
    try {
      await this.native.setItem(this.service, key, value, this.secure);
    } catch (e) {
      throw wrap(e, `set "${key}"`);
    }
  }

  async remove(key: string): Promise<void> {
    try {
      await this.native.removeItem(this.service, key, this.secure);
    } catch (e) {
      throw wrap(e, `remove "${key}"`);
    }
  }

  async clear(): Promise<void> {
    try {
      await this.native.clear(this.service, this.secure);
    } catch (e) {
      throw wrap(e, 'clear');
    }
  }

  async keys(): Promise<string[]> {
    try {
      const ks = await this.native.getAllKeys(this.service, this.secure);
      return ks ?? [];
    } catch (e) {
      throw wrap(e, 'keys');
    }
  }
}

function wrap(cause: unknown, op: string): OkintStorageError {
  const msg = cause instanceof Error ? cause.message : String(cause);
  return new OkintStorageError('NATIVE_ERROR', `Native storage failed during ${op}: ${msg}`, cause);
}
