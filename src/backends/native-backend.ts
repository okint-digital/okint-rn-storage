import type { NativeOkintStorage, NativeStoreKind, StorageBackend } from '../types';
import { OkintStorageError } from '../errors';

/**
 * Backend that delegates to the native module. One class drives all four
 * native-backed stores, selected by `kind`, which is forwarded to native as the
 * `store` discriminator:
 *   - `secure`    → hardware Keystore / Keychain
 *   - `async`     → SharedPreferences / UserDefaults (plaintext)
 *   - `encrypted` → AES-encrypted blobs, key in Keystore/Keychain (large values)
 *   - `sqlite`    → SQLite-backed key/value
 *
 * The native module is injected (not imported here) so this file stays free of
 * `react-native` and is unit-testable under plain Node with a fake bridge.
 */
export class NativeBackend implements StorageBackend {
  constructor(
    private readonly native: NativeOkintStorage,
    private readonly service: string,
    readonly kind: NativeStoreKind,
    /** Gate reads/writes behind device-credential auth (secure backend only). */
    private readonly requireAuth: boolean = false,
  ) {}

  async getString(key: string): Promise<string | null> {
    try {
      const v = await this.native.getItem(this.service, key, this.kind, this.requireAuth);
      return v ?? null;
    } catch (e) {
      throw wrap(e, `get "${key}"`);
    }
  }

  async setString(key: string, value: string): Promise<void> {
    try {
      await this.native.setItem(this.service, key, value, this.kind, this.requireAuth);
    } catch (e) {
      throw wrap(e, `set "${key}"`);
    }
  }

  async remove(key: string): Promise<void> {
    try {
      await this.native.removeItem(this.service, key, this.kind);
    } catch (e) {
      throw wrap(e, `remove "${key}"`);
    }
  }

  async clear(): Promise<void> {
    try {
      await this.native.clear(this.service, this.kind);
    } catch (e) {
      throw wrap(e, 'clear');
    }
  }

  async keys(): Promise<string[]> {
    try {
      const ks = await this.native.getAllKeys(this.service, this.kind);
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
