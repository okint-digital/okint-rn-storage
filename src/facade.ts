import type { BackendKind, OkintStorage, StorageBackend } from './types';
import {
  assertKey,
  assertStringValue,
  fromJson,
  numberToString,
  stringToBoolean,
  stringToNumber,
  toJson,
} from './validate';

/**
 * Wraps a low-level StorageBackend with ergonomic, typed accessors. All values
 * are persisted as strings; the facade handles JSON / number / boolean
 * (de)serialization, key validation, and typed errors.
 *
 * Every method is async and REJECTS (never throws synchronously) on validation
 * errors, so callers can rely on a single error channel (.catch / try-await).
 */
export class StorageFacade implements OkintStorage {
  constructor(private readonly impl: StorageBackend) {}

  get backend(): BackendKind {
    return this.impl.kind;
  }

  async getString(key: string): Promise<string | null> {
    assertKey(key);
    return this.impl.getString(key);
  }

  async setString(key: string, value: string): Promise<void> {
    assertKey(key);
    assertStringValue(value);
    return this.impl.setString(key, value);
  }

  async getItem<T>(key: string): Promise<T | null> {
    assertKey(key);
    const raw = await this.impl.getString(key);
    return raw == null ? null : fromJson<T>(key, raw);
  }

  async setItem<T>(key: string, value: T): Promise<void> {
    assertKey(key);
    return this.impl.setString(key, toJson(key, value));
  }

  async getNumber(key: string): Promise<number | null> {
    assertKey(key);
    const raw = await this.impl.getString(key);
    return raw == null ? null : stringToNumber(raw);
  }

  async setNumber(key: string, value: number): Promise<void> {
    assertKey(key);
    return this.impl.setString(key, numberToString(key, value));
  }

  async getBoolean(key: string): Promise<boolean | null> {
    assertKey(key);
    const raw = await this.impl.getString(key);
    return raw == null ? null : stringToBoolean(raw);
  }

  async setBoolean(key: string, value: boolean): Promise<void> {
    assertKey(key);
    return this.impl.setString(key, value ? 'true' : 'false');
  }

  async has(key: string): Promise<boolean> {
    assertKey(key);
    return (await this.impl.getString(key)) !== null;
  }

  async remove(key: string): Promise<void> {
    assertKey(key);
    return this.impl.remove(key);
  }

  clear(): Promise<void> {
    return this.impl.clear();
  }

  keys(): Promise<string[]> {
    return this.impl.keys();
  }

  async multiGet(keys: string[]): Promise<Record<string, string | null>> {
    const out: Record<string, string | null> = {};
    await Promise.all(
      keys.map(async (k) => {
        assertKey(k);
        out[k] = await this.impl.getString(k);
      }),
    );
    return out;
  }

  async multiSet(entries: Record<string, string>): Promise<void> {
    await Promise.all(
      Object.entries(entries).map(([k, v]) => {
        assertKey(k);
        assertStringValue(v);
        return this.impl.setString(k, v);
      }),
    );
  }

  async multiRemove(keys: string[]): Promise<void> {
    await Promise.all(
      keys.map((k) => {
        assertKey(k);
        return this.impl.remove(k);
      }),
    );
  }
}
