import type { JSIStore, OkintSyncStorage, SyncBackendKind } from '../types';
import {
  assertKey,
  assertStringValue,
  fromJson,
  numberToString,
  stringToBoolean,
  stringToNumber,
  toJson,
} from '../validate';

/**
 * OkintSyncStorage backed by the C++/JSI HostObject. Reads and writes go
 * straight into C++ with no bridge serialization and no snapshot — the
 * maximum-performance synchronous path. Writes are persisted synchronously by
 * the native engine, so `flush()` is a no-op.
 */
export class JSISyncStore implements OkintSyncStorage {
  readonly backend: SyncBackendKind = 'fast';

  constructor(private readonly store: JSIStore) {}

  getString(key: string): string | null {
    assertKey(key);
    return this.store.getString(key);
  }

  setString(key: string, value: string): void {
    assertKey(key);
    assertStringValue(value);
    this.store.setString(key, value);
  }

  getItem<T>(key: string): T | null {
    const raw = this.getString(key);
    return raw == null ? null : fromJson<T>(key, raw);
  }

  setItem<T>(key: string, value: T): void {
    assertKey(key);
    this.store.setString(key, toJson(key, value));
  }

  getNumber(key: string): number | null {
    const raw = this.getString(key);
    return raw == null ? null : stringToNumber(raw);
  }

  setNumber(key: string, value: number): void {
    assertKey(key);
    this.store.setString(key, numberToString(key, value));
  }

  getBoolean(key: string): boolean | null {
    const raw = this.getString(key);
    return raw == null ? null : stringToBoolean(raw);
  }

  setBoolean(key: string, value: boolean): void {
    this.setString(key, value ? 'true' : 'false');
  }

  has(key: string): boolean {
    assertKey(key);
    return this.store.contains(key);
  }

  remove(key: string): void {
    assertKey(key);
    this.store.remove(key);
  }

  clear(): void {
    this.store.clear();
  }

  keys(): string[] {
    return this.store.getAllKeys();
  }

  multiGet(keys: string[]): Record<string, string | null> {
    const out: Record<string, string | null> = {};
    for (const k of keys) out[k] = this.getString(k);
    return out;
  }

  multiSet(entries: Record<string, string>): void {
    for (const [k, v] of Object.entries(entries)) this.setString(k, v);
  }

  multiRemove(keys: string[]): void {
    for (const k of keys) this.remove(k);
  }

  async flush(): Promise<void> {
    // The JSI engine persists synchronously on each write — nothing to flush.
  }
}
