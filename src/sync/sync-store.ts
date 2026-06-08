import type { OkintSyncStorage, SyncBackendKind, SyncPersistence } from '../types';
import { OkintStorageError } from '../errors';
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
 * Synchronous storage over an in-memory snapshot. After `load()`, every accessor
 * is synchronous; writes update the map immediately and are persisted to the
 * backing `SyncPersistence` in the background.
 *
 * Persistence is **coalesced**: a burst of writes collapses to the latest value
 * per key and is drained once per microtask (bounded by the number of distinct
 * dirty keys, not the number of writes). `flush()` awaits durability and
 * surfaces any background failure.
 */
export class OkintSyncStore implements OkintSyncStorage {
  readonly backend: SyncBackendKind;
  private map = new Map<string, string>();
  private loaded = false;

  // Coalescing state.
  private pending = new Map<string, string | null>(); // value === null → delete
  private pendingClear = false;
  private drainScheduled = false;
  private chain: Promise<void> = Promise.resolve();
  private persistErrors: unknown[] = [];

  constructor(
    backend: SyncBackendKind,
    private readonly persistence: SyncPersistence,
  ) {
    this.backend = backend;
  }

  /** Load the snapshot. Idempotent — the factory calls it once; extra calls no-op. */
  async load(): Promise<void> {
    if (this.loaded) return;
    const all = await this.persistence.loadAll();
    this.map = new Map(Object.entries(all));
    this.loaded = true;
  }

  getString(key: string): string | null {
    assertKey(key);
    const v = this.map.get(key);
    return v === undefined ? null : v;
  }

  setString(key: string, value: string): void {
    assertKey(key);
    assertStringValue(value);
    this.map.set(key, value);
    this.queueWrite(key, value);
  }

  getItem<T>(key: string): T | null {
    const raw = this.getString(key);
    return raw == null ? null : fromJson<T>(key, raw);
  }

  setItem<T>(key: string, value: T): void {
    assertKey(key);
    const json = toJson(key, value);
    this.map.set(key, json);
    this.queueWrite(key, json);
  }

  getNumber(key: string): number | null {
    const raw = this.getString(key);
    return raw == null ? null : stringToNumber(raw);
  }

  setNumber(key: string, value: number): void {
    assertKey(key);
    const s = numberToString(key, value);
    this.map.set(key, s);
    this.queueWrite(key, s);
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
    return this.map.has(key);
  }

  remove(key: string): void {
    assertKey(key);
    this.map.delete(key);
    this.queueWrite(key, null);
  }

  clear(): void {
    this.map.clear();
    this.pending.clear(); // superseded by the clear
    this.pendingClear = true;
    this.schedule();
  }

  keys(): string[] {
    return [...this.map.keys()];
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
    if ((this.pending.size > 0 || this.pendingClear) && !this.drainScheduled) {
      this.schedule();
    }
    await this.chain;
    if (this.persistErrors.length > 0) {
      const first = this.persistErrors[0];
      const count = this.persistErrors.length;
      this.persistErrors = [];
      throw new OkintStorageError(
        'NATIVE_ERROR',
        `${count} background persist operation(s) failed.`,
        first,
      );
    }
  }

  private queueWrite(key: string, value: string | null): void {
    this.pending.set(key, value);
    this.schedule();
  }

  private schedule(): void {
    if (this.drainScheduled) return;
    this.drainScheduled = true;
    this.chain = this.chain.then(() => this.drain());
  }

  private async drain(): Promise<void> {
    this.drainScheduled = false;
    const doClear = this.pendingClear;
    this.pendingClear = false;
    const writes = this.pending;
    this.pending = new Map();

    try {
      if (doClear) await this.persistence.clearAll();
      for (const [key, value] of writes) {
        await this.persistence.persist(key, value);
      }
    } catch (e) {
      this.persistErrors.push(e);
    }
  }
}
