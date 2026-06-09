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
  // Bounded failure tracking (count + first error) so a never-flushed store with
  // a permanently failing backend can't grow an unbounded error array.
  private persistFailCount = 0;
  private firstPersistError: unknown;
  private warnedPersistError = false;

  constructor(
    backend: SyncBackendKind,
    private readonly persistence: SyncPersistence,
    /**
     * Optional sink for background persist failures. Without it, failures are
     * still retained (surfaced by `flush()`) and warned once via console — but a
     * caller that wants every failure should pass this. Background writes are
     * otherwise invisible: the synchronous setter already returned.
     */
    private readonly onPersistError?: (error: unknown) => void,
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

  /**
   * Synchronous hydration (the zero-load path). Used by `createSyncStorageSync`
   * after one blocking native bulk-read. Idempotent like `load()`.
   */
  loadSync(entries: Record<string, string>): void {
    if (this.loaded) return;
    this.map = new Map(Object.entries(entries));
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
    // Null-prototype map so a key named "__proto__"/"constructor" is a plain
    // own key, not swallowed by the prototype setter. (See facade.multiGet.)
    const out: Record<string, string | null> = Object.create(null);
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
    if (this.persistFailCount > 0) {
      const first = this.firstPersistError;
      const count = this.persistFailCount;
      this.persistFailCount = 0;
      this.firstPersistError = undefined;
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
    // Defense-in-depth: a rejection from drain() must NEVER poison the chain — a
    // permanently-rejected chain would silently stop all future persistence. The
    // trailing catch keeps `this.chain` always-resolving; drain() records its own
    // failures internally (persistFailCount), so nothing is lost by swallowing here.
    this.chain = this.chain.then(() => this.drain()).catch(() => {});
  }

  private async drain(): Promise<void> {
    this.drainScheduled = false;
    const doClear = this.pendingClear;
    this.pendingClear = false;
    const writes = this.pending;
    this.pending = new Map();

    // Re-enqueue an entry for a later retry, but NEVER:
    //  - clobber a value queued AFTER this batch was taken (a newer write wins), or
    //  - resurrect a value a clear() armed DURING this drain has superseded. A
    //    clear() that races in while a persist is awaiting empties `pending` and
    //    sets `pendingClear`; without the `!pendingClear` guard a failed write
    //    would be re-queued and then re-persisted after the clear, bringing back a
    //    key the user explicitly removed (and which is already gone from `map`).
    const requeue = (key: string, value: string | null) => {
      if (!this.pendingClear && !this.pending.has(key)) this.pending.set(key, value);
    };

    if (doClear) {
      try {
        await this.persistence.clearAll();
      } catch (e) {
        // The clear is the first step of "clear then re-apply": if it fails we
        // must re-run the WHOLE sequence, so re-enqueue the batch (these writes
        // come AFTER the clear, so they must survive) and re-arm the clear. Order
        // matters: requeue BEFORE re-arming pendingClear, so the guard above only
        // suppresses writes superseded by a *different* clear that raced in.
        for (const [key, value] of writes) requeue(key, value);
        this.pendingClear = true;
        this.recordPersistError(e);
        return;
      }
    }

    // Persist EVERY write even if one fails — a single bad key must not drop the
    // rest of the coalesced batch (the original bug). Collect failures and
    // re-enqueue them so the next write or flush() retries; never silently lose.
    let firstError: unknown;
    const failed: Array<[string, string | null]> = [];
    for (const [key, value] of writes) {
      try {
        await this.persistence.persist(key, value);
      } catch (e) {
        if (firstError === undefined) firstError = e;
        failed.push([key, value]);
      }
    }
    for (const [key, value] of failed) requeue(key, value);
    if (firstError !== undefined) this.recordPersistError(firstError);
  }

  private recordPersistError(error: unknown): void {
    this.persistFailCount += 1;
    if (this.firstPersistError === undefined) this.firstPersistError = error;
    // The error sink (user callback OR console) must NEVER throw out of here:
    // recordPersistError runs inside drain(), and an escaping throw would reject
    // the persist chain and silently kill all future persistence (total data
    // loss). So the entire sink — including console.warn, which a RN console
    // polyfill could make throw — is wrapped.
    try {
      if (this.onPersistError) {
        this.onPersistError(error);
      } else if (!this.warnedPersistError) {
        // Surface at least once so background data loss is never fully silent,
        // even when the caller never calls flush(). Subsequent failures are
        // counted (persistFailCount) and reported by flush().
        this.warnedPersistError = true;
        // eslint-disable-next-line no-console
        console.warn(
          'okint-rn-storage: a background persist failed; data is kept in memory and ' +
            'will be retried on the next write or flush(). Call flush() to observe durability.',
          error,
        );
      }
    } catch {
      /* durability must not depend on a working console / callback */
    }
  }
}
