/**
 * okint-rn-storage — public types.
 *
 * One async API, several swappable backends. Pick the backend per the data's
 * needs: secrets → `secure` (hardware Keystore / Keychain); large/plain data →
 * `async`; ephemeral → `memory`. `encrypted` and `sqlite` are on the roadmap.
 */

export type BackendKind = 'memory' | 'secure' | 'async' | 'encrypted' | 'sqlite';

export interface OkintStorageOptions {
  /** Which storage backend to use. */
  backend: BackendKind;
  /**
   * Logical store name. Partitions data so two stores never collide. Maps to:
   *   - secure  → Keychain service (iOS) / EncryptedSharedPreferences file (Android)
   *   - async   → UserDefaults suite (iOS) / SharedPreferences file (Android)
   *   - memory  → a private in-process Map
   * Defaults to `'okint'`.
   */
  namespace?: string;
}

/**
 * Low-level backend contract. Everything is async (the secure/native backends
 * cross the bridge). Keys reaching a backend are already partitioned by
 * namespace at construction, so backends store keys verbatim.
 */
export interface StorageBackend {
  readonly kind: BackendKind;
  getString(key: string): Promise<string | null>;
  setString(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
  clear(): Promise<void>;
  keys(): Promise<string[]>;
}

/**
 * The storage instance returned by `createStorage`. Adds ergonomic typed
 * accessors (JSON / number / boolean) on top of the raw string backend.
 */
export interface OkintStorage {
  /** The backend kind backing this instance. */
  readonly backend: BackendKind;

  getString(key: string): Promise<string | null>;
  setString(key: string, value: string): Promise<void>;

  /** JSON-parsed read. Throws OkintStorageError('PARSE_ERROR') on malformed data. */
  getItem<T>(key: string): Promise<T | null>;
  /** JSON-stringified write. */
  setItem<T>(key: string, value: T): Promise<void>;

  getNumber(key: string): Promise<number | null>;
  setNumber(key: string, value: number): Promise<void>;

  getBoolean(key: string): Promise<boolean | null>;
  setBoolean(key: string, value: boolean): Promise<void>;

  has(key: string): Promise<boolean>;
  remove(key: string): Promise<void>;
  clear(): Promise<void>;
  keys(): Promise<string[]>;

  /** Batched string reads/writes/removes. */
  multiGet(keys: string[]): Promise<Record<string, string | null>>;
  multiSet(entries: Record<string, string>): Promise<void>;
  multiRemove(keys: string[]): Promise<void>;
}

// ──────────────────────────────────────────────────────────────────────────
// Synchronous stores (the MMKV-style use case)
//
// React Native's bridge is async, so true zero-latency sync needs JSI. Instead
// of reinventing MMKV's C++, the `fast` store loads a snapshot once (async),
// then serves get/set SYNCHRONOUSLY from memory while persisting writes in the
// background. Covers the dominant sync need — persist/rehydrate, flags, cached
// UI state — with no native risk. `memory` is ephemeral sync (no persistence).
// ──────────────────────────────────────────────────────────────────────────

export type SyncBackendKind = 'memory' | 'fast';

export interface OkintSyncStorageOptions {
  backend: SyncBackendKind;
  /** Partitions the store (see OkintStorageOptions.namespace). Defaults to 'okint'. */
  namespace?: string;
}

/**
 * A synchronous storage instance. Obtained via `await createSyncStorage(...)`,
 * which resolves only after the initial snapshot has loaded — so every method
 * below is safe to call synchronously thereafter.
 */
export interface OkintSyncStorage {
  readonly backend: SyncBackendKind;

  getString(key: string): string | null;
  setString(key: string, value: string): void;

  getItem<T>(key: string): T | null;
  setItem<T>(key: string, value: T): void;

  getNumber(key: string): number | null;
  setNumber(key: string, value: number): void;

  getBoolean(key: string): boolean | null;
  setBoolean(key: string, value: boolean): void;

  has(key: string): boolean;
  remove(key: string): void;
  clear(): void;
  keys(): string[];

  /** Batched (synchronous) reads/writes/removes. */
  multiGet(keys: string[]): Record<string, string | null>;
  multiSet(entries: Record<string, string>): void;
  multiRemove(keys: string[]): void;

  /**
   * Await pending background writes (the `fast` store persists asynchronously).
   * Call on app background / before exit for guaranteed durability. Rejects if a
   * background persist failed.
   */
  flush(): Promise<void>;
}

/** Persistence sink for sync stores. Snapshot load + per-key write-through. */
export interface SyncPersistence {
  loadAll(): Promise<Record<string, string>>;
  /** value === null → delete the key. */
  persist(key: string, value: string | null): Promise<void>;
  clearAll(): Promise<void>;
}

/**
 * Shape of the native module (Android/iOS). The JS layer talks to this; tests
 * inject a fake implementation. `secure=true` selects the hardware-backed store.
 */
export interface NativeOkintStorage {
  setItem(service: string, key: string, value: string, secure: boolean): Promise<void>;
  getItem(service: string, key: string, secure: boolean): Promise<string | null>;
  removeItem(service: string, key: string, secure: boolean): Promise<void>;
  clear(service: string, secure: boolean): Promise<void>;
  getAllKeys(service: string, secure: boolean): Promise<string[]>;
}
