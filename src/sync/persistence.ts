import type { StorageBackend, SyncPersistence } from '../types';

/** No-op persistence for the ephemeral `memory` sync store. */
export class MemorySyncPersistence implements SyncPersistence {
  async loadAll(): Promise<Record<string, string>> {
    return {};
  }
  async persist(): Promise<void> {
    /* nothing to persist */
  }
  async clearAll(): Promise<void> {
    /* nothing to clear */
  }
}

/**
 * Persists a sync store to any async StorageBackend (e.g. the native plain
 * store). Pure TS — takes the backend by injection, so it's testable in Node
 * with a MemoryBackend standing in for native.
 */
export class BackendSyncPersistence implements SyncPersistence {
  constructor(private readonly backend: StorageBackend) {}

  async loadAll(): Promise<Record<string, string>> {
    const keys = await this.backend.keys();
    const out: Record<string, string> = {};
    await Promise.all(
      keys.map(async (k) => {
        const v = await this.backend.getString(k);
        if (v !== null) out[k] = v;
      }),
    );
    return out;
  }

  async persist(key: string, value: string | null): Promise<void> {
    if (value === null) {
      await this.backend.remove(key);
    } else {
      await this.backend.setString(key, value);
    }
  }

  async clearAll(): Promise<void> {
    await this.backend.clear();
  }
}
