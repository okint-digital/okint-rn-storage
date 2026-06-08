import type { BackendKind, StorageBackend } from '../types';

/**
 * Pure-JS, in-process backend. Zero native dependencies. Data lives only for the
 * lifetime of the instance — ideal for tests, ephemeral caches, and as a safe
 * default before the native module is available.
 */
export class MemoryBackend implements StorageBackend {
  readonly kind: BackendKind;
  private readonly store = new Map<string, string>();

  constructor(kind: BackendKind = 'memory') {
    this.kind = kind;
  }

  async getString(key: string): Promise<string | null> {
    return this.store.has(key) ? (this.store.get(key) as string) : null;
  }

  async setString(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }

  async remove(key: string): Promise<void> {
    this.store.delete(key);
  }

  async clear(): Promise<void> {
    this.store.clear();
  }

  async keys(): Promise<string[]> {
    return [...this.store.keys()];
  }
}
