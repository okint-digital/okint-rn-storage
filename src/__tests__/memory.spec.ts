import { MemoryBackend } from '../backends/memory';

describe('MemoryBackend', () => {
  it('stores and retrieves verbatim', async () => {
    const b = new MemoryBackend();
    await b.setString('k', 'v');
    expect(await b.getString('k')).toBe('v');
  });

  it('returns null for missing keys', async () => {
    const b = new MemoryBackend();
    expect(await b.getString('missing')).toBeNull();
  });

  it('isolates instances (no shared global state)', async () => {
    const a = new MemoryBackend();
    const b = new MemoryBackend();
    await a.setString('k', 'from-a');
    expect(await b.getString('k')).toBeNull();
  });

  it('carries the kind it was constructed with', () => {
    expect(new MemoryBackend('async').kind).toBe('async');
    expect(new MemoryBackend().kind).toBe('memory');
  });
});
