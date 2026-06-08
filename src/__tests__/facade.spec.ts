import { StorageFacade } from '../facade';
import { MemoryBackend } from '../backends/memory';
import { OkintStorageError } from '../errors';

function makeStorage() {
  return new StorageFacade(new MemoryBackend('memory'));
}

describe('StorageFacade', () => {
  it('exposes the backing backend kind', () => {
    expect(makeStorage().backend).toBe('memory');
  });

  it('round-trips strings', async () => {
    const s = makeStorage();
    expect(await s.getString('k')).toBeNull();
    await s.setString('k', 'hello');
    expect(await s.getString('k')).toBe('hello');
  });

  it('round-trips JSON via getItem/setItem', async () => {
    const s = makeStorage();
    const obj = { a: 1, b: ['x', 'y'], c: { d: true } };
    await s.setItem('obj', obj);
    expect(await s.getItem<typeof obj>('obj')).toEqual(obj);
  });

  it('round-trips numbers and booleans', async () => {
    const s = makeStorage();
    await s.setNumber('n', 42);
    await s.setBoolean('flag', true);
    expect(await s.getNumber('n')).toBe(42);
    expect(await s.getBoolean('flag')).toBe(true);
    await s.setBoolean('flag', false);
    expect(await s.getBoolean('flag')).toBe(false);
  });

  it('returns null for missing typed keys', async () => {
    const s = makeStorage();
    expect(await s.getItem('nope')).toBeNull();
    expect(await s.getNumber('nope')).toBeNull();
    expect(await s.getBoolean('nope')).toBeNull();
  });

  it('returns null for a non-numeric value read as number', async () => {
    const s = makeStorage();
    await s.setString('n', 'not-a-number');
    expect(await s.getNumber('n')).toBeNull();
  });

  it('throws PARSE_ERROR on malformed JSON', async () => {
    const s = makeStorage();
    await s.setString('bad', '{ not json');
    await expect(s.getItem('bad')).rejects.toMatchObject({
      name: 'OkintStorageError',
      code: 'PARSE_ERROR',
    });
  });

  it('rejects with INVALID_VALUE when setString gets a non-string', async () => {
    const s = makeStorage();
    await expect(s.setString('k', 123 as unknown as string)).rejects.toBeInstanceOf(OkintStorageError);
  });

  it('has() reflects presence', async () => {
    const s = makeStorage();
    expect(await s.has('k')).toBe(false);
    await s.setString('k', 'v');
    expect(await s.has('k')).toBe(true);
  });

  it('remove() and clear() work; keys() lists entries', async () => {
    const s = makeStorage();
    await s.setString('a', '1');
    await s.setString('b', '2');
    expect((await s.keys()).sort()).toEqual(['a', 'b']);
    await s.remove('a');
    expect(await s.has('a')).toBe(false);
    expect((await s.keys())).toEqual(['b']);
    await s.clear();
    expect(await s.keys()).toEqual([]);
  });
});
