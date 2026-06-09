import {
  normalizeNamespace,
  assertKey,
  toJson,
  numberToString,
  stringToBoolean,
  stringToNumber,
} from '../validate';
import { OkintStorageError } from '../errors';

const NUL = String.fromCharCode(0);
const TAB = String.fromCharCode(9);

describe('normalizeNamespace', () => {
  it('accepts safe namespaces and trims', () => {
    expect(normalizeNamespace('auth', 'okint')).toBe('auth');
    expect(normalizeNamespace('  app_cache_1  ', 'okint')).toBe('app_cache_1');
  });

  it('defaults when empty/whitespace/undefined', () => {
    expect(normalizeNamespace(undefined, 'okint')).toBe('okint');
    expect(normalizeNamespace('   ', 'okint')).toBe('okint');
  });

  it('rejects path separators and traversal (filename-injection)', () => {
    for (const bad of ['../evil', 'a/b', 'a\\b', 'foo bar', 'x;y', 'name@1']) {
      expect(() => normalizeNamespace(bad, 'okint')).toThrow(OkintStorageError);
    }
  });

  it('rejects "." and "-" — they collapse to "_" in native table names and would let distinct namespaces collide', () => {
    // Regression for the namespace-collision finding: "a.b", "a-b", "a_b" all
    // map to table kv_a_b / enc_a_b natively. Only "_" is allowed, so the
    // JS→native mapping is injective and collisions are impossible.
    for (const bad of ['a.b', 'a-b', 'app.cache', 'app-cache', '.', '..', '...', 'a..b']) {
      expect(() => normalizeNamespace(bad, 'okint')).toThrow(OkintStorageError);
    }
    expect(normalizeNamespace('a_b', 'okint')).toBe('a_b'); // the safe equivalent
  });

  it('rejects over-long namespaces', () => {
    expect(() => normalizeNamespace('a'.repeat(201), 'okint')).toThrow(/INVALID_NAMESPACE|namespace/i);
  });
});

describe('assertKey', () => {
  it('accepts normal keys incl. colons/slashes/spaces (stored verbatim)', () => {
    for (const ok of ['k', 'user:123', 'a/b', 'with space']) {
      expect(() => assertKey(ok)).not.toThrow();
    }
  });

  it('rejects empty / non-string / control chars', () => {
    expect(() => assertKey('')).toThrow(OkintStorageError);
    expect(() => assertKey(123 as unknown as string)).toThrow(OkintStorageError);
    expect(() => assertKey('a' + NUL + 'b')).toThrow(OkintStorageError);
    expect(() => assertKey('a' + TAB + 'b')).toThrow(OkintStorageError);
  });
});

describe('toJson', () => {
  it('rejects undefined / function / symbol', () => {
    expect(() => toJson('k', undefined)).toThrow(OkintStorageError);
    expect(() => toJson('k', () => {})).toThrow(OkintStorageError);
    expect(() => toJson('k', Symbol('x'))).toThrow(OkintStorageError);
  });

  it('rejects circular references and BigInt', () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => toJson('k', circular)).toThrow(OkintStorageError);
    expect(() => toJson('k', BigInt(1) as unknown)).toThrow(OkintStorageError);
  });

  it('serializes valid values', () => {
    expect(toJson('k', { a: 1 })).toBe('{"a":1}');
    expect(toJson('k', null)).toBe('null');
  });
});

describe('numberToString', () => {
  it('rejects NaN / Infinity / -Infinity', () => {
    expect(() => numberToString('k', NaN)).toThrow(OkintStorageError);
    expect(() => numberToString('k', Infinity)).toThrow(OkintStorageError);
    expect(() => numberToString('k', -Infinity)).toThrow(OkintStorageError);
  });

  it('round-trips finite numbers', () => {
    expect(numberToString('k', 42)).toBe('42');
    expect(numberToString('k', -3.14)).toBe('-3.14');
  });
});

describe('stringToNumber (strict canonical form)', () => {
  it('round-trips everything setNumber/String(number) can produce', () => {
    for (const n of [0, -0, 1, -1, 42, -3.14, 0.1, 1e21, 1e-7, 1.5e-10, Number.MAX_VALUE, 123456789012345680000]) {
      const round = stringToNumber(numberToString('k', n));
      expect(round).toBe(Number(String(n)));
    }
  });

  it('rejects non-canonical / non-numeric strings (no silent coercion)', () => {
    // Number("") === 0, Number("  ") === 0, Number("0x10") === 16,
    // Number("Infinity") === Infinity — all must map to null, not a surprise.
    for (const bad of ['', '   ', '\t', '0x10', '1,000', ' 5 ', '5 ', '007', '+5', 'Infinity', '-Infinity', 'NaN', '1e', '.5', '5.', '0b1']) {
      expect(stringToNumber(bad)).toBeNull();
    }
  });

  it('parses canonical decimals', () => {
    expect(stringToNumber('42')).toBe(42);
    expect(stringToNumber('-3.14')).toBe(-3.14);
    expect(stringToNumber('0')).toBe(0);
    expect(stringToNumber('1e+21')).toBe(1e21);
  });
});

describe('stringToBoolean (strict)', () => {
  it('only maps canonical true/false', () => {
    expect(stringToBoolean('true')).toBe(true);
    expect(stringToBoolean('false')).toBe(false);
    expect(stringToBoolean('1')).toBeNull();
    expect(stringToBoolean('TRUE')).toBeNull();
    expect(stringToBoolean('')).toBeNull();
  });
});
