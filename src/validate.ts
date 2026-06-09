import { OkintStorageError } from './errors';

/**
 * Namespace becomes an Android SharedPreferences FILE NAME, an iOS Keychain
 * service / UserDefaults suite, AND the suffix of a native SQLite table name
 * (`kv_<ns>` / `enc_<ns>`). The native table builders only preserve
 * `[A-Za-z0-9_]` and collapse every other character to `_`. If the JS charset
 * were any wider than that, two DISTINCT namespaces (e.g. `a.b` and `a-b`)
 * would collapse to the SAME table and silently share / overwrite / wipe each
 * other's data — breaking the "namespaces never collide" guarantee.
 *
 * So the charset is intentionally restricted to EXACTLY the set the strictest
 * native sink preserves verbatim: `[A-Za-z0-9_]`. With this charset the native
 * sanitizer is a provable no-op, so the JS→native mapping is injective and no
 * two namespaces can ever collide. `.`, `-`, `/`, `..`, NUL, spaces, etc. are
 * rejected. (Native code re-validates this independently as defense-in-depth.)
 */
const NAMESPACE_RE = /^[A-Za-z0-9_]{1,200}$/;

const MAX_KEY_LENGTH = 1024;

/** Validate + default the namespace. Throws on anything unsafe. */
export function normalizeNamespace(ns: string | undefined, fallback: string): string {
  const value = (typeof ns === 'string' ? ns.trim() : '') || fallback;
  if (!NAMESPACE_RE.test(value)) {
    throw new OkintStorageError(
      'INVALID_NAMESPACE',
      `Invalid namespace "${String(ns)}". Use only letters, digits and "_" (1-200 chars). ` +
        `"." and "-" are not allowed: they collide in native table names and would let ` +
        `distinct namespaces share storage.`,
    );
  }
  return value;
}

/**
 * Validate a key. Keys are stored verbatim (not used as filenames), so the rules
 * are looser than namespaces — but must be a non-empty string free of control
 * characters (NUL etc.), within a sane length.
 */
export function assertKey(key: string): void {
  if (typeof key !== 'string' || key.length === 0) {
    throw new OkintStorageError('INVALID_KEY', 'Key must be a non-empty string.');
  }
  if (key.length > MAX_KEY_LENGTH) {
    throw new OkintStorageError('INVALID_KEY', `Key exceeds the ${MAX_KEY_LENGTH}-character limit.`);
  }
  for (let i = 0; i < key.length; i++) {
    if (key.charCodeAt(i) < 0x20) {
      throw new OkintStorageError('INVALID_KEY', 'Key must not contain control characters.');
    }
  }
}

/** Serialize a value to JSON, surfacing non-serializable inputs as a typed error. */
export function toJson(key: string, value: unknown): string {
  let json: string | undefined;
  try {
    json = JSON.stringify(value);
  } catch (e) {
    throw new OkintStorageError(
      'INVALID_VALUE',
      `Value for "${key}" is not JSON-serializable (circular reference or BigInt).`,
      e,
    );
  }
  if (json === undefined) {
    throw new OkintStorageError(
      'INVALID_VALUE',
      `Value for "${key}" is not JSON-serializable (undefined, function, or symbol).`,
    );
  }
  return json;
}

/** Parse JSON, surfacing malformed data as a typed error. */
export function fromJson<T>(key: string, raw: string): T {
  try {
    return JSON.parse(raw) as T;
  } catch (e) {
    throw new OkintStorageError('PARSE_ERROR', `Stored value for "${key}" is not valid JSON.`, e);
  }
}

/** Serialize a number, rejecting NaN/+-Infinity (which don't round-trip). */
export function numberToString(key: string, value: number): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new OkintStorageError(
      'INVALID_VALUE',
      `setNumber requires a finite number for "${key}" (got ${String(value)}). ` +
        `For integers above 2^53 use setString to avoid precision loss.`,
    );
  }
  return String(value);
}

/**
 * Canonical decimal/scientific form, matching exactly what `String(number)`
 * produces for a finite number (`-0` stringifies to `"0"`). We validate the
 * TEXT first, before coercion, so that non-canonical inputs do NOT silently
 * coerce: `Number("")`/`Number("  ")` are `0`, `Number("0x10")` is `16`,
 * `Number("1,000")`/`Number("Infinity")` surprise too. `getNumber` must report
 * "non-numeric → null", so anything outside this canonical form returns null.
 */
const CANONICAL_NUMBER_RE = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/;

/** Parse a stored number; anything not in canonical numeric form -> null. */
export function stringToNumber(raw: string): number | null {
  if (typeof raw !== 'string' || !CANONICAL_NUMBER_RE.test(raw)) return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}

/** Strict boolean parse: only canonical 'true'/'false' map; anything else -> null. */
export function stringToBoolean(raw: string): boolean | null {
  return raw === 'true' ? true : raw === 'false' ? false : null;
}

/** Assert a raw value is a string (for setString / multiSet). */
export function assertStringValue(value: unknown): asserts value is string {
  if (typeof value !== 'string') {
    throw new OkintStorageError('INVALID_VALUE', 'Value must be a string.');
  }
}
