import { OkintStorageError } from './errors';

/**
 * Namespace becomes an Android SharedPreferences FILE NAME and an iOS Keychain
 * service / UserDefaults suite. It must therefore be filename-safe — no path
 * separators, `..`, NUL, or other characters that could traverse or collide.
 * Restrict to a conservative charset.
 */
const NAMESPACE_RE = /^[A-Za-z0-9._-]{1,200}$/;

const MAX_KEY_LENGTH = 1024;

/** Validate + default the namespace. Throws on anything unsafe. */
export function normalizeNamespace(ns: string | undefined, fallback: string): string {
  const value = (typeof ns === 'string' ? ns.trim() : '') || fallback;
  if (!NAMESPACE_RE.test(value)) {
    throw new OkintStorageError(
      'INVALID_NAMESPACE',
      `Invalid namespace "${String(ns)}". Use only letters, digits, "." "-" "_" (1-200 chars).`,
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

/** Parse a stored number; non-numeric -> null. */
export function stringToNumber(raw: string): number | null {
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
