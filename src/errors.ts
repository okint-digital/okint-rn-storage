export type OkintStorageErrorCode =
  | 'NATIVE_MODULE_MISSING'
  | 'BACKEND_NOT_IMPLEMENTED'
  | 'UNKNOWN_BACKEND'
  | 'PARSE_ERROR'
  | 'INVALID_VALUE'
  | 'INVALID_NAMESPACE'
  | 'INVALID_KEY'
  | 'NATIVE_ERROR';

/**
 * Single error type for the whole package. Carries a stable `code` so callers
 * can branch without string-matching messages.
 */
export class OkintStorageError extends Error {
  readonly code: OkintStorageErrorCode;

  constructor(code: OkintStorageErrorCode, message: string, cause?: unknown) {
    // `cause` is carried by the native Error.cause (ES2022) — we don't redeclare it.
    super(message, cause !== undefined ? { cause } : undefined);
    this.name = 'OkintStorageError';
    this.code = code;
    // Restore prototype chain (TS targeting ES5/ES2015 class-extends-builtin caveat).
    Object.setPrototypeOf(this, OkintStorageError.prototype);
  }
}
