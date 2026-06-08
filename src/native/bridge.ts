import { NativeModules } from 'react-native';
import type { NativeOkintStorage } from '../types';
import { OkintStorageError } from '../errors';

/**
 * Resolves the native module. This is the ONLY file that imports `react-native`,
 * so the rest of the package (facade, backends, types) stays runtime-agnostic
 * and unit-testable under Node.
 *
 * Uses the classic NativeModules registry (works on both the legacy and the New
 * Architecture via the interop layer). If the module isn't present — e.g. the
 * app wasn't rebuilt after install — we throw a clear, actionable error rather
 * than failing deep in a call.
 */
export function getNativeModule(): NativeOkintStorage {
  const mod = (NativeModules as Record<string, unknown>)['OkintRnStorage'] as
    | NativeOkintStorage
    | undefined;

  if (!mod) {
    throw new OkintStorageError(
      'NATIVE_MODULE_MISSING',
      "okint-rn-storage native module not found. Rebuild the app after install " +
        "(pod install on iOS / gradle sync on Android), or use backend: 'memory'.",
    );
  }
  return mod;
}
