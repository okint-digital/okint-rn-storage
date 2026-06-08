# okint-rn-storage

> One async storage API for React Native. Swappable backends — hardware
> **Keystore/Keychain** for secrets, **SharedPreferences/UserDefaults** for plain
> data, or **in-memory** for ephemerals. No third-party runtime dependencies.

Built by **Okint**. Designed to be the simple, dependable storage layer you reach
for instead of juggling `react-native-keychain` + `react-native-encrypted-storage`
+ `async-storage` + an MMKV wrapper.

## Why

- **One API, many backends.** Choose per data sensitivity at init — same calls everywhere.
- **Secrets in hardware.** `secure` keeps the encryption key in the Android Keystore /
  iOS Keychain (hardware-backed where available). Right home for JWTs, refresh & FCM tokens.
- **Vanilla.** Zero JS runtime deps. The native module is ours (Kotlin + Swift),
  no transitive native libraries beyond AndroidX Security.
- **Typed & async.** Promise-based, fully typed, with JSON / number / boolean helpers.

## Install

```sh
npm install okint-rn-storage
# iOS
cd ios && pod install
# Android: autolinked. Rebuild the app.
```

Requires React Native 0.73+ (AGP 8 `namespace`, Java 17). Works on the legacy
and the New Architecture (via the interop layer).

## Usage

```ts
import { createStorage } from 'okint-rn-storage';

// Secrets → hardware-backed Keystore / Keychain
const auth = createStorage({ backend: 'secure', namespace: 'auth' });
await auth.setString('refreshToken', token);
const token = await auth.getString('refreshToken');
await auth.setItem('fcm', { token: t, platform: 'android' }); // JSON helper

// Plain persistent data → SharedPreferences / UserDefaults
const prefs = createStorage({ backend: 'async', namespace: 'prefs' });
await prefs.setBoolean('onboarded', true);

// Ephemeral / tests → in-memory, zero native
const cache = createStorage({ backend: 'memory' });

// SYNCHRONOUS store (the MMKV-style use case) — load once, then sync everywhere.
import { createSyncStorage } from 'okint-rn-storage';
const fast = await createSyncStorage({ backend: 'fast', namespace: 'app' });
fast.setBoolean('onboarded', true);              // sync write (persists in background)
const onboarded = fast.getBoolean('onboarded');  // sync read — no await
await fast.flush();                              // optional: guarantee durability
```

### API

Every instance implements:

| Method | Notes |
|---|---|
| `getString / setString` | raw strings |
| `getItem<T> / setItem<T>` | JSON (throws `PARSE_ERROR` on malformed read) |
| `getNumber / setNumber` | numbers |
| `getBoolean / setBoolean` | booleans |
| `has(key)` | presence check |
| `remove(key)` · `clear()` · `keys()` | |
| `multiGet / multiSet / multiRemove` | batched string ops |
| `backend` | the backing `BackendKind` |

All methods return Promises and **reject** (never throw synchronously) on
invalid input. `namespace` partitions stores so they never collide.

### Input validation

- **Namespace** becomes a file/service name → restricted to `[A-Za-z0-9._-]`
  (1–200 chars); `../`, `/`, spaces, etc. are rejected (`INVALID_NAMESPACE`) to
  prevent filename injection / cross-store collisions.
- **Keys** must be non-empty strings without control characters (`INVALID_KEY`).
- **`setNumber`** rejects `NaN`/`±Infinity` (they don't round-trip). Numbers are
  IEEE-754 doubles — for integers above 2^53 (e.g. snowflake IDs) use `setString`.
- **`setItem`** rejects non-JSON-serializable values (`undefined`, functions,
  symbols, circular refs, BigInt) with `INVALID_VALUE` instead of corrupting.
- **`getBoolean`** is strict: only canonical `"true"`/`"false"` map; anything
  else returns `null`.

## Backends

| Kind | Android | iOS | Encrypted | Use for |
|---|---|---|---|---|
| `secure` | EncryptedSharedPreferences (Keystore master key) | Keychain (`kSecClassGenericPassword`) | ✅ hardware | JWTs, refresh/FCM tokens, secrets |
| `async` | SharedPreferences | UserDefaults suite | ❌ | large / non-sensitive data |
| `memory` | — (pure JS) | — (pure JS) | n/a | ephemeral cache, tests |
| `fast` (sync) | SharedPreferences snapshot | UserDefaults snapshot | ❌ | **synchronous** state/flags/cache (MMKV-style) — via `createSyncStorage` |
| `encrypted` | AES-256-GCM (Keystore key) + plain prefs | Keychain (dedicated service) | ✅ hardware key | larger encrypted blobs (bigger headroom than `secure`) |
| `sqlite` | SQLite key/value table | SQLite (`sqlite3`) key/value table | ❌ | larger datasets, SQL-backed key/value |

All five backends are implemented. On Android, `encrypted` wraps values in
AES-256-GCM using a per-namespace AndroidKeystore key and stores the ciphertext
in plain SharedPreferences (so it isn't bound by Keystore item sizes); on iOS it
uses the Keychain under a dedicated service (so it shares the Keychain size
envelope — use Android for very large iOS-incompatible blobs, or `sqlite`).

### Synchronous (`fast`) store

`createStorage` is async (correct for `secure` — never block the UI thread on
Keystore crypto). For the MMKV-style **synchronous** need — persist/rehydrate,
feature flags, hot-path UI state — use `createSyncStorage`:

- It loads a snapshot **once** (the `await` on `createSyncStorage`), then every
  `get`/`set` is **synchronous**.
- Writes apply to memory immediately and persist in the background; call
  `flush()` (e.g. on app background) for a durability barrier.
- **Trade-off vs MMKV:** okint's sync is snapshot-based (one async load up front;
  background persistence) rather than mmap zero-load. This covers the dominant
  sync use cases with zero native risk. A true zero-load JSI backend is on the
  roadmap. Use `secure` (async) for tokens — never a sync store.

## Compared to alternatives

| | okint-rn-storage | react-native-keychain | react-native-encrypted-storage | expo-secure-store | react-native-mmkv | async-storage |
|---|---|---|---|---|---|---|
| Secure (hardware-backed) | ✅ | ✅ | ✅ | ✅ | ❌ (key in JS) | ❌ |
| Plain persistent store | ✅ (`async`) | ❌ | ❌ | ❌ | ✅ | ✅ |
| Synchronous access | ✅ (`fast`, snapshot) | ❌ | ❌ | ❌ | ✅ (mmap) | ❌ |
| In-memory / test backend | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| One API, swappable backends | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| New Architecture (RN 0.81) | ✅ (interop) | ✅ (TurboModule) | ❌ unmaintained | ✅ | ✅ (v3 requires it) | ✅ |
| Android crash-recovery¹ | ✅ | partial | ❌ | n/a | n/a | n/a |
| Third-party runtime deps | none | none | none | Expo modules | MMKV (C++) | — |
| Maintained (2026) | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |

¹ EncryptedSharedPreferences can corrupt after backup/restore, device transfer, or
Keystore key invalidation — historically a **startup crash** (the gap that sank
`react-native-encrypted-storage`). okint catches it, wipes the corrupt keyset +
master key, and recreates — reads then return `null` so the app re-authenticates
instead of crashing.

**When to use what:** secrets/tokens → `secure` (async, hardware-backed). Big or
non-sensitive data → `async`. Synchronous state/flags/cache → `fast` (via
`createSyncStorage`) — this is okint's MMKV replacement, so you don't need a
separate sync library. Tests/ephemeral → `memory`. One package, every store.

## Errors

All failures throw `OkintStorageError` with a stable `code`:
`NATIVE_MODULE_MISSING` · `BACKEND_NOT_IMPLEMENTED` · `UNKNOWN_BACKEND` ·
`PARSE_ERROR` · `INVALID_VALUE` · `NATIVE_ERROR`.

```ts
import { OkintStorageError } from 'okint-rn-storage';
try { await auth.getItem('x'); }
catch (e) { if (e instanceof OkintStorageError && e.code === 'PARSE_ERROR') { /* … */ } }
```

## Security & reliability

- **Android secure** uses AndroidX `EncryptedSharedPreferences`; the AES-256
  master key lives in the AndroidKeystore (TEE-backed where available), keys
  encrypted AES256-SIV, values AES256-GCM. Writes use `commit()` so a secret is
  durably persisted before the promise resolves.
- **Per-namespace master key:** each secure namespace gets its **own** Keystore
  alias, so a failure or recovery in one namespace can never affect another's
  data (no shared-key blast radius).
- **Conservative, scoped crash recovery (Android):** if a keyset becomes
  unreadable (backup/restore, device transfer, key invalidation —
  `AEADBadTagException` / `InvalidProtocolBufferException` /
  `KeyPermanentlyInvalidatedException`) okint recovers instead of crashing on
  launch: it first drops **only that namespace's** prefs file (recreating the
  keyset under the existing master key); only if that still fails does it drop
  that namespace's master key. Transient errors (device locked, OOM) are **not**
  treated as corruption — they're surfaced, never destroy data. Recovered reads
  return `null`, so the app re-authenticates. (Tink/protobuf keep-rules are
  shipped so R8 minification can't masquerade as corruption.)
- **iOS secure** uses the Keychain with
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` — not synced to iCloud, not
  migrated in encrypted backups, available to background tasks after first
  unlock. Writes are add-or-update (`SecItemUpdate` → `SecItemAdd`). The module
  is Objective-C for maximum build compatibility (no Swift/`use_frameworks!`
  pitfalls).
- Keychain/Keystore are sized for secrets, not megabytes. Store tokens & keys in
  `secure`; store bulk data in `async` (or `encrypted` once shipped).
- **Secrets are never logged** (avoids the class of bug behind CVE-2024-21668 in
  another RN storage lib). Error messages carry key names + OS status codes only.

### Threat model (read this)

Hardware-backed Keystore/Keychain protects secrets **at rest on an uncompromised
device**. It does **not** protect against: rooted/jailbroken devices, runtime
instrumentation (Frida) or memory dumps of a running app, malware running as the
same app, or a handed-over unlocked device. For high-value secrets, pair okint
with root/jailbreak detection and short-lived tokens. okint encrypts on Android
by **default** (unlike libraries that fall back to plaintext SharedPreferences).

## Roadmap

- TurboModule (codegen) implementation for a true zero-load JSI sync path (the
  `fast` store already provides synchronous access via a loaded snapshot).
- SQLCipher option for the `sqlite` backend (encrypted database).
- Android: migrate the `secure` backend off the now-deprecated `security-crypto`
  to Jetpack DataStore + Tink `StreamingAead` (transparent to callers).
- iOS `encrypted`: optional file-protection / app-level AEAD path for very large
  blobs beyond the Keychain size envelope.

## License

MIT © Okint Digital — see [LICENSE](./LICENSE).
