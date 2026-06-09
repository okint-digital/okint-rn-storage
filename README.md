# @okint-digital/okint-rn-storage

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
- **Vanilla.** Zero third-party dependencies — JS or native. The native module is
  ours (Kotlin + Objective-C); all crypto is the platform's own (`javax.crypto` +
  AndroidKeystore / CommonCrypto + Keychain). Nothing to audit but us.
- **Typed & async.** Promise-based, fully typed, with JSON / number / boolean helpers.

## Install

```sh
npm install @okint-digital/okint-rn-storage
# iOS
cd ios && pod install
# Android: autolinked. Rebuild the app.
```

Requires React Native 0.73+ (AGP 8 `namespace`, Java 17). Works on the legacy
and the New Architecture (via the interop layer).

## Usage

```ts
import { createStorage } from '@okint-digital/okint-rn-storage';

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
import { createSyncStorage } from '@okint-digital/okint-rn-storage';
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
| `secure` | AES-256-GCM (Keystore key) over SharedPreferences | Keychain (`kSecClassGenericPassword`) | ✅ hardware | JWTs, refresh/FCM tokens, secrets |
| `async` | SharedPreferences | UserDefaults suite | ❌ | large / non-sensitive data |
| `memory` | — (pure JS) | — (pure JS) | n/a | ephemeral cache, tests |
| `fast` (sync) | SharedPreferences snapshot | UserDefaults snapshot | ❌ | **synchronous** state/flags/cache (MMKV-style) — via `createSyncStorage` |
| `encrypted` | AES-256-GCM keys **and** values (Keystore key) over SQLite | AES-256-CBC + HMAC-SHA256 keys **and** values (key in Keychain) over SQLite | ✅ hardware-rooted key | large encrypted blobs / encrypted DB |
| `sqlite` | SQLite key/value table | SQLite (`sqlite3`) key/value table | ❌ | larger datasets, SQL-backed key/value |

All five backends are implemented. `encrypted` is a genuinely encrypted
database: **both keys and values** are sealed with an authenticated cipher whose
key is rooted in the hardware Keystore/Keychain, and rows are looked up by a
deterministic HMAC token — so nothing readable touches disk, yet it still scales
to large blobs and many entries. No SQLCipher dependency.

### Synchronous (`fast`) store

`createStorage` is async (correct for `secure` — never block the UI thread on
Keystore crypto). For the MMKV-style **synchronous** need — persist/rehydrate,
feature flags, hot-path UI state — use `createSyncStorage`:

- It loads a snapshot **once**, then every `get`/`set` is **synchronous** in-JS
  memory (the fastest possible read path — no per-call bridge crossing).
- Writes apply to memory immediately and persist in the background, **coalesced**
  per key; call `flush()` (e.g. on app background) for a durability barrier.
- **Zero-load variant** — `createSyncStorageSync` hydrates the snapshot in a
  single blocking native bulk-read and returns synchronously, so state is
  available immediately at startup (e.g. before first render):

  ```ts
  import { createSyncStorageSync } from '@okint-digital/okint-rn-storage';
  const fast = createSyncStorageSync({ backend: 'fast', namespace: 'app' });
  const onboarded = fast.getBoolean('onboarded'); // sync, no await, no load step
  ```

- **JSI engine** — `createJSIStorage` installs a C++ `jsi::HostObject` and runs
  every `get`/`set` **directly in C++ with no bridge serialization** — the
  maximum-performance synchronous path, with no JS-memory snapshot:

  ```ts
  import { createJSIStorage } from '@okint-digital/okint-rn-storage';
  const kv = createJSIStorage({ namespace: 'app' });
  kv.setString('theme', 'dark');        // sync, in C++
  const theme = kv.getString('theme');  // sync, in C++
  ```

  It installs lazily on first use and throws a clear error under remote JS
  debugging (no JSI runtime) — fall back to `createSyncStorageSync` there.

  Use `secure` for tokens — never a sync store.

## Compared to alternatives

| | okint-rn-storage | react-native-keychain | react-native-encrypted-storage | expo-secure-store | react-native-mmkv | async-storage |
|---|---|---|---|---|---|---|
| Secure (hardware-backed) | ✅ | ✅ | ✅ | ✅ | ❌ (key in JS) | ❌ |
| Plain persistent store | ✅ (`async`) | ❌ | ❌ | ❌ | ✅ | ✅ |
| Synchronous access | ✅ (`fast` snapshot · zero-load · **C++/JSI**) | ❌ | ❌ | ❌ | ✅ (mmap) | ❌ |
| In-memory / test backend | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| One API, swappable backends | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| New Architecture (RN 0.81) | ✅ (interop) | ✅ (TurboModule) | ❌ unmaintained | ✅ | ✅ (v3 requires it) | ✅ |
| Android crash-recovery¹ | ✅ | partial | ❌ | n/a | n/a | n/a |
| Third-party runtime deps | none | none | none | Expo modules | MMKV (C++) | — |
| Maintained (2026) | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |

¹ Encrypted Android stores can break after backup/restore, device transfer, or
Keystore key invalidation — historically a **startup crash** (the gap that sank
`react-native-encrypted-storage`, which wrapped EncryptedSharedPreferences). okint
never crashes on this: a value that can't be decrypted with the current Keystore
key simply reads back as `null`, so the app re-authenticates instead of dying on
launch.

**When to use what:** secrets/tokens → `secure` (async, hardware-backed). Big or
non-sensitive data → `async`. Synchronous state/flags/cache → `fast` (via
`createSyncStorage`) — this is okint's MMKV replacement, so you don't need a
separate sync library. Tests/ephemeral → `memory`. One package, every store.

## Errors

All failures throw `OkintStorageError` with a stable `code`:
`NATIVE_MODULE_MISSING` · `BACKEND_NOT_IMPLEMENTED` · `UNKNOWN_BACKEND` ·
`PARSE_ERROR` · `INVALID_VALUE` · `NATIVE_ERROR`.

```ts
import { OkintStorageError } from '@okint-digital/okint-rn-storage';
try { await auth.getItem('x'); }
catch (e) { if (e instanceof OkintStorageError && e.code === 'PARSE_ERROR') { /* … */ } }
```

## Security & reliability

- **Android `secure`** encrypts every value with **AES-256-GCM** under a
  per-namespace, non-exportable **AndroidKeystore** key (hardware-backed where the
  device offers it); ciphertext is held in plain SharedPreferences. This is the
  same construction `EncryptedSharedPreferences` used internally — without the
  now-deprecated `androidx.security:security-crypto`, and with **no third-party
  dependency** (Tink, DataStore, etc.). A failed decrypt (restored backup,
  invalidated key) returns `null` rather than crashing on launch.
- **iOS `secure`** uses the Keychain with
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (not iCloud-synced, not in
  encrypted backups, available to background tasks after first unlock) + the
  data-protection keychain. Writes are add-or-update (`SecItemUpdate` →
  `SecItemAdd`). The module is Objective-C for maximum build compatibility (no
  Swift / `use_frameworks!` pitfalls).
- **`encrypted`** authenticates as well as encrypts, and seals **both keys and
  values**: Android AES-256-GCM (per-namespace Keystore key); iOS AES-256-CBC +
  HMAC-SHA256 encrypt-then-MAC (96-byte key in the Keychain, constant-time MAC
  check). Rows are addressed by a deterministic HMAC token, so the database holds
  no readable key or value, yet scales to large blobs and many entries.
- Keychain/Keystore are sized for secrets, not megabytes. Store tokens & keys in
  `secure`; store bulk data in `async`, or encrypted bulk data in `encrypted`.
- **Secrets are never logged** (avoids the class of bug behind CVE-2024-21668 in
  another RN storage lib). Error messages carry key names + OS status codes only.

### Threat model (read this)

Hardware-backed Keystore/Keychain protects secrets **at rest on an uncompromised
device**. It does **not** protect against: rooted/jailbroken devices, runtime
instrumentation (Frida) or memory dumps of a running app, malware running as the
same app, or a handed-over unlocked device. For high-value secrets, pair okint
with root/jailbreak detection and short-lived tokens. okint encrypts on Android
by **default** (unlike libraries that fall back to plaintext SharedPreferences).

## License

MIT © Okint Digital — see [LICENSE](./LICENSE).
