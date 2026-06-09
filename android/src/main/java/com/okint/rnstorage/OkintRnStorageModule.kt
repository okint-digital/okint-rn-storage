package com.okint.rnstorage

import android.content.Context
import android.content.SharedPreferences
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableMap
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * okint-rn-storage — Android native module. One module, four stores, ZERO
 * third-party dependencies (only the Android platform + AndroidKeystore):
 *
 *   - "secure"    → AES-256-GCM with a per-namespace, non-exportable
 *                   AndroidKeystore key (hardware-backed where available);
 *                   ciphertext lives in plain SharedPreferences. This is the
 *                   construction EncryptedSharedPreferences used internally,
 *                   without the deprecated androidx.security dependency. A
 *                   decrypt failure (restored backup, invalidated key) returns
 *                   null instead of crashing at launch — crash-recovery built in.
 *   - "async"     → plain SharedPreferences (fast, unencrypted).
 *   - "encrypted" → a fully-encrypted SQLite table: both KEYS and VALUES are
 *                   AES-256-GCM encrypted; lookups use a deterministic HMAC
 *                   token (Keystore HMAC key). No plaintext in the database — an
 *                   encrypted DB with no SQLCipher dependency, sized for large
 *                   blobs / many entries.
 *   - "sqlite"    → plaintext values in a separate SQLite table.
 *
 * Plus a blocking-sync bulk read (`getEntriesSync`) and a C++/JSI fast-path
 * installer (`installJSI`).
 *
 * NOTE: native code is written against the stable Android crypto/Keystore APIs
 * and verified at app build time (no Gradle/NDK in the authoring environment).
 */
class OkintRnStorageModule(private val reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  override fun getName(): String = NAME

  // ── Dispatch ────────────────────────────────────────────────────────────────

  @ReactMethod
  fun setItem(service: String, key: String, value: String, store: String, requireAuth: Boolean, promise: Promise) {
    if (store == STORE_SECURE && requireAuth) {
      secureSetAuth(service, key, value, promise)
      return
    }
    try {
      when (store) {
        STORE_SECURE -> securePrefs(service).edit().putString(key, encrypt(service, value)).commit()
        STORE_ENCRYPTED -> encSet(service, key, value)
        STORE_SQLITE -> sqliteSet(service, key, value)
        else -> asyncPrefs(service).edit().putString(key, value).commit()
      }
      promise.resolve(null)
    } catch (e: Exception) {
      promise.reject("E_OKINT_SET", e.message, e)
    }
  }

  @ReactMethod
  fun getItem(service: String, key: String, store: String, requireAuth: Boolean, promise: Promise) {
    if (store == STORE_SECURE && requireAuth) {
      secureGetAuth(service, key, promise)
      return
    }
    try {
      promise.resolve(readOne(service, key, store))
    } catch (e: Exception) {
      promise.reject("E_OKINT_GET", e.message, e)
    }
  }

  @ReactMethod
  fun removeItem(service: String, key: String, store: String, promise: Promise) {
    try {
      when (store) {
        STORE_SECURE -> securePrefs(service).edit().remove(key).commit()
        STORE_ENCRYPTED -> encExec(service, "DELETE FROM ${encTable(service)} WHERE kt=?", arrayOf(token(service, key)))
        STORE_SQLITE -> sqliteExec(service, "DELETE FROM ${kvTable(service)} WHERE k=?", arrayOf(key))
        else -> asyncPrefs(service).edit().remove(key).commit()
      }
      promise.resolve(null)
    } catch (e: Exception) {
      promise.reject("E_OKINT_REMOVE", e.message, e)
    }
  }

  @ReactMethod
  fun clear(service: String, store: String, promise: Promise) {
    try {
      when (store) {
        STORE_SECURE -> securePrefs(service).edit().clear().commit()
        STORE_ENCRYPTED -> encExec(service, "DELETE FROM ${encTable(service)}", emptyArray())
        STORE_SQLITE -> sqliteExec(service, "DELETE FROM ${kvTable(service)}", emptyArray())
        else -> asyncPrefs(service).edit().clear().commit()
      }
      promise.resolve(null)
    } catch (e: Exception) {
      promise.reject("E_OKINT_CLEAR", e.message, e)
    }
  }

  @ReactMethod
  fun getAllKeys(service: String, store: String, promise: Promise) {
    try {
      val arr = Arguments.createArray()
      for (k in allKeys(service, store)) arr.pushString(k)
      promise.resolve(arr)
    } catch (e: Exception) {
      promise.reject("E_OKINT_KEYS", e.message, e)
    }
  }

  /** Blocking-synchronous bulk read for the zero-load sync store. */
  @ReactMethod(isBlockingSynchronousMethod = true)
  fun getEntriesSync(service: String, store: String): WritableMap {
    val map = Arguments.createMap()
    try {
      when (store) {
        STORE_ASYNC -> for ((k, v) in asyncPrefs(service).all) {
          if (v is String) map.putString(k, v)
        }
        else -> for (k in allKeys(service, store)) {
          readOne(service, k, store)?.let { map.putString(k, it) }
        }
      }
    } catch (ignored: Exception) {
    }
    return map
  }

  /** Install the C++/JSI fast-path engine. Returns false if the runtime is unreachable. */
  @ReactMethod(isBlockingSynchronousMethod = true)
  fun installJSI(): Boolean {
    return try {
      val ptr = reactContext.javaScriptContextHolder?.get() ?: return false
      if (ptr == 0L) return false
      nativeInstallJSI(ptr, reactContext.filesDir.absolutePath)
      true
    } catch (e: Throwable) {
      false
    }
  }

  private external fun nativeInstallJSI(jsiPtr: Long, dir: String)

  // ── Shared read helpers ──────────────────────────────────────────────────────

  private fun readOne(service: String, key: String, store: String): String? = when (store) {
    STORE_SECURE -> securePrefs(service).getString(key, null)?.let { decryptOrNull(service, it) }
    STORE_ENCRYPTED -> encGet(service, key)
    STORE_SQLITE -> sqliteGet(service, key)
    else -> asyncPrefs(service).getString(key, null)
  }

  private fun allKeys(service: String, store: String): List<String> = when (store) {
    STORE_SECURE -> securePrefs(service).all.keys.toList()
    STORE_ENCRYPTED -> encKeys(service)
    STORE_SQLITE -> sqliteKeys(service)
    else -> asyncPrefs(service).all.keys.toList()
  }

  // ── SharedPreferences (secure ciphertext + async plaintext) ──────────────────

  private val prefsCache = ConcurrentHashMap<String, SharedPreferences>()

  private fun prefs(name: String): SharedPreferences =
    prefsCache.getOrPut(name) { reactContext.getSharedPreferences(name, Context.MODE_PRIVATE) }

  /**
   * Defense-in-depth: the JS layer restricts namespaces to [A-Za-z0-9_], but the
   * native module is also reachable directly via NativeModules. Re-validate so a
   * direct caller cannot pass "." / "-" — which would otherwise collapse to "_" in
   * the SQLite table name and let two distinct namespaces share one table.
   */
  private fun assertSafeService(service: String) {
    require(SAFE_SERVICE.matches(service)) { "Invalid namespace (allowed: [A-Za-z0-9_], 1-200 chars)" }
  }

  private fun asyncPrefs(service: String): SharedPreferences {
    assertSafeService(service)
    return prefs("okint_$service")
  }

  private fun securePrefs(service: String): SharedPreferences {
    assertSafeService(service)
    return prefs("okint_secure_$service")
  }

  // ── Crypto core (AES-256-GCM + HMAC token, rooted in AndroidKeystore) ────────

  private fun loadKey(alias: String): SecretKey? {
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
    ks.load(null)
    return ks.getKey(alias, null) as? SecretKey
  }

  /**
   * Generate a Keystore key, preferring the dedicated **StrongBox** secure
   * element (Titan M / SE) when present and falling back to the TEE otherwise.
   * Some devices advertise StrongBox but fail at generation time, so we catch
   * broadly on the StrongBox attempt and retry without it — the documented
   * pattern. Existing keys are loaded by alias first, so this never re-keys an
   * install; only brand-new keys gain StrongBox backing.
   */
  private fun aesKey(service: String): SecretKey {
    val alias = "okint_enckey_$service"
    loadKey(alias)?.let { return it }
    return generateAesKey(alias, strongBox = true) ?: generateAesKey(alias, strongBox = false)!!
  }

  private fun generateAesKey(alias: String, strongBox: Boolean): SecretKey? = try {
    val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
    val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
    if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setIsStrongBoxBacked(true)
    kg.init(builder.build())
    kg.generateKey()
  } catch (e: Exception) {
    if (strongBox) null else throw e
  }

  private fun hmacKey(service: String): SecretKey {
    val alias = "okint_enchmac_$service"
    loadKey(alias)?.let { return it }
    return generateHmacKey(alias, strongBox = true) ?: generateHmacKey(alias, strongBox = false)!!
  }

  private fun generateHmacKey(alias: String, strongBox: Boolean): SecretKey? = try {
    val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
    val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
    if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setIsStrongBoxBacked(true)
    kg.init(builder.build())
    kg.generateKey()
  } catch (e: Exception) {
    if (strongBox) null else throw e
  }

  private fun token(service: String, key: String): String {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(hmacKey(service))
    return Base64.encodeToString(mac.doFinal(key.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
  }

  private fun encrypt(service: String, plaintext: String): String {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, aesKey(service))
    val iv = cipher.iv
    val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
    val out = ByteArray(1 + iv.size + ct.size)
    out[0] = iv.size.toByte()
    System.arraycopy(iv, 0, out, 1, iv.size)
    System.arraycopy(ct, 0, out, 1 + iv.size, ct.size)
    return Base64.encodeToString(out, Base64.NO_WRAP)
  }

  private fun decrypt(service: String, b64: String): String {
    val data = Base64.decode(b64, Base64.NO_WRAP)
    // Bounds-check the [ivLen|iv|ct] framing before slicing so malformed/corrupt
    // input fails closed (caught by decryptOrNull → null) instead of throwing an
    // index exception. GCM IV is 12 bytes; allow 12..16 defensively.
    require(data.size >= 2) { "ciphertext too short" }
    val ivLen = data[0].toInt() and 0xFF
    require(ivLen in 12..16 && 1 + ivLen < data.size) { "bad IV framing" }
    val iv = data.copyOfRange(1, 1 + ivLen)
    val ct = data.copyOfRange(1 + ivLen, data.size)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, aesKey(service), GCMParameterSpec(128, iv))
    return String(cipher.doFinal(ct), Charsets.UTF_8)
  }

  /** Decrypt that tolerates a lost/rotated key (restored backup) — returns null, never crashes. */
  private fun decryptOrNull(service: String, b64: String): String? = try {
    decrypt(service, b64)
  } catch (e: Exception) {
    null
  }

  // ── secure + requireAuth (biometric-gated AES key, per-operation CryptoObject)
  //
  // Opt-in path (createStorage({ backend:'secure', requireAuth:true })). The AES
  // key is `setUserAuthenticationRequired`, so every encrypt/decrypt must run
  // through a framework BiometricPrompt bound to the operation's Cipher. Uses a
  // distinct key alias so it never collides with the non-gated secure key;
  // ciphertext lives in the same SharedPreferences file, so remove/clear/keys
  // work unchanged. Strong biometric only (CryptoObject can't combine with
  // device-credential); API 28+. NOTE: the BiometricPrompt UI cannot be
  // exercised without a real device — this path is build-verified on-device.

  private fun secureAuthAesKey(service: String): SecretKey {
    val alias = "okint_secauth_$service"
    loadKey(alias)?.let { return it }
    return generateAuthAesKey(alias, strongBox = true) ?: generateAuthAesKey(alias, strongBox = false)!!
  }

  private fun generateAuthAesKey(alias: String, strongBox: Boolean): SecretKey? = try {
    val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
    val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setUserAuthenticationRequired(true)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      // Timeout 0 → every use requires a fresh auth via CryptoObject.
      builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
    }
    if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setIsStrongBoxBacked(true)
    kg.init(builder.build())
    kg.generateKey()
  } catch (e: Exception) {
    if (strongBox) null else throw e
  }

  private fun secureSetAuth(service: String, key: String, value: String, promise: Promise) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
      promise.reject("E_OKINT_AUTH", "requireAuth needs Android 9 (API 28)+")
      return
    }
    try {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.ENCRYPT_MODE, secureAuthAesKey(service))
      authenticate(cipher, "Authenticate to save", promise) { authed ->
        val iv = authed.iv
        val ct = authed.doFinal(value.toByteArray(Charsets.UTF_8))
        val out = ByteArray(1 + iv.size + ct.size)
        out[0] = iv.size.toByte()
        System.arraycopy(iv, 0, out, 1, iv.size)
        System.arraycopy(ct, 0, out, 1 + iv.size, ct.size)
        securePrefs(service).edit().putString(key, Base64.encodeToString(out, Base64.NO_WRAP)).commit()
        null
      }
    } catch (e: Exception) {
      promise.reject("E_OKINT_SET", e.message, e)
    }
  }

  private fun secureGetAuth(service: String, key: String, promise: Promise) {
    // securePrefs() validates the namespace and can throw; this runs before the
    // try below (and getItem dispatches here before ITS try), so reject cleanly
    // rather than letting the throw escape and leave the promise unsettled.
    val raw = try {
      securePrefs(service).getString(key, null)
    } catch (e: Exception) {
      promise.reject("E_OKINT_GET", e.message, e)
      return
    }
    if (raw == null) {
      promise.resolve(null)
      return
    }
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
      promise.reject("E_OKINT_AUTH", "requireAuth needs Android 9 (API 28)+")
      return
    }
    try {
      val data = Base64.decode(raw, Base64.NO_WRAP)
      require(data.size >= 2) { "ciphertext too short" }
      val ivLen = data[0].toInt() and 0xFF
      require(ivLen in 12..16 && 1 + ivLen < data.size) { "bad IV framing" }
      val iv = data.copyOfRange(1, 1 + ivLen)
      val ct = data.copyOfRange(1 + ivLen, data.size)
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.DECRYPT_MODE, secureAuthAesKey(service), GCMParameterSpec(128, iv))
      authenticate(cipher, "Authenticate to access", promise) { authed ->
        String(authed.doFinal(ct), Charsets.UTF_8)
      }
    } catch (e: Exception) {
      promise.reject("E_OKINT_GET", e.message, e)
    }
  }

  /**
   * Present a framework BiometricPrompt bound to [cipher]; on success run
   * [onAuthed] with the authenticated cipher and resolve [promise] with its
   * result. Runs on the UI thread (BiometricPrompt requirement).
   */
  @androidx.annotation.RequiresApi(Build.VERSION_CODES.P)
  private fun authenticate(cipher: Cipher, title: String, promise: Promise, onAuthed: (Cipher) -> String?) {
    // The current Activity lives on the React context, not on the module base class.
    val activity = reactContext.currentActivity
    if (activity == null) {
      promise.reject("E_OKINT_AUTH", "No foreground Activity to present the authentication prompt")
      return
    }
    activity.runOnUiThread {
      try {
        val executor = activity.mainExecutor
        val builder = android.hardware.biometrics.BiometricPrompt.Builder(activity).setTitle(title)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          builder.setAllowedAuthenticators(android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG)
        } else {
          builder.setNegativeButton("Cancel", executor) { _, _ ->
            promise.reject("E_OKINT_AUTH_CANCELLED", "Authentication cancelled")
          }
        }
        val prompt = builder.build()
        val crypto = android.hardware.biometrics.BiometricPrompt.CryptoObject(cipher)
        prompt.authenticate(
          crypto,
          android.os.CancellationSignal(),
          executor,
          object : android.hardware.biometrics.BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: android.hardware.biometrics.BiometricPrompt.AuthenticationResult) {
              try {
                val authedCipher = result.cryptoObject?.cipher ?: cipher
                promise.resolve(onAuthed(authedCipher))
              } catch (e: Exception) {
                promise.reject("E_OKINT_AUTH_CRYPTO", e.message, e)
              }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
              promise.reject("E_OKINT_AUTH", errString.toString())
            }
          },
        )
      } catch (e: Exception) {
        promise.reject("E_OKINT_AUTH", e.message, e)
      }
    }
  }

  // ── encrypted store (enc_ table: HMAC token + encrypted key + encrypted value)

  // Service is validated to [A-Za-z0-9_] (assertSafeService), so it is used
  // verbatim in the table name — injective, no lossy collapse, no collision.
  private fun encTable(service: String): String {
    assertSafeService(service)
    return "enc_$service"
  }

  private fun ensureEnc(db: SQLiteDatabase, service: String) {
    db.execSQL("CREATE TABLE IF NOT EXISTS ${encTable(service)} (kt TEXT PRIMARY KEY, ke TEXT NOT NULL, ve TEXT NOT NULL)")
  }

  @Synchronized
  private fun encSet(service: String, key: String, value: String) {
    val db = dbHelper.writableDatabase
    ensureEnc(db, service)
    db.execSQL(
      "INSERT OR REPLACE INTO ${encTable(service)} (kt, ke, ve) VALUES (?, ?, ?)",
      arrayOf(token(service, key), encrypt(service, key), encrypt(service, value)),
    )
  }

  @Synchronized
  private fun encGet(service: String, key: String): String? {
    val db = dbHelper.readableDatabase
    ensureEnc(db, service)
    db.rawQuery("SELECT ve FROM ${encTable(service)} WHERE kt = ?", arrayOf(token(service, key))).use { c ->
      return if (c.moveToFirst()) decryptOrNull(service, c.getString(0)) else null
    }
  }

  @Synchronized
  private fun encExec(service: String, sql: String, args: Array<String>) {
    val db = dbHelper.writableDatabase
    ensureEnc(db, service)
    if (args.isEmpty()) db.execSQL(sql) else db.execSQL(sql, args)
  }

  @Synchronized
  private fun encKeys(service: String): List<String> {
    val db = dbHelper.readableDatabase
    ensureEnc(db, service)
    val keys = ArrayList<String>()
    db.rawQuery("SELECT ke FROM ${encTable(service)}", emptyArray()).use { c ->
      while (c.moveToNext()) decryptOrNull(service, c.getString(0))?.let { keys.add(it) }
    }
    return keys
  }

  // ── sqlite store (plaintext key/value table) ──────────────────────────────────

  private val dbHelper: SQLiteOpenHelper by lazy {
    object : SQLiteOpenHelper(reactContext, "okint_sqlite.db", null, 1) {
      override fun onCreate(db: SQLiteDatabase) {}
      override fun onUpgrade(db: SQLiteDatabase, oldV: Int, newV: Int) {}
    }
  }

  private fun kvTable(service: String): String {
    assertSafeService(service)
    return "kv_$service"
  }

  private fun ensureKv(db: SQLiteDatabase, service: String) {
    db.execSQL("CREATE TABLE IF NOT EXISTS ${kvTable(service)} (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
  }

  @Synchronized
  private fun sqliteSet(service: String, key: String, value: String) {
    val db = dbHelper.writableDatabase
    ensureKv(db, service)
    db.execSQL("INSERT OR REPLACE INTO ${kvTable(service)} (k, v) VALUES (?, ?)", arrayOf(key, value))
  }

  @Synchronized
  private fun sqliteGet(service: String, key: String): String? {
    val db = dbHelper.readableDatabase
    ensureKv(db, service)
    db.rawQuery("SELECT v FROM ${kvTable(service)} WHERE k = ?", arrayOf(key)).use { c ->
      return if (c.moveToFirst()) c.getString(0) else null
    }
  }

  @Synchronized
  private fun sqliteExec(service: String, sql: String, args: Array<String>) {
    val db = dbHelper.writableDatabase
    ensureKv(db, service)
    if (args.isEmpty()) db.execSQL(sql) else db.execSQL(sql, args)
  }

  @Synchronized
  private fun sqliteKeys(service: String): List<String> {
    val db = dbHelper.readableDatabase
    ensureKv(db, service)
    val keys = ArrayList<String>()
    db.rawQuery("SELECT k FROM ${kvTable(service)}", emptyArray()).use { c ->
      while (c.moveToNext()) keys.add(c.getString(0))
    }
    return keys
  }

  companion object {
    init {
      try {
        System.loadLibrary("okint")
      } catch (ignored: Throwable) {
        // JSI engine optional — installJSI() returns false if the lib is absent.
      }
    }

    const val NAME = "OkintRnStorage"
    private val SAFE_SERVICE = Regex("^[A-Za-z0-9_]{1,200}$")
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val STORE_SECURE = "secure"
    private const val STORE_ASYNC = "async"
    private const val STORE_ENCRYPTED = "encrypted"
    private const val STORE_SQLITE = "sqlite"
  }
}
