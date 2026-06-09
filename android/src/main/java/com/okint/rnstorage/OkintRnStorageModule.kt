package com.okint.rnstorage

import android.content.Context
import android.content.SharedPreferences
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
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
  fun setItem(service: String, key: String, value: String, store: String, promise: Promise) {
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
  fun getItem(service: String, key: String, store: String, promise: Promise) {
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

  private fun asyncPrefs(service: String): SharedPreferences = prefs("okint_$service")

  private fun securePrefs(service: String): SharedPreferences = prefs("okint_secure_$service")

  // ── Crypto core (AES-256-GCM + HMAC token, rooted in AndroidKeystore) ────────

  private fun aesKey(service: String): SecretKey {
    val alias = "okint_enckey_$service"
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
    ks.load(null)
    (ks.getKey(alias, null) as? SecretKey)?.let { return it }
    val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
    kg.init(
      KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .build(),
    )
    return kg.generateKey()
  }

  private fun hmacKey(service: String): SecretKey {
    val alias = "okint_enchmac_$service"
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
    ks.load(null)
    (ks.getKey(alias, null) as? SecretKey)?.let { return it }
    val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
    kg.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN).build())
    return kg.generateKey()
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
    val ivLen = data[0].toInt() and 0xFF
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

  // ── encrypted store (enc_ table: HMAC token + encrypted key + encrypted value)

  private fun encTable(service: String): String = "enc_" + service.replace(Regex("[^A-Za-z0-9_]"), "_")

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

  private fun kvTable(service: String): String = "kv_" + service.replace(Regex("[^A-Za-z0-9_]"), "_")

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
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val STORE_SECURE = "secure"
    private const val STORE_ASYNC = "async"
    private const val STORE_ENCRYPTED = "encrypted"
    private const val STORE_SQLITE = "sqlite"
  }
}
