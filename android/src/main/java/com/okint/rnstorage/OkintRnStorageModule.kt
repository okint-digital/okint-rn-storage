package com.okint.rnstorage

import android.content.Context
import android.content.SharedPreferences
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * okint-rn-storage — Android native module. One module, four stores selected by
 * the `store` argument:
 *
 *   - "secure"    → EncryptedSharedPreferences; per-namespace Keystore master key
 *                   (TEE-backed where available), with conservative crash recovery.
 *   - "async"     → plain SharedPreferences (fast, unencrypted).
 *   - "encrypted" → values AES-256-GCM encrypted with a per-namespace AndroidKeystore
 *                   key, ciphertext stored in plain SharedPreferences. Handles large
 *                   blobs that exceed practical Keystore item sizes.
 *   - "sqlite"    → a per-namespace SQLite key/value table.
 *
 * Each store is partitioned by namespace, so stores never collide.
 *
 * NOTE: native code is written against current Android/Keystore APIs; it is
 * verified at app build time (no Gradle/NDK in the authoring environment).
 */
class OkintRnStorageModule(private val reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  override fun getName(): String = NAME

  private val cache = ConcurrentHashMap<String, SharedPreferences>()
  private val recovered = ConcurrentHashMap.newKeySet<String>()

  // ── Dispatch ──────────────────────────────────────────────────────────────

  @ReactMethod
  fun setItem(service: String, key: String, value: String, store: String, promise: Promise) {
    try {
      if (store == STORE_SQLITE) {
        sqliteSet(service, key, value)
        promise.resolve(null)
        return
      }
      val stored = if (store == STORE_ENCRYPTED) encrypt(service, value) else value
      val ok = prefs(service, store).edit().putString(key, stored).commit()
      if (ok) promise.resolve(null) else promise.reject("E_OKINT_SET", "Failed to persist value.")
    } catch (e: Exception) {
      promise.reject("E_OKINT_SET", e.message, e)
    }
  }

  @ReactMethod
  fun getItem(service: String, key: String, store: String, promise: Promise) {
    try {
      if (store == STORE_SQLITE) {
        promise.resolve(sqliteGet(service, key))
        return
      }
      val raw = prefs(service, store).getString(key, null)
      promise.resolve(if (raw != null && store == STORE_ENCRYPTED) decrypt(service, raw) else raw)
    } catch (e: Exception) {
      promise.reject("E_OKINT_GET", e.message, e)
    }
  }

  @ReactMethod
  fun removeItem(service: String, key: String, store: String, promise: Promise) {
    try {
      if (store == STORE_SQLITE) {
        sqliteExec(service, "DELETE FROM ${table(service)} WHERE k=?", arrayOf(key))
        promise.resolve(null)
        return
      }
      val ok = prefs(service, store).edit().remove(key).commit()
      if (ok) promise.resolve(null) else promise.reject("E_OKINT_REMOVE", "Failed to remove key.")
    } catch (e: Exception) {
      promise.reject("E_OKINT_REMOVE", e.message, e)
    }
  }

  @ReactMethod
  fun clear(service: String, store: String, promise: Promise) {
    try {
      if (store == STORE_SQLITE) {
        sqliteExec(service, "DELETE FROM ${table(service)}", emptyArray())
        promise.resolve(null)
        return
      }
      val ok = prefs(service, store).edit().clear().commit()
      if (ok) promise.resolve(null) else promise.reject("E_OKINT_CLEAR", "Failed to clear store.")
    } catch (e: Exception) {
      promise.reject("E_OKINT_CLEAR", e.message, e)
    }
  }

  @ReactMethod
  fun getAllKeys(service: String, store: String, promise: Promise) {
    try {
      val arr = Arguments.createArray()
      if (store == STORE_SQLITE) {
        for (k in sqliteKeys(service)) arr.pushString(k)
      } else {
        for (k in prefs(service, store).all.keys) arr.pushString(k)
      }
      promise.resolve(arr)
    } catch (e: Exception) {
      promise.reject("E_OKINT_KEYS", e.message, e)
    }
  }

  // ── SharedPreferences (secure / async / encrypted) ──────────────────────────

  private fun fileName(service: String, store: String): String = when (store) {
    STORE_SECURE -> "okint_secure_$service"
    STORE_ENCRYPTED -> "okint_enc_$service"
    else -> "okint_$service" // async
  }

  private fun masterKeyAlias(file: String): String = "okint_mk_$file"

  @Synchronized
  private fun prefs(service: String, store: String): SharedPreferences {
    val file = fileName(service, store)
    cache[file]?.let { return it }
    val created =
      if (store == STORE_SECURE) openSecure(file)
      else reactContext.getSharedPreferences(file, Context.MODE_PRIVATE)
    cache[file] = created
    return created
  }

  private fun openSecure(file: String): SharedPreferences {
    try {
      return createEncryptedPrefs(file)
    } catch (e: Throwable) {
      if (!isRecoverable(e) || !recovered.add(file)) throw e
      deletePrefsFile(file)
      try {
        return createEncryptedPrefs(file)
      } catch (e2: Throwable) {
        if (!isRecoverable(e2)) throw e2
        deleteMasterKey(masterKeyAlias(file))
        deletePrefsFile(file)
        return createEncryptedPrefs(file)
      }
    }
  }

  private fun createEncryptedPrefs(file: String): SharedPreferences {
    val masterKey = MasterKey.Builder(reactContext, masterKeyAlias(file))
      .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
      .build()
    return EncryptedSharedPreferences.create(
      reactContext,
      file,
      masterKey,
      EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
      EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
  }

  private fun isRecoverable(t: Throwable): Boolean {
    var cur: Throwable? = t
    var depth = 0
    while (cur != null && depth < 10) {
      val name = cur.javaClass.simpleName
      if (name == "AEADBadTagException" ||
        name == "InvalidProtocolBufferException" ||
        name == "KeyPermanentlyInvalidatedException"
      ) {
        return true
      }
      cur = cur.cause
      depth++
    }
    return false
  }

  private fun deletePrefsFile(file: String) {
    cache.remove(file)
    try {
      reactContext.deleteSharedPreferences(file)
    } catch (ignored: Throwable) {
    }
  }

  private fun deleteMasterKey(alias: String) {
    try {
      val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
      ks.load(null)
      if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    } catch (ignored: Throwable) {
    }
  }

  // ── Encrypted (AES-256-GCM with a per-namespace Keystore key) ───────────────

  private fun encKey(service: String): SecretKey {
    val alias = "okint_enckey_$service"
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
    ks.load(null)
    (ks.getKey(alias, null) as? SecretKey)?.let { return it }
    val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
    kg.init(
      KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
      )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .build(),
    )
    return kg.generateKey()
  }

  private fun encrypt(service: String, plaintext: String): String {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, encKey(service))
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
    cipher.init(Cipher.DECRYPT_MODE, encKey(service), GCMParameterSpec(128, iv))
    return String(cipher.doFinal(ct), Charsets.UTF_8)
  }

  // ── SQLite (per-namespace key/value table) ──────────────────────────────────

  private val dbHelper: SQLiteOpenHelper by lazy {
    object : SQLiteOpenHelper(reactContext, "okint_sqlite.db", null, 1) {
      override fun onCreate(db: SQLiteDatabase) {}
      override fun onUpgrade(db: SQLiteDatabase, oldV: Int, newV: Int) {}
    }
  }

  private fun table(service: String): String =
    "kv_" + service.replace(Regex("[^A-Za-z0-9_]"), "_")

  private fun ensureTable(db: SQLiteDatabase, service: String) {
    db.execSQL("CREATE TABLE IF NOT EXISTS ${table(service)} (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
  }

  @Synchronized
  private fun sqliteSet(service: String, key: String, value: String) {
    val db = dbHelper.writableDatabase
    ensureTable(db, service)
    db.execSQL("INSERT OR REPLACE INTO ${table(service)} (k, v) VALUES (?, ?)", arrayOf(key, value))
  }

  @Synchronized
  private fun sqliteGet(service: String, key: String): String? {
    val db = dbHelper.readableDatabase
    ensureTable(db, service)
    db.rawQuery("SELECT v FROM ${table(service)} WHERE k = ?", arrayOf(key)).use { c ->
      return if (c.moveToFirst()) c.getString(0) else null
    }
  }

  @Synchronized
  private fun sqliteExec(service: String, sql: String, args: Array<String>) {
    val db = dbHelper.writableDatabase
    ensureTable(db, service)
    if (args.isEmpty()) db.execSQL(sql) else db.execSQL(sql, args)
  }

  @Synchronized
  private fun sqliteKeys(service: String): List<String> {
    val db = dbHelper.readableDatabase
    ensureTable(db, service)
    val keys = ArrayList<String>()
    db.rawQuery("SELECT k FROM ${table(service)}", emptyArray()).use { c ->
      while (c.moveToNext()) keys.add(c.getString(0))
    }
    return keys
  }

  companion object {
    const val NAME = "OkintRnStorage"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val STORE_SECURE = "secure"
    private const val STORE_ENCRYPTED = "encrypted"
    private const val STORE_SQLITE = "sqlite"
  }
}
