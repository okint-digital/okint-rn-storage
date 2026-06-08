package com.okint.rnstorage

import android.content.Context
import android.content.SharedPreferences
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStoreFile
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableMap
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
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
 *   - "secure"    → Google Tink AEAD (per-namespace keyset wrapped by an
 *                   AndroidKeystore master key) over Jetpack DataStore. Replaces
 *                   the deprecated androidx.security `EncryptedSharedPreferences`.
 *   - "async"     → plain SharedPreferences (fast, unencrypted).
 *   - "encrypted" → values AES-256-GCM encrypted with a per-namespace
 *                   AndroidKeystore key, ciphertext stored in a SQLite table.
 *                   Handles large encrypted blobs and many entries.
 *   - "sqlite"    → plaintext values in a per-namespace SQLite table.
 *
 * Plus a blocking-synchronous bulk read (`getEntriesSync`) that powers the
 * zero-load `createSyncStorageSync` path.
 *
 * NOTE: native code is written against current AndroidX/Tink/Keystore APIs; it is
 * verified at app build time (no Gradle/NDK in the authoring environment).
 */
class OkintRnStorageModule(private val reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  init {
    AeadConfig.register()
  }

  override fun getName(): String = NAME

  // ── Dispatch ────────────────────────────────────────────────────────────────

  @ReactMethod
  fun setItem(service: String, key: String, value: String, store: String, promise: Promise) {
    try {
      when (store) {
        STORE_SECURE -> runBlocking {
          secureStore(service).edit { it[stringPreferencesKey(key)] = encodeAead(service, value) }
        }
        STORE_ENCRYPTED -> sqliteSet(service, key, encrypt(service, value))
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
        STORE_SECURE -> runBlocking { secureStore(service).edit { it.remove(stringPreferencesKey(key)) } }
        STORE_ENCRYPTED, STORE_SQLITE ->
          sqliteExec(service, "DELETE FROM ${table(service)} WHERE k=?", arrayOf(key))
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
        STORE_SECURE -> runBlocking { secureStore(service).edit { it.clear() } }
        STORE_ENCRYPTED, STORE_SQLITE -> sqliteExec(service, "DELETE FROM ${table(service)}", emptyArray())
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

  // ── Shared read helpers ──────────────────────────────────────────────────────

  private fun readOne(service: String, key: String, store: String): String? = when (store) {
    STORE_SECURE -> runBlocking {
      secureStore(service).data.first()[stringPreferencesKey(key)]?.let { decodeAead(service, it) }
    }
    STORE_ENCRYPTED -> sqliteGet(service, key)?.let { decrypt(service, it) }
    STORE_SQLITE -> sqliteGet(service, key)
    else -> asyncPrefs(service).getString(key, null)
  }

  private fun allKeys(service: String, store: String): List<String> = when (store) {
    STORE_SECURE -> runBlocking {
      secureStore(service).data.first().asMap().keys.map { it.name }
    }
    STORE_ENCRYPTED, STORE_SQLITE -> sqliteKeys(service)
    else -> asyncPrefs(service).all.keys.toList()
  }

  // ── async (plain SharedPreferences) ──────────────────────────────────────────

  private val prefsCache = ConcurrentHashMap<String, SharedPreferences>()

  private fun asyncPrefs(service: String): SharedPreferences =
    prefsCache.getOrPut("okint_$service") {
      reactContext.getSharedPreferences("okint_$service", Context.MODE_PRIVATE)
    }

  // ── secure (Tink AEAD + DataStore) ───────────────────────────────────────────

  private val dataStores = ConcurrentHashMap<String, DataStore<Preferences>>()
  private val aeads = ConcurrentHashMap<String, Aead>()

  private fun secureStore(service: String): DataStore<Preferences> =
    dataStores.getOrPut(service) {
      PreferenceDataStoreFactory.create(
        corruptionHandler = androidx.datastore.core.handlers.ReplaceFileCorruptionHandler { emptyPreferences() },
      ) { reactContext.preferencesDataStoreFile("okint_secure_$service") }
    }

  @Synchronized
  private fun secureAead(service: String): Aead = aeads.getOrPut(service) {
    AndroidKeysetManager.Builder()
      .withSharedPref(reactContext, "okint_tink_$service", "okint_tink_pref_$service")
      .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
      .withMasterKeyUri("android-keystore://okint_tink_mk_$service")
      .build()
      .keysetHandle
      .getPrimitive(Aead::class.java)
  }

  private fun encodeAead(service: String, plaintext: String): String =
    Base64.encodeToString(secureAead(service).encrypt(plaintext.toByteArray(Charsets.UTF_8), EMPTY_AAD), Base64.NO_WRAP)

  private fun decodeAead(service: String, b64: String): String =
    String(secureAead(service).decrypt(Base64.decode(b64, Base64.NO_WRAP), EMPTY_AAD), Charsets.UTF_8)

  // ── encrypted (AES-256-GCM with a per-namespace Keystore key, over SQLite) ────

  private fun encKey(service: String): SecretKey {
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

  // ── SQLite (backs encrypted + sqlite stores) ──────────────────────────────────

  private val dbHelper: SQLiteOpenHelper by lazy {
    object : SQLiteOpenHelper(reactContext, "okint_sqlite.db", null, 1) {
      override fun onCreate(db: SQLiteDatabase) {}
      override fun onUpgrade(db: SQLiteDatabase, oldV: Int, newV: Int) {}
    }
  }

  private fun table(service: String): String = "kv_" + service.replace(Regex("[^A-Za-z0-9_]"), "_")

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
    private const val STORE_ASYNC = "async"
    private const val STORE_ENCRYPTED = "encrypted"
    private const val STORE_SQLITE = "sqlite"
    private val EMPTY_AAD = ByteArray(0)
  }
}
