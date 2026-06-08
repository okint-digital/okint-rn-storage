package com.okint.rnstorage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap

/**
 * okint-rn-storage — Android native module.
 *
 *   - secure = true  → EncryptedSharedPreferences. Each namespace gets its OWN
 *                      Keystore master key (per-namespace alias), so a failure in
 *                      one namespace can never affect another's data. Hardware
 *                      (TEE) backed where available. For JWTs / tokens / secrets.
 *   - secure = false → plain SharedPreferences. For large/non-sensitive data.
 *
 * Reliability:
 *  - One cached prefs instance per file (creating EncryptedSharedPreferences
 *    repeatedly is wasteful and has been linked to Tink keyset races).
 *  - Writes use commit() (durable + reports success) rather than apply().
 *  - Corruption recovery is CONSERVATIVE and SCOPED: we only recover on
 *    definitive corruption (AEADBadTagException / InvalidProtocolBufferException /
 *    KeyPermanentlyInvalidatedException) — never on transient errors (device
 *    locked, OOM), which are rethrown so valid data is preserved. Recovery first
 *    drops only the corrupt prefs file (recreating the keyset under the existing
 *    master key); only if that still fails do we drop that namespace's master
 *    key. A per-file sentinel prevents wipe loops within a session.
 *
 * Note: androidx.security:security-crypto is deprecated upstream; this recovery
 * is what mitigates its known crash modes. DataStore + Tink StreamingAead is on
 * the roadmap (transparent to callers).
 */
class OkintRnStorageModule(private val reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  override fun getName(): String = NAME

  private val cache = ConcurrentHashMap<String, SharedPreferences>()
  private val recovered = ConcurrentHashMap.newKeySet<String>()

  private fun fileName(service: String, secure: Boolean): String =
    if (secure) "okint_secure_$service" else "okint_$service"

  private fun masterKeyAlias(file: String): String = "okint_mk_$file"

  @Synchronized
  private fun prefs(service: String, secure: Boolean): SharedPreferences {
    val file = fileName(service, secure)
    cache[file]?.let { return it }

    val created =
      if (!secure) {
        reactContext.getSharedPreferences(file, Context.MODE_PRIVATE)
      } else {
        openSecure(file)
      }
    cache[file] = created
    return created
  }

  private fun openSecure(file: String): SharedPreferences {
    try {
      return createEncrypted(file)
    } catch (e: Throwable) {
      if (!isRecoverable(e) || !recovered.add(file)) throw e

      // Stage 1: drop only the corrupt prefs file; keep the master key.
      deletePrefsFile(file)
      try {
        return createEncrypted(file)
      } catch (e2: Throwable) {
        if (!isRecoverable(e2)) throw e2
        // Stage 2: the master key itself is bad — drop this namespace's alias.
        deleteMasterKey(masterKeyAlias(file))
        deletePrefsFile(file)
        return createEncrypted(file)
      }
    }
  }

  private fun createEncrypted(file: String): SharedPreferences {
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

  /** Only definitive, unrecoverable corruption warrants wiping data. */
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
      // best-effort
    }
  }

  private fun deleteMasterKey(alias: String) {
    try {
      val ks = KeyStore.getInstance("AndroidKeyStore")
      ks.load(null)
      if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    } catch (ignored: Throwable) {
      // best-effort
    }
  }

  @ReactMethod
  fun setItem(service: String, key: String, value: String, secure: Boolean, promise: Promise) {
    try {
      val ok = prefs(service, secure).edit().putString(key, value).commit()
      if (ok) promise.resolve(null) else promise.reject("E_OKINT_SET", "Failed to persist value.")
    } catch (e: Exception) {
      promise.reject("E_OKINT_SET", e.message, e)
    }
  }

  @ReactMethod
  fun getItem(service: String, key: String, secure: Boolean, promise: Promise) {
    try {
      promise.resolve(prefs(service, secure).getString(key, null))
    } catch (e: Exception) {
      promise.reject("E_OKINT_GET", e.message, e)
    }
  }

  @ReactMethod
  fun removeItem(service: String, key: String, secure: Boolean, promise: Promise) {
    try {
      val ok = prefs(service, secure).edit().remove(key).commit()
      if (ok) promise.resolve(null) else promise.reject("E_OKINT_REMOVE", "Failed to remove key.")
    } catch (e: Exception) {
      promise.reject("E_OKINT_REMOVE", e.message, e)
    }
  }

  @ReactMethod
  fun clear(service: String, secure: Boolean, promise: Promise) {
    try {
      val ok = prefs(service, secure).edit().clear().commit()
      if (ok) promise.resolve(null) else promise.reject("E_OKINT_CLEAR", "Failed to clear store.")
    } catch (e: Exception) {
      promise.reject("E_OKINT_CLEAR", e.message, e)
    }
  }

  @ReactMethod
  fun getAllKeys(service: String, secure: Boolean, promise: Promise) {
    try {
      val arr = Arguments.createArray()
      for (k in prefs(service, secure).all.keys) {
        arr.pushString(k)
      }
      promise.resolve(arr)
    } catch (e: Exception) {
      promise.reject("E_OKINT_KEYS", e.message, e)
    }
  }

  companion object {
    const val NAME = "OkintRnStorage"
  }
}
