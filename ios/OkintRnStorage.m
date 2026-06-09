#import <React/RCTBridgeModule.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <sqlite3.h>

/**
 * okint-rn-storage — iOS native module (Objective-C; no Swift bridging pitfalls).
 *
 * One module, four stores selected by `store`:
 *   - "secure"    → Keychain (kSecClassGenericPassword, AfterFirstUnlock,
 *                   this-device-only). For JWTs / FCM / secrets.
 *   - "async"     → a per-namespace NSUserDefaults suite (plaintext).
 *   - "encrypted" → a fully-encrypted SQLite table: KEYS and VALUES sealed with
 *                   AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC, public
 *                   CommonCrypto); lookups via a deterministic HMAC token. The
 *                   96-byte key (enc|mac|token) lives in the Keychain. No
 *                   plaintext in the database — an encrypted DB, no SQLCipher dep.
 *   - "sqlite"    → plaintext values in a separate SQLite table.
 *
 * Plus a blocking-sync bulk read (`getEntriesSync`) and a C++/JSI installer
 * (`installJSI`, implemented in OkintRnStorageJSI.mm).
 *
 * NOTE: reviewed against current Apple APIs; verified at app build time.
 */

// Implemented in OkintRnStorageJSI.mm (Obj-C++).
extern BOOL OkintInstallJSIForBridge(RCTBridge *bridge);

@interface OkintRnStorage : NSObject <RCTBridgeModule>
@end

@implementation OkintRnStorage

@synthesize bridge = _bridge;

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup { return NO; }

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(installJSI) {
  return @(OkintInstallJSIForBridge(self.bridge));
}

#pragma mark - Scoping

static NSString *OkintScope(NSString *store, NSString *service) {
  return [NSString stringWithFormat:@"okint.%@.%@", store, service];
}

static NSUserDefaults *OkintDefaults(NSString *store, NSString *service) {
  NSUserDefaults *d = [[NSUserDefaults alloc] initWithSuiteName:OkintScope(store, service)];
  return d ?: [NSUserDefaults standardUserDefaults];
}

#pragma mark - Keychain (secure store + encrypted-key storage)

static NSMutableDictionary *OkintKCQuery(NSString *scope, NSString *_Nullable key) {
  NSMutableDictionary *q = [NSMutableDictionary dictionary];
  q[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
  q[(__bridge id)kSecAttrService] = scope;
  q[(__bridge id)kSecUseDataProtectionKeychain] = @YES;
  if (key) q[(__bridge id)kSecAttrAccount] = key;
  return q;
}

static OSStatus OkintKCSetData(NSString *scope, NSString *key, NSData *data) {
  NSMutableDictionary *q = OkintKCQuery(scope, key);
  OSStatus s = SecItemUpdate((__bridge CFDictionaryRef)q, (__bridge CFDictionaryRef)@{ (__bridge id)kSecValueData: data });
  if (s == errSecItemNotFound) {
    NSMutableDictionary *add = OkintKCQuery(scope, key);
    add[(__bridge id)kSecValueData] = data;
    add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    s = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
  }
  return s;
}

/**
 * Store a secret behind device-credential auth: the item is bound to the Secure
 * Enclave via SecAccessControl (`.userPresence` — Face ID / Touch ID OR device
 * passcode). The OS prompts automatically on READ; writing doesn't prompt. We
 * delete-then-add so overwriting an existing gated item never triggers a prompt.
 */
static OSStatus OkintKCSetDataAuth(NSString *scope, NSString *key, NSData *data) {
  SecAccessControlRef ac = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      kSecAccessControlUserPresence,
      NULL);
  if (ac == NULL) return errSecParam;
  SecItemDelete((__bridge CFDictionaryRef)OkintKCQuery(scope, key));
  NSMutableDictionary *add = OkintKCQuery(scope, key);
  add[(__bridge id)kSecValueData] = data;
  add[(__bridge id)kSecAttrAccessControl] = (__bridge_transfer id)ac; // supersedes kSecAttrAccessible
  return SecItemAdd((__bridge CFDictionaryRef)add, NULL);
}

static NSData *OkintKCGetData(NSString *scope, NSString *key) {
  NSMutableDictionary *q = OkintKCQuery(scope, key);
  q[(__bridge id)kSecReturnData] = @YES;
  q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
  CFTypeRef result = NULL;
  if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &result) == errSecSuccess) {
    return (__bridge_transfer NSData *)result;
  }
  return nil;
}

/**
 * Read a gated secret. If the item carries an access-control (written via
 * OkintKCSetDataAuth), the Keychain shows the auth UI automatically; `prompt`
 * sets the reason string. On a plain item this behaves like OkintKCGetData.
 */
static NSData *OkintKCGetDataAuth(NSString *scope, NSString *key, NSString *prompt) {
  NSMutableDictionary *q = OkintKCQuery(scope, key);
  q[(__bridge id)kSecReturnData] = @YES;
  q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
  if (prompt) q[(__bridge id)kSecUseOperationPrompt] = prompt;
  CFTypeRef result = NULL;
  if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &result) == errSecSuccess) {
    return (__bridge_transfer NSData *)result;
  }
  return nil;
}

#pragma mark - Crypto (encrypted store)

static NSData *OkintRandom(size_t n) {
  NSMutableData *d = [NSMutableData dataWithLength:n];
  if (SecRandomCopyBytes(kSecRandomDefault, n, d.mutableBytes) != errSecSuccess) return nil;
  return d;
}

static NSData *OkintAES(CCOperation op, NSData *key, NSData *iv, NSData *in) {
  size_t bufLen = in.length + kCCBlockSizeAES128;
  NSMutableData *out = [NSMutableData dataWithLength:bufLen];
  size_t moved = 0;
  CCCryptorStatus s = CCCrypt(op, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                              key.bytes, kCCKeySizeAES256, iv.bytes,
                              in.bytes, in.length, out.mutableBytes, bufLen, &moved);
  if (s != kCCSuccess) return nil;
  out.length = moved;
  return out;
}

static NSData *OkintHMAC(NSData *key, NSData *data) {
  NSMutableData *mac = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
  CCHmac(kCCHmacAlgSHA256, key.bytes, key.length, data.bytes, data.length, mac.mutableBytes);
  return mac;
}

static BOOL OkintConstEq(NSData *a, NSData *b) {
  if (a.length != b.length) return NO;
  const uint8_t *pa = a.bytes;
  const uint8_t *pb = b.bytes;
  uint8_t r = 0;
  for (NSUInteger i = 0; i < a.length; i++) r |= (uint8_t)(pa[i] ^ pb[i]);
  return r == 0;
}

/** 96-byte key: [0,32) AES enc, [32,64) HMAC for MAC, [64,96) HMAC for token. */
static NSData *OkintEncKey(NSString *service) {
  NSString *scope = OkintScope(@"enckey", service);
  NSData *existing = OkintKCGetData(scope, @"key");
  if (existing && existing.length == 96) return existing;
  NSData *fresh = OkintRandom(96);
  if (fresh) OkintKCSetData(scope, @"key", fresh);
  return fresh;
}

static NSString *OkintToken(NSString *service, NSString *key) {
  NSData *k = OkintEncKey(service);
  if (k.length != 96) return nil;
  NSData *tokKey = [k subdataWithRange:NSMakeRange(64, 32)];
  NSData *mac = OkintHMAC(tokKey, [key dataUsingEncoding:NSUTF8StringEncoding]);
  return [mac base64EncodedStringWithOptions:0];
}

static NSString *OkintEncrypt(NSString *service, NSString *value) {
  NSData *k = OkintEncKey(service);
  if (k.length != 96) return nil;
  NSData *encKey = [k subdataWithRange:NSMakeRange(0, 32)];
  NSData *macKey = [k subdataWithRange:NSMakeRange(32, 32)];
  NSData *iv = OkintRandom(16);
  NSData *ct = OkintAES(kCCEncrypt, encKey, iv, [value dataUsingEncoding:NSUTF8StringEncoding]);
  if (!ct) return nil;
  NSMutableData *ivct = [NSMutableData dataWithData:iv];
  [ivct appendData:ct];
  NSData *mac = OkintHMAC(macKey, ivct);
  NSMutableData *blob = [NSMutableData dataWithData:ivct];
  [blob appendData:mac];
  return [blob base64EncodedStringWithOptions:0];
}

static NSString *OkintDecrypt(NSString *service, NSString *b64) {
  NSData *blob = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
  if (!blob || blob.length < 16 + CC_SHA256_DIGEST_LENGTH) return nil;
  NSData *k = OkintEncKey(service);
  if (k.length != 96) return nil;
  NSData *encKey = [k subdataWithRange:NSMakeRange(0, 32)];
  NSData *macKey = [k subdataWithRange:NSMakeRange(32, 32)];
  NSUInteger ctLen = blob.length - 16 - CC_SHA256_DIGEST_LENGTH;
  NSData *iv = [blob subdataWithRange:NSMakeRange(0, 16)];
  NSData *ct = [blob subdataWithRange:NSMakeRange(16, ctLen)];
  NSData *mac = [blob subdataWithRange:NSMakeRange(16 + ctLen, CC_SHA256_DIGEST_LENGTH)];
  NSData *ivct = [blob subdataWithRange:NSMakeRange(0, 16 + ctLen)];
  if (!OkintConstEq(OkintHMAC(macKey, ivct), mac)) return nil;
  NSData *pt = OkintAES(kCCDecrypt, encKey, iv, ct);
  if (!pt) return nil;
  return [[NSString alloc] initWithData:pt encoding:NSUTF8StringEncoding];
}

#pragma mark - SQLite

static sqlite3 *gOkintDB = NULL;

static sqlite3 *OkintDB(void) {
  if (gOkintDB == NULL) {
    NSString *dir = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [dir stringByAppendingPathComponent:@"okint_sqlite.db"];
    sqlite3_open([path UTF8String], &gOkintDB);
  }
  return gOkintDB;
}

static NSString *OkintSanitize(NSString *prefix, NSString *service) {
  NSMutableString *t = [NSMutableString stringWithString:prefix];
  for (NSUInteger i = 0; i < service.length; i++) {
    unichar c = [service characterAtIndex:i];
    BOOL ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
    [t appendFormat:@"%C", ok ? c : (unichar)'_'];
  }
  return t;
}

static void OkintExec(NSString *sql) {
  sqlite3_exec(OkintDB(), [sql UTF8String], NULL, NULL, NULL);
}

// ── sqlite store (plaintext, kv_ table) ──────────────────────────────────────

static NSString *OkintKvTable(NSString *service) { return OkintSanitize(@"kv_", service); }

static void OkintKvEnsure(NSString *service) {
  OkintExec([NSString stringWithFormat:@"CREATE TABLE IF NOT EXISTS %@ (k TEXT PRIMARY KEY, v TEXT NOT NULL)", OkintKvTable(service)]);
}

static BOOL OkintKvSet(NSString *service, NSString *key, NSString *value) {
  OkintKvEnsure(service);
  sqlite3_stmt *st = NULL;
  BOOL ok = NO;
  NSString *sql = [NSString stringWithFormat:@"INSERT OR REPLACE INTO %@ (k, v) VALUES (?, ?)", OkintKvTable(service)];
  if (sqlite3_prepare_v2(OkintDB(), [sql UTF8String], -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_text(st, 1, [key UTF8String], -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, [value UTF8String], -1, SQLITE_TRANSIENT);
    ok = (sqlite3_step(st) == SQLITE_DONE);
  }
  sqlite3_finalize(st);
  return ok;
}

static NSString *OkintKvGet(NSString *service, NSString *key) {
  OkintKvEnsure(service);
  sqlite3_stmt *st = NULL;
  NSString *out = nil;
  NSString *sql = [NSString stringWithFormat:@"SELECT v FROM %@ WHERE k = ?", OkintKvTable(service)];
  if (sqlite3_prepare_v2(OkintDB(), [sql UTF8String], -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_text(st, 1, [key UTF8String], -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
      const unsigned char *t = sqlite3_column_text(st, 0);
      if (t) out = [NSString stringWithUTF8String:(const char *)t];
    }
  }
  sqlite3_finalize(st);
  return out;
}

static void OkintKvDelete(NSString *service, NSString *key) {
  OkintKvEnsure(service);
  sqlite3_stmt *st = NULL;
  NSString *sql = [NSString stringWithFormat:@"DELETE FROM %@ WHERE k = ?", OkintKvTable(service)];
  if (sqlite3_prepare_v2(OkintDB(), [sql UTF8String], -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_text(st, 1, [key UTF8String], -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
  }
  sqlite3_finalize(st);
}

static NSDictionary *OkintKvAll(NSString *service) {
  OkintKvEnsure(service);
  sqlite3_stmt *st = NULL;
  NSMutableDictionary *out = [NSMutableDictionary dictionary];
  NSString *sql = [NSString stringWithFormat:@"SELECT k, v FROM %@", OkintKvTable(service)];
  if (sqlite3_prepare_v2(OkintDB(), [sql UTF8String], -1, &st, NULL) == SQLITE_OK) {
    while (sqlite3_step(st) == SQLITE_ROW) {
      const unsigned char *k = sqlite3_column_text(st, 0);
      const unsigned char *v = sqlite3_column_text(st, 1);
      if (k && v) out[[NSString stringWithUTF8String:(const char *)k]] = [NSString stringWithUTF8String:(const char *)v];
    }
  }
  sqlite3_finalize(st);
  return out;
}

// ── encrypted store (enc_ table, encrypted keys + values, HMAC token) ─────────

static NSString *OkintEncTable(NSString *service) { return OkintSanitize(@"enc_", service); }

static void OkintEncEnsure(NSString *service) {
  OkintExec([NSString stringWithFormat:@"CREATE TABLE IF NOT EXISTS %@ (kt TEXT PRIMARY KEY, ke TEXT NOT NULL, ve TEXT NOT NULL)", OkintEncTable(service)]);
}

static BOOL OkintEncSet(NSString *service, NSString *key, NSString *value) {
  NSString *ke = OkintEncrypt(service, key);
  NSString *ve = OkintEncrypt(service, value);
  NSString *kt = OkintToken(service, key);
  if (!ke || !ve || !kt) return NO;
  OkintEncEnsure(service);
  sqlite3_stmt *st = NULL;
  BOOL ok = NO;
  NSString *sql = [NSString stringWithFormat:@"INSERT OR REPLACE INTO %@ (kt, ke, ve) VALUES (?, ?, ?)", OkintEncTable(service)];
  if (sqlite3_prepare_v2(OkintDB(), [sql UTF8String], -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_text(st, 1, [kt UTF8String], -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, [ke UTF8String], -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, [ve UTF8String], -1, SQLITE_TRANSIENT);
    ok = (sqlite3_step(st) == SQLITE_DONE);
  }
  sqlite3_finalize(st);
  return ok;
}

static NSString *OkintEncGet(NSString *service, NSString *key) {
  OkintEncEnsure(service);
  NSString *kt = OkintToken(service, key);
  if (!kt) return nil;
  sqlite3_stmt *st = NULL;
  NSString *ve = nil;
  NSString *sql = [NSString stringWithFormat:@"SELECT ve FROM %@ WHERE kt = ?", OkintEncTable(service)];
  if (sqlite3_prepare_v2(OkintDB(), [sql UTF8String], -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_text(st, 1, [kt UTF8String], -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
      const unsigned char *t = sqlite3_column_text(st, 0);
      if (t) ve = [NSString stringWithUTF8String:(const char *)t];
    }
  }
  sqlite3_finalize(st);
  return ve ? OkintDecrypt(service, ve) : nil;
}

static void OkintEncDelete(NSString *service, NSString *key) {
  OkintEncEnsure(service);
  NSString *kt = OkintToken(service, key);
  if (!kt) return;
  sqlite3_stmt *st = NULL;
  NSString *sql = [NSString stringWithFormat:@"DELETE FROM %@ WHERE kt = ?", OkintEncTable(service)];
  if (sqlite3_prepare_v2(OkintDB(), [sql UTF8String], -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_text(st, 1, [kt UTF8String], -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
  }
  sqlite3_finalize(st);
}

static NSDictionary *OkintEncAll(NSString *service) {
  OkintEncEnsure(service);
  sqlite3_stmt *st = NULL;
  NSMutableDictionary *out = [NSMutableDictionary dictionary];
  NSString *sql = [NSString stringWithFormat:@"SELECT ke, ve FROM %@", OkintEncTable(service)];
  if (sqlite3_prepare_v2(OkintDB(), [sql UTF8String], -1, &st, NULL) == SQLITE_OK) {
    while (sqlite3_step(st) == SQLITE_ROW) {
      const unsigned char *ke = sqlite3_column_text(st, 0);
      const unsigned char *ve = sqlite3_column_text(st, 1);
      if (ke && ve) {
        NSString *k = OkintDecrypt(service, [NSString stringWithUTF8String:(const char *)ke]);
        NSString *v = OkintDecrypt(service, [NSString stringWithUTF8String:(const char *)ve]);
        if (k && v) out[k] = v;
      }
    }
  }
  sqlite3_finalize(st);
  return out;
}

#pragma mark - Read dispatch

static NSString *OkintReadOne(NSString *service, NSString *key, NSString *store, BOOL requireAuth) {
  if ([store isEqualToString:@"secure"]) {
    NSData *d = requireAuth
        ? OkintKCGetDataAuth(OkintScope(@"secure", service), key, @"Authenticate to access your saved data")
        : OkintKCGetData(OkintScope(@"secure", service), key);
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
  }
  if ([store isEqualToString:@"encrypted"]) return OkintEncGet(service, key);
  if ([store isEqualToString:@"sqlite"]) return OkintKvGet(service, key);
  return [OkintDefaults(store, service) stringForKey:key];
}

#pragma mark - Methods

RCT_EXPORT_METHOD(setItem:(NSString *)service key:(NSString *)key value:(NSString *)value store:(NSString *)store
                  requireAuth:(BOOL)requireAuth
                  resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
  if ([store isEqualToString:@"secure"]) {
    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
    OSStatus s = requireAuth
        ? OkintKCSetDataAuth(OkintScope(@"secure", service), key, data)
        : OkintKCSetData(OkintScope(@"secure", service), key, data);
    if (s == errSecSuccess) resolve([NSNull null]);
    else reject(@"E_OKINT_SET", [NSString stringWithFormat:@"Keychain set failed (%d)", (int)s], nil);
    return;
  }
  if ([store isEqualToString:@"encrypted"]) {
    if (OkintEncSet(service, key, value)) resolve([NSNull null]);
    else reject(@"E_OKINT_SET", @"Encrypted set failed", nil);
    return;
  }
  if ([store isEqualToString:@"sqlite"]) {
    if (OkintKvSet(service, key, value)) resolve([NSNull null]);
    else reject(@"E_OKINT_SET", @"SQLite insert failed", nil);
    return;
  }
  [OkintDefaults(store, service) setObject:value forKey:key];
  resolve([NSNull null]);
}

RCT_EXPORT_METHOD(getItem:(NSString *)service key:(NSString *)key store:(NSString *)store
                  requireAuth:(BOOL)requireAuth
                  resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
  NSString *v = OkintReadOne(service, key, store, requireAuth);
  resolve(v ?: [NSNull null]);
}

RCT_EXPORT_METHOD(removeItem:(NSString *)service key:(NSString *)key store:(NSString *)store
                  resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
  if ([store isEqualToString:@"secure"]) {
    OSStatus s = SecItemDelete((__bridge CFDictionaryRef)OkintKCQuery(OkintScope(@"secure", service), key));
    if (s == errSecSuccess || s == errSecItemNotFound) resolve([NSNull null]);
    else reject(@"E_OKINT_REMOVE", [NSString stringWithFormat:@"Keychain delete failed (%d)", (int)s], nil);
    return;
  }
  if ([store isEqualToString:@"encrypted"]) { OkintEncDelete(service, key); resolve([NSNull null]); return; }
  if ([store isEqualToString:@"sqlite"]) { OkintKvDelete(service, key); resolve([NSNull null]); return; }
  [OkintDefaults(store, service) removeObjectForKey:key];
  resolve([NSNull null]);
}

RCT_EXPORT_METHOD(clear:(NSString *)service store:(NSString *)store
                  resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
  if ([store isEqualToString:@"secure"]) {
    OSStatus s = SecItemDelete((__bridge CFDictionaryRef)OkintKCQuery(OkintScope(@"secure", service), nil));
    if (s == errSecSuccess || s == errSecItemNotFound) resolve([NSNull null]);
    else reject(@"E_OKINT_CLEAR", [NSString stringWithFormat:@"Keychain clear failed (%d)", (int)s], nil);
    return;
  }
  if ([store isEqualToString:@"encrypted"]) { OkintExec([NSString stringWithFormat:@"DELETE FROM %@", OkintEncTable(service)]); resolve([NSNull null]); return; }
  if ([store isEqualToString:@"sqlite"]) { OkintExec([NSString stringWithFormat:@"DELETE FROM %@", OkintKvTable(service)]); resolve([NSNull null]); return; }
  [OkintDefaults(store, service) removePersistentDomainForName:OkintScope(store, service)];
  resolve([NSNull null]);
}

RCT_EXPORT_METHOD(getAllKeys:(NSString *)service store:(NSString *)store
                  resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
  if ([store isEqualToString:@"secure"]) {
    NSMutableDictionary *q = OkintKCQuery(OkintScope(@"secure", service), nil);
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    q[(__bridge id)kSecReturnAttributes] = @YES;
    CFTypeRef result = NULL;
    OSStatus s = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
    if (s == errSecItemNotFound) { resolve(@[]); return; }
    if (s != errSecSuccess) { reject(@"E_OKINT_KEYS", [NSString stringWithFormat:@"Keychain enumerate failed (%d)", (int)s], nil); return; }
    NSArray *items = (__bridge_transfer NSArray *)result;
    NSMutableArray<NSString *> *keys = [NSMutableArray array];
    for (NSDictionary *item in items) {
      NSString *account = item[(__bridge id)kSecAttrAccount];
      if (account) [keys addObject:account];
    }
    resolve(keys);
    return;
  }
  if ([store isEqualToString:@"encrypted"]) { resolve([OkintEncAll(service) allKeys]); return; }
  if ([store isEqualToString:@"sqlite"]) { resolve([OkintKvAll(service) allKeys]); return; }
  NSDictionary *domain = [OkintDefaults(store, service) persistentDomainForName:OkintScope(store, service)];
  resolve(domain ? [domain allKeys] : @[]);
}

/** Blocking-synchronous bulk read for the zero-load sync store. */
RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(getEntriesSync:(NSString *)service store:(NSString *)store) {
  if ([store isEqualToString:@"async"]) {
    NSDictionary *domain = [OkintDefaults(store, service) persistentDomainForName:OkintScope(store, service)];
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    for (NSString *k in domain.allKeys) {
      id v = domain[k];
      if ([v isKindOfClass:[NSString class]]) out[k] = v;
    }
    return out;
  }
  if ([store isEqualToString:@"encrypted"]) return OkintEncAll(service);
  if ([store isEqualToString:@"sqlite"]) return OkintKvAll(service);
  return @{};
}

@end
