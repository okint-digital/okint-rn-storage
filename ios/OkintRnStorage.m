#import <React/RCTBridgeModule.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <sqlite3.h>

/**
 * okint-rn-storage — iOS native module (Objective-C for maximum build
 * compatibility: no Swift bridging-header / use_frameworks! pitfalls).
 *
 * One module, four stores selected by the `store` argument:
 *   - "secure"    → Keychain (kSecClassGenericPassword), AfterFirstUnlock,
 *                   this-device-only. For JWTs / FCM / secrets.
 *   - "async"     → a per-namespace NSUserDefaults suite (plaintext).
 *   - "encrypted" → values sealed with AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC,
 *                   public CommonCrypto), the 64-byte key kept in the Keychain;
 *                   ciphertext stored in SQLite. Handles large encrypted blobs.
 *   - "sqlite"    → plaintext values in SQLite.
 *
 * Plus a blocking-synchronous bulk read (`getEntriesSync`) powering the zero-load
 * `createSyncStorageSync` path.
 *
 * NOTE: iOS native is reviewed against current Apple APIs but verified at app
 * build time (no Xcode in the authoring environment).
 */
@interface OkintRnStorage : NSObject <RCTBridgeModule>
@end

@implementation OkintRnStorage

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup { return NO; }

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

#pragma mark - Crypto (encrypted store: AES-256-CBC + HMAC-SHA256, encrypt-then-MAC)

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

static NSData *OkintEncKey(NSString *service) {
  NSString *scope = OkintScope(@"enckey", service);
  NSData *existing = OkintKCGetData(scope, @"key");
  if (existing && existing.length == 64) return existing;
  NSData *fresh = OkintRandom(64);
  if (fresh) OkintKCSetData(scope, @"key", fresh);
  return fresh;
}

static NSString *OkintEncrypt(NSString *service, NSString *value) {
  NSData *k = OkintEncKey(service);
  if (k.length != 64) return nil;
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
  if (k.length != 64) return nil;
  NSData *encKey = [k subdataWithRange:NSMakeRange(0, 32)];
  NSData *macKey = [k subdataWithRange:NSMakeRange(32, 32)];
  NSUInteger ctLen = blob.length - 16 - CC_SHA256_DIGEST_LENGTH;
  NSData *iv = [blob subdataWithRange:NSMakeRange(0, 16)];
  NSData *ct = [blob subdataWithRange:NSMakeRange(16, ctLen)];
  NSData *mac = [blob subdataWithRange:NSMakeRange(16 + ctLen, CC_SHA256_DIGEST_LENGTH)];
  NSData *ivct = [blob subdataWithRange:NSMakeRange(0, 16 + ctLen)];
  if (!OkintConstEq(OkintHMAC(macKey, ivct), mac)) return nil; // tampered / wrong key
  NSData *pt = OkintAES(kCCDecrypt, encKey, iv, ct);
  if (!pt) return nil;
  return [[NSString alloc] initWithData:pt encoding:NSUTF8StringEncoding];
}

#pragma mark - SQLite (backs encrypted + sqlite stores)

static sqlite3 *gOkintDB = NULL;

static sqlite3 *OkintDB(void) {
  if (gOkintDB == NULL) {
    NSString *dir = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [dir stringByAppendingPathComponent:@"okint_sqlite.db"];
    sqlite3_open([path UTF8String], &gOkintDB);
  }
  return gOkintDB;
}

static NSString *OkintTable(NSString *service) {
  NSMutableString *t = [NSMutableString stringWithString:@"kv_"];
  for (NSUInteger i = 0; i < service.length; i++) {
    unichar c = [service characterAtIndex:i];
    BOOL ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
    [t appendFormat:@"%C", ok ? c : (unichar)'_'];
  }
  return t;
}

static void OkintEnsureTable(NSString *service) {
  NSString *sql = [NSString stringWithFormat:@"CREATE TABLE IF NOT EXISTS %@ (k TEXT PRIMARY KEY, v TEXT NOT NULL)", OkintTable(service)];
  sqlite3_exec(OkintDB(), [sql UTF8String], NULL, NULL, NULL);
}

static BOOL OkintSqliteSet(NSString *service, NSString *key, NSString *value) {
  OkintEnsureTable(service);
  NSString *sql = [NSString stringWithFormat:@"INSERT OR REPLACE INTO %@ (k, v) VALUES (?, ?)", OkintTable(service)];
  sqlite3_stmt *stmt = NULL;
  BOOL ok = NO;
  if (sqlite3_prepare_v2(OkintDB(), [sql UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
    sqlite3_bind_text(stmt, 1, [key UTF8String], -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, [value UTF8String], -1, SQLITE_TRANSIENT);
    ok = (sqlite3_step(stmt) == SQLITE_DONE);
  }
  sqlite3_finalize(stmt);
  return ok;
}

static NSString *OkintSqliteGet(NSString *service, NSString *key) {
  OkintEnsureTable(service);
  NSString *sql = [NSString stringWithFormat:@"SELECT v FROM %@ WHERE k = ?", OkintTable(service)];
  sqlite3_stmt *stmt = NULL;
  NSString *out = nil;
  if (sqlite3_prepare_v2(OkintDB(), [sql UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
    sqlite3_bind_text(stmt, 1, [key UTF8String], -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
      const unsigned char *txt = sqlite3_column_text(stmt, 0);
      if (txt) out = [NSString stringWithUTF8String:(const char *)txt];
    }
  }
  sqlite3_finalize(stmt);
  return out;
}

static void OkintSqliteExec(NSString *service, NSString *sql, NSString *_Nullable arg) {
  OkintEnsureTable(service);
  sqlite3_stmt *stmt = NULL;
  if (sqlite3_prepare_v2(OkintDB(), [sql UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
    if (arg) sqlite3_bind_text(stmt, 1, [arg UTF8String], -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
  }
  sqlite3_finalize(stmt);
}

static NSDictionary *OkintSqliteAll(NSString *service) {
  OkintEnsureTable(service);
  NSString *sql = [NSString stringWithFormat:@"SELECT k, v FROM %@", OkintTable(service)];
  sqlite3_stmt *stmt = NULL;
  NSMutableDictionary *out = [NSMutableDictionary dictionary];
  if (sqlite3_prepare_v2(OkintDB(), [sql UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      const unsigned char *k = sqlite3_column_text(stmt, 0);
      const unsigned char *v = sqlite3_column_text(stmt, 1);
      if (k && v) out[[NSString stringWithUTF8String:(const char *)k]] = [NSString stringWithUTF8String:(const char *)v];
    }
  }
  sqlite3_finalize(stmt);
  return out;
}

#pragma mark - Store helpers

static BOOL OkintIsSqliteStore(NSString *store) {
  return [store isEqualToString:@"encrypted"] || [store isEqualToString:@"sqlite"];
}

/** Read a single value (decrypting for the encrypted store). */
static NSString *OkintReadOne(NSString *service, NSString *key, NSString *store) {
  if ([store isEqualToString:@"secure"]) {
    NSData *d = OkintKCGetData(OkintScope(@"secure", service), key);
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
  }
  if ([store isEqualToString:@"encrypted"]) {
    NSString *ct = OkintSqliteGet(service, key);
    return ct ? OkintDecrypt(service, ct) : nil;
  }
  if ([store isEqualToString:@"sqlite"]) {
    return OkintSqliteGet(service, key);
  }
  return [OkintDefaults(store, service) stringForKey:key]; // async
}

#pragma mark - Methods

RCT_EXPORT_METHOD(setItem:(NSString *)service
                  key:(NSString *)key
                  value:(NSString *)value
                  store:(NSString *)store
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
  if ([store isEqualToString:@"secure"]) {
    OSStatus s = OkintKCSetData(OkintScope(@"secure", service), key, [value dataUsingEncoding:NSUTF8StringEncoding]);
    if (s == errSecSuccess) resolve([NSNull null]);
    else reject(@"E_OKINT_SET", [NSString stringWithFormat:@"Keychain set failed (%d)", (int)s], nil);
    return;
  }
  if (OkintIsSqliteStore(store)) {
    NSString *stored = [store isEqualToString:@"encrypted"] ? OkintEncrypt(service, value) : value;
    if (!stored) { reject(@"E_OKINT_SET", @"Encryption failed", nil); return; }
    if (OkintSqliteSet(service, key, stored)) resolve([NSNull null]);
    else reject(@"E_OKINT_SET", @"SQLite insert failed", nil);
    return;
  }
  [OkintDefaults(store, service) setObject:value forKey:key];
  resolve([NSNull null]);
}

RCT_EXPORT_METHOD(getItem:(NSString *)service
                  key:(NSString *)key
                  store:(NSString *)store
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
  NSString *v = OkintReadOne(service, key, store);
  resolve(v ?: [NSNull null]);
}

RCT_EXPORT_METHOD(removeItem:(NSString *)service
                  key:(NSString *)key
                  store:(NSString *)store
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
  if ([store isEqualToString:@"secure"]) {
    OSStatus s = SecItemDelete((__bridge CFDictionaryRef)OkintKCQuery(OkintScope(@"secure", service), key));
    if (s == errSecSuccess || s == errSecItemNotFound) resolve([NSNull null]);
    else reject(@"E_OKINT_REMOVE", [NSString stringWithFormat:@"Keychain delete failed (%d)", (int)s], nil);
    return;
  }
  if (OkintIsSqliteStore(store)) {
    OkintSqliteExec(service, [NSString stringWithFormat:@"DELETE FROM %@ WHERE k = ?", OkintTable(service)], key);
    resolve([NSNull null]);
    return;
  }
  [OkintDefaults(store, service) removeObjectForKey:key];
  resolve([NSNull null]);
}

RCT_EXPORT_METHOD(clear:(NSString *)service
                  store:(NSString *)store
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
  if ([store isEqualToString:@"secure"]) {
    OSStatus s = SecItemDelete((__bridge CFDictionaryRef)OkintKCQuery(OkintScope(@"secure", service), nil));
    if (s == errSecSuccess || s == errSecItemNotFound) resolve([NSNull null]);
    else reject(@"E_OKINT_CLEAR", [NSString stringWithFormat:@"Keychain clear failed (%d)", (int)s], nil);
    return;
  }
  if (OkintIsSqliteStore(store)) {
    OkintSqliteExec(service, [NSString stringWithFormat:@"DELETE FROM %@", OkintTable(service)], nil);
    resolve([NSNull null]);
    return;
  }
  [OkintDefaults(store, service) removePersistentDomainForName:OkintScope(store, service)];
  resolve([NSNull null]);
}

RCT_EXPORT_METHOD(getAllKeys:(NSString *)service
                  store:(NSString *)store
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
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
  if (OkintIsSqliteStore(store)) {
    resolve([OkintSqliteAll(service) allKeys]);
    return;
  }
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
  if ([store isEqualToString:@"sqlite"]) {
    return OkintSqliteAll(service);
  }
  if ([store isEqualToString:@"encrypted"]) {
    NSDictionary *raw = OkintSqliteAll(service);
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    for (NSString *k in raw.allKeys) {
      NSString *pt = OkintDecrypt(service, raw[k]);
      if (pt) out[k] = pt;
    }
    return out;
  }
  return @{};
}

@end
