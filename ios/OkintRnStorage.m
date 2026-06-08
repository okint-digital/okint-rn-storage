#import <React/RCTBridgeModule.h>
#import <Security/Security.h>
#import <sqlite3.h>

/**
 * okint-rn-storage — iOS native module (Objective-C for maximum build
 * compatibility: no Swift bridging-header / use_frameworks! pitfalls).
 *
 * One module, four stores selected by the `store` argument:
 *   - "secure"    → Keychain (kSecClassGenericPassword), AfterFirstUnlock,
 *                   this-device-only. For JWTs / FCM / secrets.
 *   - "async"     → a per-namespace NSUserDefaults suite (plaintext).
 *   - "encrypted" → Keychain under a dedicated service (hardware-encrypted,
 *                   partitioned from `secure`). Note: bounded by Keychain item
 *                   size; the Android `encrypted` store has more headroom for
 *                   very large blobs.
 *   - "sqlite"    → a per-namespace key/value table in a SQLite database.
 *
 * Works under the New Architecture interop layer.
 *
 * NOTE: iOS native is reviewed against current Apple APIs but verified at app
 * build time (no Xcode in the authoring environment).
 */
@interface OkintRnStorage : NSObject <RCTBridgeModule>
@end

@implementation OkintRnStorage

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup { return NO; }

#pragma mark - Scoping helpers

static NSString *OkintScope(NSString *store, NSString *service) {
  return [NSString stringWithFormat:@"okint.%@.%@", store, service];
}

static BOOL OkintIsKeychainStore(NSString *store) {
  return [store isEqualToString:@"secure"] || [store isEqualToString:@"encrypted"];
}

static NSUserDefaults *OkintDefaults(NSString *store, NSString *service) {
  NSUserDefaults *d = [[NSUserDefaults alloc] initWithSuiteName:OkintScope(store, service)];
  return d ?: [NSUserDefaults standardUserDefaults];
}

#pragma mark - Keychain helpers (secure + encrypted)

static NSMutableDictionary *OkintKeychainQuery(NSString *scope, NSString *_Nullable key) {
  NSMutableDictionary *q = [NSMutableDictionary dictionary];
  q[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
  q[(__bridge id)kSecAttrService] = scope;
  q[(__bridge id)kSecUseDataProtectionKeychain] = @YES;
  if (key) {
    q[(__bridge id)kSecAttrAccount] = key;
  }
  return q;
}

static OSStatus OkintKeychainSet(NSString *scope, NSString *key, NSString *value) {
  NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
  NSMutableDictionary *q = OkintKeychainQuery(scope, key);
  NSDictionary *attrs = @{ (__bridge id)kSecValueData: data };
  OSStatus s = SecItemUpdate((__bridge CFDictionaryRef)q, (__bridge CFDictionaryRef)attrs);
  if (s == errSecItemNotFound) {
    NSMutableDictionary *add = OkintKeychainQuery(scope, key);
    add[(__bridge id)kSecValueData] = data;
    add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    s = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
  }
  return s;
}

#pragma mark - SQLite helpers

static sqlite3 *gOkintDB = NULL;

static sqlite3 *OkintDB(void) {
  if (gOkintDB == NULL) {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES);
    NSString *dir = paths.firstObject;
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

#pragma mark - Methods

RCT_EXPORT_METHOD(setItem:(NSString *)service
                  key:(NSString *)key
                  value:(NSString *)value
                  store:(NSString *)store
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
  if (OkintIsKeychainStore(store)) {
    OSStatus s = OkintKeychainSet(OkintScope(store, service), key, value);
    if (s == errSecSuccess) resolve([NSNull null]);
    else reject(@"E_OKINT_SET", [NSString stringWithFormat:@"Keychain set failed (%d)", (int)s], nil);
    return;
  }
  if ([store isEqualToString:@"sqlite"]) {
    OkintEnsureTable(service);
    NSString *sql = [NSString stringWithFormat:@"INSERT OR REPLACE INTO %@ (k, v) VALUES (?, ?)", OkintTable(service)];
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(OkintDB(), [sql UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
      sqlite3_bind_text(stmt, 1, [key UTF8String], -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, 2, [value UTF8String], -1, SQLITE_TRANSIENT);
      int rc = sqlite3_step(stmt);
      sqlite3_finalize(stmt);
      if (rc == SQLITE_DONE) { resolve([NSNull null]); return; }
    }
    reject(@"E_OKINT_SET", @"SQLite insert failed", nil);
    return;
  }
  // async
  [OkintDefaults(store, service) setObject:value forKey:key];
  resolve([NSNull null]);
}

RCT_EXPORT_METHOD(getItem:(NSString *)service
                  key:(NSString *)key
                  store:(NSString *)store
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
  if (OkintIsKeychainStore(store)) {
    NSMutableDictionary *q = OkintKeychainQuery(OkintScope(store, service), key);
    q[(__bridge id)kSecReturnData] = @YES;
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef result = NULL;
    OSStatus s = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
    if (s == errSecSuccess) {
      NSData *data = (__bridge_transfer NSData *)result;
      NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
      resolve(str ?: [NSNull null]);
    } else if (s == errSecItemNotFound) {
      resolve([NSNull null]);
    } else {
      reject(@"E_OKINT_GET", [NSString stringWithFormat:@"Keychain get failed (%d)", (int)s], nil);
    }
    return;
  }
  if ([store isEqualToString:@"sqlite"]) {
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
    resolve(out ?: [NSNull null]);
    return;
  }
  NSString *v = [OkintDefaults(store, service) stringForKey:key];
  resolve(v ?: [NSNull null]);
}

RCT_EXPORT_METHOD(removeItem:(NSString *)service
                  key:(NSString *)key
                  store:(NSString *)store
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
  if (OkintIsKeychainStore(store)) {
    OSStatus s = SecItemDelete((__bridge CFDictionaryRef)OkintKeychainQuery(OkintScope(store, service), key));
    if (s == errSecSuccess || s == errSecItemNotFound) resolve([NSNull null]);
    else reject(@"E_OKINT_REMOVE", [NSString stringWithFormat:@"Keychain delete failed (%d)", (int)s], nil);
    return;
  }
  if ([store isEqualToString:@"sqlite"]) {
    OkintEnsureTable(service);
    NSString *sql = [NSString stringWithFormat:@"DELETE FROM %@ WHERE k = ?", OkintTable(service)];
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(OkintDB(), [sql UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
      sqlite3_bind_text(stmt, 1, [key UTF8String], -1, SQLITE_TRANSIENT);
      sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
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
  if (OkintIsKeychainStore(store)) {
    OSStatus s = SecItemDelete((__bridge CFDictionaryRef)OkintKeychainQuery(OkintScope(store, service), nil));
    if (s == errSecSuccess || s == errSecItemNotFound) resolve([NSNull null]);
    else reject(@"E_OKINT_CLEAR", [NSString stringWithFormat:@"Keychain clear failed (%d)", (int)s], nil);
    return;
  }
  if ([store isEqualToString:@"sqlite"]) {
    OkintEnsureTable(service);
    NSString *sql = [NSString stringWithFormat:@"DELETE FROM %@", OkintTable(service)];
    sqlite3_exec(OkintDB(), [sql UTF8String], NULL, NULL, NULL);
    resolve([NSNull null]);
    return;
  }
  NSString *suite = OkintScope(store, service);
  [OkintDefaults(store, service) removePersistentDomainForName:suite];
  resolve([NSNull null]);
}

RCT_EXPORT_METHOD(getAllKeys:(NSString *)service
                  store:(NSString *)store
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
  if (OkintIsKeychainStore(store)) {
    NSMutableDictionary *q = OkintKeychainQuery(OkintScope(store, service), nil);
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    q[(__bridge id)kSecReturnAttributes] = @YES;
    CFTypeRef result = NULL;
    OSStatus s = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
    if (s == errSecItemNotFound) { resolve(@[]); return; }
    if (s != errSecSuccess) {
      reject(@"E_OKINT_KEYS", [NSString stringWithFormat:@"Keychain enumerate failed (%d)", (int)s], nil);
      return;
    }
    NSArray *items = (__bridge_transfer NSArray *)result;
    NSMutableArray<NSString *> *keys = [NSMutableArray array];
    for (NSDictionary *item in items) {
      NSString *account = item[(__bridge id)kSecAttrAccount];
      if (account) [keys addObject:account];
    }
    resolve(keys);
    return;
  }
  if ([store isEqualToString:@"sqlite"]) {
    OkintEnsureTable(service);
    NSString *sql = [NSString stringWithFormat:@"SELECT k FROM %@", OkintTable(service)];
    sqlite3_stmt *stmt = NULL;
    NSMutableArray<NSString *> *keys = [NSMutableArray array];
    if (sqlite3_prepare_v2(OkintDB(), [sql UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
      while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *txt = sqlite3_column_text(stmt, 0);
        if (txt) [keys addObject:[NSString stringWithUTF8String:(const char *)txt]];
      }
    }
    sqlite3_finalize(stmt);
    resolve(keys);
    return;
  }
  NSString *suite = OkintScope(store, service);
  NSDictionary *domain = [OkintDefaults(store, service) persistentDomainForName:suite];
  resolve(domain ? [domain allKeys] : @[]);
}

@end
