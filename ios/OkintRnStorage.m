#import <React/RCTBridgeModule.h>
#import <Security/Security.h>

/**
 * okint-rn-storage — iOS native module (Objective-C for maximum compatibility:
 * no Swift bridging-header / use_frameworks! pitfalls).
 *
 *   - secure = YES → Keychain (kSecClassGenericPassword), accessible after first
 *                    unlock, this-device-only (never synced to iCloud / migrated
 *                    in encrypted backups). For JWTs / FCM / secrets.
 *   - secure = NO  → a per-namespace NSUserDefaults suite. For non-sensitive data.
 *
 * Each `service` (namespace) is isolated via the Keychain service attribute or a
 * dedicated UserDefaults suite. Works under the New Architecture interop layer.
 */
@interface OkintRnStorage : NSObject <RCTBridgeModule>
@end

@implementation OkintRnStorage

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup { return NO; }

#pragma mark - Helpers

static NSString *OkintServiceName(NSString *service) {
  return [NSString stringWithFormat:@"okint.%@", service];
}

static NSUserDefaults *OkintDefaults(NSString *service) {
  NSUserDefaults *d = [[NSUserDefaults alloc] initWithSuiteName:OkintServiceName(service)];
  return d ?: [NSUserDefaults standardUserDefaults];
}

/** Base Keychain query. `key` may be nil for service-wide operations. */
static NSMutableDictionary *OkintBaseQuery(NSString *service, NSString *_Nullable key) {
  NSMutableDictionary *q = [NSMutableDictionary dictionary];
  q[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
  q[(__bridge id)kSecAttrService] = OkintServiceName(service);
  // Use the modern data-protection keychain (default on iOS; required for
  // correctness on macOS/Catalyst). Keep it consistent across all operations.
  q[(__bridge id)kSecUseDataProtectionKeychain] = @YES;
  if (key) {
    q[(__bridge id)kSecAttrAccount] = key;
  }
  return q;
}

#pragma mark - Methods

RCT_EXPORT_METHOD(setItem:(NSString *)service
                  key:(NSString *)key
                  value:(NSString *)value
                  secure:(BOOL)secure
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
  if (!secure) {
    [OkintDefaults(service) setObject:value forKey:key];
    resolve([NSNull null]);
    return;
  }

  NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];

  // Add-or-update: update touches only the data attribute (search keys must not
  // appear in the update dict or Keychain returns errSecDuplicateItem).
  NSMutableDictionary *query = OkintBaseQuery(service, key);
  NSDictionary *attrs = @{ (__bridge id)kSecValueData: data };
  OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attrs);

  if (status == errSecItemNotFound) {
    NSMutableDictionary *add = OkintBaseQuery(service, key);
    add[(__bridge id)kSecValueData] = data;
    add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    status = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
  }

  if (status == errSecSuccess) {
    resolve([NSNull null]);
  } else {
    reject(@"E_OKINT_SET", [NSString stringWithFormat:@"Keychain set failed (%d)", (int)status], nil);
  }
}

RCT_EXPORT_METHOD(getItem:(NSString *)service
                  key:(NSString *)key
                  secure:(BOOL)secure
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
  if (!secure) {
    NSString *v = [OkintDefaults(service) stringForKey:key];
    resolve(v ?: [NSNull null]);
    return;
  }

  NSMutableDictionary *query = OkintBaseQuery(service, key);
  query[(__bridge id)kSecReturnData] = @YES;
  query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

  if (status == errSecSuccess) {
    NSData *data = (__bridge_transfer NSData *)result;
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    resolve(str ?: [NSNull null]);
  } else if (status == errSecItemNotFound) {
    resolve([NSNull null]);
  } else {
    reject(@"E_OKINT_GET", [NSString stringWithFormat:@"Keychain get failed (%d)", (int)status], nil);
  }
}

RCT_EXPORT_METHOD(removeItem:(NSString *)service
                  key:(NSString *)key
                  secure:(BOOL)secure
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
  if (!secure) {
    [OkintDefaults(service) removeObjectForKey:key];
    resolve([NSNull null]);
    return;
  }

  OSStatus status = SecItemDelete((__bridge CFDictionaryRef)OkintBaseQuery(service, key));
  if (status == errSecSuccess || status == errSecItemNotFound) {
    resolve([NSNull null]);
  } else {
    reject(@"E_OKINT_REMOVE", [NSString stringWithFormat:@"Keychain delete failed (%d)", (int)status], nil);
  }
}

RCT_EXPORT_METHOD(clear:(NSString *)service
                  secure:(BOOL)secure
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
  if (!secure) {
    // Use the SAME suite instance used for writes, and clear its own domain
    // (mixing standardUserDefaults with a suite instance reads/writes a
    // different domain and would silently no-op).
    NSString *suite = OkintServiceName(service);
    [OkintDefaults(service) removePersistentDomainForName:suite];
    resolve([NSNull null]);
    return;
  }

  OSStatus status = SecItemDelete((__bridge CFDictionaryRef)OkintBaseQuery(service, nil));
  if (status == errSecSuccess || status == errSecItemNotFound) {
    resolve([NSNull null]);
  } else {
    reject(@"E_OKINT_CLEAR", [NSString stringWithFormat:@"Keychain clear failed (%d)", (int)status], nil);
  }
}

RCT_EXPORT_METHOD(getAllKeys:(NSString *)service
                  secure:(BOOL)secure
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
  if (!secure) {
    // Same suite instance + its own domain — returns ONLY this suite's keys
    // (dictionaryRepresentation would also include global/registration domains).
    NSString *suite = OkintServiceName(service);
    NSDictionary *domain = [OkintDefaults(service) persistentDomainForName:suite];
    resolve(domain ? [domain allKeys] : @[]);
    return;
  }

  NSMutableDictionary *query = OkintBaseQuery(service, nil);
  query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
  query[(__bridge id)kSecReturnAttributes] = @YES; // attributes only — don't decrypt values

  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

  if (status == errSecItemNotFound) {
    resolve(@[]);
    return;
  }
  if (status != errSecSuccess) {
    reject(@"E_OKINT_KEYS", [NSString stringWithFormat:@"Keychain enumerate failed (%d)", (int)status], nil);
    return;
  }

  NSArray *items = (__bridge_transfer NSArray *)result;
  NSMutableArray<NSString *> *keys = [NSMutableArray array];
  for (NSDictionary *item in items) {
    NSString *account = item[(__bridge id)kSecAttrAccount];
    if (account) {
      [keys addObject:account];
    }
  }
  resolve(keys);
}

@end
