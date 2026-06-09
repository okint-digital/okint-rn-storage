#import <Foundation/Foundation.h>
#import <React/RCTBridge.h>
#import <React/RCTBridge+Private.h>
#import <jsi/jsi.h>

#import "OkintJSI.h"

/**
 * Installs the okint C++/JSI engine into the bridge's JS runtime. Isolated in an
 * Obj-C++ (.mm) file so the main Obj-C module stays free of C++.
 *
 * `extern "C"` is REQUIRED: this is declared in OkintRnStorage.m (a .m file, C
 * linkage) and called from there. Without it, the C++ compiler name-mangles the
 * symbol and the linker fails with "Undefined symbol _OkintInstallJSIForBridge".
 */
extern "C" BOOL OkintInstallJSIForBridge(RCTBridge *bridge) {
  RCTCxxBridge *cxxBridge = (RCTCxxBridge *)bridge;
  if (cxxBridge == nil || ![cxxBridge respondsToSelector:@selector(runtime)]) {
    return NO;
  }
  void *runtimePtr = cxxBridge.runtime;
  if (runtimePtr == NULL) {
    return NO;
  }
  NSString *dir = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES).firstObject;
  const char *dirUtf8 = [dir UTF8String];
  if (dir == nil || dirUtf8 == NULL) {
    return NO; // no writable dir → don't pass a NULL c-string into std::string (UB)
  }
  okint::install(*reinterpret_cast<facebook::jsi::Runtime *>(runtimePtr), std::string(dirUtf8));
  return YES;
}
