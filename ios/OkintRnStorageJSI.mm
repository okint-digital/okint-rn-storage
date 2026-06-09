#import <Foundation/Foundation.h>
#import <React/RCTBridge.h>
#import <React/RCTBridge+Private.h>
#import <jsi/jsi.h>

#import "OkintJSI.h"

/**
 * Installs the okint C++/JSI engine into the bridge's JS runtime. Isolated in an
 * Obj-C++ (.mm) file so the main Obj-C module stays free of C++.
 */
BOOL OkintInstallJSIForBridge(RCTBridge *bridge) {
  RCTCxxBridge *cxxBridge = (RCTCxxBridge *)bridge;
  if (cxxBridge == nil || ![cxxBridge respondsToSelector:@selector(runtime)]) {
    return NO;
  }
  void *runtimePtr = cxxBridge.runtime;
  if (runtimePtr == NULL) {
    return NO;
  }
  NSString *dir = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES).firstObject;
  okint::install(*reinterpret_cast<facebook::jsi::Runtime *>(runtimePtr), std::string([dir UTF8String]));
  return YES;
}
