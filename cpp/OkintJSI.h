#pragma once

#include <jsi/jsi.h>
#include <string>

namespace okint {

/**
 * Installs the okint JSI fast path into the given runtime. Exposes a global
 * function `global.__okintCreateJSI(namespace)` that returns a HostObject with
 * synchronous get/set/remove/clear/getAllKeys/contains — direct C++ access with
 * no bridge serialization (the maximum-performance synchronous path).
 *
 * `storageDir` is a writable directory; each namespace persists to its own file.
 */
void install(facebook::jsi::Runtime &rt, const std::string &storageDir);

} // namespace okint
