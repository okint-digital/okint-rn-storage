#include "OkintJSI.h"

#include <cstdint>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

using namespace facebook::jsi;

namespace okint {

/**
 * In-memory key/value store with simple length-prefixed file persistence.
 * Synchronous and thread-safe. Loaded once on construction; rewritten on each
 * mutation (correct + simple; a future mmap engine can make writes incremental).
 */
class Store {
public:
  explicit Store(std::string path) : path_(std::move(path)) { load(); }

  bool get(const std::string &key, std::string &out) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(key);
    if (it == map_.end()) return false;
    out = it->second;
    return true;
  }

  void set(const std::string &key, const std::string &value) {
    std::lock_guard<std::mutex> lock(mutex_);
    map_[key] = value;
    persist();
  }

  void remove(const std::string &key) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (map_.erase(key) > 0) persist();
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    map_.clear();
    persist();
  }

  bool contains(const std::string &key) {
    std::lock_guard<std::mutex> lock(mutex_);
    return map_.find(key) != map_.end();
  }

  std::vector<std::string> keys() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> out;
    out.reserve(map_.size());
    for (const auto &kv : map_) out.push_back(kv.first);
    return out;
  }

private:
  void load() {
    std::ifstream f(path_, std::ios::binary);
    if (!f) return;
    while (true) {
      uint32_t kl = 0, vl = 0;
      if (!f.read(reinterpret_cast<char *>(&kl), 4)) break;
      std::string k(kl, '\0');
      if (kl && !f.read(&k[0], kl)) break;
      if (!f.read(reinterpret_cast<char *>(&vl), 4)) break;
      std::string v(vl, '\0');
      if (vl && !f.read(&v[0], vl)) break;
      map_[std::move(k)] = std::move(v);
    }
  }

  void persist() {
    std::ofstream f(path_, std::ios::binary | std::ios::trunc);
    if (!f) return;
    for (const auto &kv : map_) {
      uint32_t kl = static_cast<uint32_t>(kv.first.size());
      uint32_t vl = static_cast<uint32_t>(kv.second.size());
      f.write(reinterpret_cast<const char *>(&kl), 4);
      f.write(kv.first.data(), kl);
      f.write(reinterpret_cast<const char *>(&vl), 4);
      f.write(kv.second.data(), vl);
    }
  }

  std::string path_;
  std::unordered_map<std::string, std::string> map_;
  std::mutex mutex_;
};

namespace {

Function hostFn(Runtime &rt, const char *name, unsigned argc, HostFunctionType fn) {
  return Function::createFromHostFunction(rt, PropNameID::forAscii(rt, name), argc, std::move(fn));
}

/** HostObject exposing the synchronous store API to JS. */
class OkintHostObject : public HostObject {
public:
  explicit OkintHostObject(std::shared_ptr<Store> store) : store_(std::move(store)) {}

  Value get(Runtime &rt, const PropNameID &name) override {
    std::string prop = name.utf8(rt);
    auto store = store_;

    if (prop == "getString") {
      return hostFn(rt, "getString", 1, [store](Runtime &rt, const Value &, const Value *args, size_t count) -> Value {
        if (count < 1 || !args[0].isString()) return Value::null();
        std::string out;
        if (store->get(args[0].asString(rt).utf8(rt), out)) return String::createFromUtf8(rt, out);
        return Value::null();
      });
    }
    if (prop == "setString") {
      return hostFn(rt, "setString", 2, [store](Runtime &rt, const Value &, const Value *args, size_t count) -> Value {
        if (count < 2 || !args[0].isString() || !args[1].isString()) return Value::undefined();
        store->set(args[0].asString(rt).utf8(rt), args[1].asString(rt).utf8(rt));
        return Value::undefined();
      });
    }
    if (prop == "remove") {
      return hostFn(rt, "remove", 1, [store](Runtime &rt, const Value &, const Value *args, size_t count) -> Value {
        if (count >= 1 && args[0].isString()) store->remove(args[0].asString(rt).utf8(rt));
        return Value::undefined();
      });
    }
    if (prop == "clear") {
      return hostFn(rt, "clear", 0, [store](Runtime &, const Value &, const Value *, size_t) -> Value {
        store->clear();
        return Value::undefined();
      });
    }
    if (prop == "contains") {
      return hostFn(rt, "contains", 1, [store](Runtime &rt, const Value &, const Value *args, size_t count) -> Value {
        if (count < 1 || !args[0].isString()) return Value(false);
        return Value(store->contains(args[0].asString(rt).utf8(rt)));
      });
    }
    if (prop == "getAllKeys") {
      return hostFn(rt, "getAllKeys", 0, [store](Runtime &rt, const Value &, const Value *, size_t) -> Value {
        auto ks = store->keys();
        Array arr(rt, ks.size());
        for (size_t i = 0; i < ks.size(); i++) arr.setValueAtIndex(rt, i, String::createFromUtf8(rt, ks[i]));
        return arr;
      });
    }
    return Value::undefined();
  }

private:
  std::shared_ptr<Store> store_;
};

} // namespace

void install(Runtime &rt, const std::string &storageDir) {
  auto create = hostFn(rt, "__okintCreateJSI", 1, [storageDir](Runtime &rt, const Value &, const Value *args, size_t count) -> Value {
    std::string ns = (count >= 1 && args[0].isString()) ? args[0].asString(rt).utf8(rt) : "okint";
    auto store = std::make_shared<Store>(storageDir + "/okint_jsi_" + ns + ".bin");
    return Object::createFromHostObject(rt, std::make_shared<OkintHostObject>(store));
  });
  rt.global().setProperty(rt, "__okintCreateJSI", create);
}

} // namespace okint
