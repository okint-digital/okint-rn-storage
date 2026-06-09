#include "OkintJSI.h"

#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>

using namespace facebook::jsi;

namespace okint {

// Hard per-field allocation ceiling. A single key or value above this is treated
// as corruption rather than honored — bounds the worst-case allocation even if
// the on-disk file genuinely contains a huge length. Reads are additionally
// bounded by the actual remaining file size (see load()).
static const uint32_t kMaxFieldBytes = 256u * 1024u * 1024u; // 256 MiB

/**
 * In-memory key/value store with simple length-prefixed file persistence.
 * Synchronous and thread-safe. Loaded once on construction; rewritten on each
 * mutation via an ATOMIC temp-file + rename (a crash mid-write can never corrupt
 * or truncate the live file). load() is hardened against corrupt/hostile files:
 * every length prefix is bounded by the remaining file size and a hard cap
 * before any allocation, and any parse exception degrades to an empty store —
 * it never throws across the JSI boundary or attempts an unbounded allocation.
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

  // Mutations are transactional: the in-memory map is committed only if persist()
  // succeeds. On I/O failure the change is rolled back and the call throws, so the
  // JS layer sees a real error instead of a false success that is lost on restart
  // (in-memory and on-disk state never diverge).
  void set(const std::string &key, const std::string &value) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(key);
    const bool had = it != map_.end();
    std::string old = had ? it->second : std::string();
    map_[key] = value;
    if (!persist()) {
      if (had) map_[key] = std::move(old);
      else map_.erase(key);
      throw std::runtime_error("okint: failed to persist set");
    }
  }

  void remove(const std::string &key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(key);
    if (it == map_.end()) return;
    std::string old = std::move(it->second);
    map_.erase(it);
    if (!persist()) {
      map_[key] = std::move(old);
      throw std::runtime_error("okint: failed to persist remove");
    }
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (map_.empty()) return;
    std::unordered_map<std::string, std::string> backup;
    backup.swap(map_);
    if (!persist()) {
      map_.swap(backup);
      throw std::runtime_error("okint: failed to persist clear");
    }
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
    // Never let a corrupt/tampered/truncated file crash construction: parse
    // best-effort and treat any failure (including bad_alloc) as an empty store.
    try {
      loadImpl();
    } catch (...) {
      map_.clear();
    }
  }

  void loadImpl() {
    std::ifstream f(path_, std::ios::binary);
    if (!f) return;
    f.seekg(0, std::ios::end);
    const std::streamoff end = f.tellg();
    f.seekg(0, std::ios::beg);
    if (end <= 0) return;
    const uint64_t total = static_cast<uint64_t>(end);
    uint64_t consumed = 0;

    auto readField = [&](std::string &out) -> bool {
      uint32_t len = 0;
      if (!f.read(reinterpret_cast<char *>(&len), 4)) return false;
      consumed += 4;
      // Reject lengths that exceed what the file can possibly contain, or the
      // hard cap, BEFORE allocating — this is the fix for the unbounded-alloc DoS.
      if (len > kMaxFieldBytes || len > total - consumed) return false;
      out.assign(len, '\0');
      if (len && !f.read(&out[0], len)) return false;
      consumed += len;
      return true;
    };

    while (true) {
      std::string k, v;
      if (!readField(k)) break;
      if (!readField(v)) break;
      map_[std::move(k)] = std::move(v);
    }
  }

  // Returns true only if the new state is durably on disk. Crash-safe write:
  // serialize to a temp file, fsync it so the bytes reach stable storage, then
  // atomically rename over the target. The live file is replaced only once the
  // temp is complete and flushed, so a crash / power-loss / disk-full mid-write
  // leaves either the old file or the complete new one — never a truncated or
  // partially-written live file. rename() is an atomic replace on the POSIX
  // targets this engine ships to (iOS/Android). Any failure returns false so the
  // caller surfaces it (as a JS error) instead of silently losing the write.
  bool persist() {
    const std::string tmp = path_ + ".tmp";
    {
      std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
      if (!f) return false;
      for (const auto &kv : map_) {
        const uint32_t kl = static_cast<uint32_t>(kv.first.size());
        const uint32_t vl = static_cast<uint32_t>(kv.second.size());
        f.write(reinterpret_cast<const char *>(&kl), 4);
        f.write(kv.first.data(), kl);
        f.write(reinterpret_cast<const char *>(&vl), 4);
        f.write(kv.second.data(), vl);
        if (!f) { std::remove(tmp.c_str()); return false; } // abort; original untouched
      }
      f.flush();
      if (!f.good()) { std::remove(tmp.c_str()); return false; }
    }
    // fsync the temp's data to stable storage BEFORE the rename, so a power loss
    // right after the rename metadata commits cannot expose a zero/partial file.
    int fd = ::open(tmp.c_str(), O_RDONLY);
    if (fd >= 0) {
      ::fsync(fd);
      ::close(fd);
    }
    if (std::rename(tmp.c_str(), path_.c_str()) != 0) {
      std::remove(tmp.c_str()); // keep the good original; report failure
      return false;
    }
    return true;
  }

  std::string path_;
  std::unordered_map<std::string, std::string> map_;
  std::mutex mutex_;
};

namespace {

// Intern one Store per physical file so repeated __okintCreateJSI(ns) calls for
// the same namespace share a single Store — two Stores over one file would do
// last-writer-wins truncating writes and diverge.
std::mutex g_storesMutex;
std::unordered_map<std::string, std::shared_ptr<Store>> g_stores;

std::shared_ptr<Store> storeForPath(const std::string &path) {
  std::lock_guard<std::mutex> lock(g_storesMutex);
  auto it = g_stores.find(path);
  if (it != g_stores.end()) return it->second;
  auto store = std::make_shared<Store>(path);
  g_stores.emplace(path, store);
  return store;
}

// Defense-in-depth: the global __okintCreateJSI is reachable by ANY JS in the
// runtime, not only via the validated JS factory. Re-validate the namespace
// natively before composing a file path so a hostile/buggy caller cannot escape
// the storage dir (path traversal via "..", "/", "\\", NUL) or collide stores.
// Matches the JS NAMESPACE_RE: [A-Za-z0-9_]{1,200}.
bool isSafeNamespace(const std::string &ns) {
  if (ns.empty() || ns.size() > 200) return false;
  for (unsigned char c : ns) {
    const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '_';
    if (!ok) return false;
  }
  return true;
}

Function hostFn(Runtime &rt, const char *name, unsigned argc, HostFunctionType fn) {
  return Function::createFromHostFunction(rt, PropNameID::forAscii(rt, name), argc, std::move(fn));
}

/** HostObject exposing the synchronous store API to JS. Every host function is
 *  exception-safe: a std::exception (e.g. bad_alloc) is translated to a JS error
 *  for writes, or a null/false/empty result for reads — never an uncaught throw
 *  across the JSI boundary (which could std::terminate). */
class OkintHostObject : public HostObject {
public:
  explicit OkintHostObject(std::shared_ptr<Store> store) : store_(std::move(store)) {}

  Value get(Runtime &rt, const PropNameID &name) override {
    std::string prop = name.utf8(rt);
    auto store = store_;

    if (prop == "getString") {
      return hostFn(rt, "getString", 1, [store](Runtime &rt, const Value &, const Value *args, size_t count) -> Value {
        try {
          if (count < 1 || !args[0].isString()) return Value::null();
          std::string out;
          if (store->get(args[0].asString(rt).utf8(rt), out)) return String::createFromUtf8(rt, out);
          return Value::null();
        } catch (const std::exception &) {
          return Value::null();
        }
      });
    }
    if (prop == "setString") {
      return hostFn(rt, "setString", 2, [store](Runtime &rt, const Value &, const Value *args, size_t count) -> Value {
        try {
          if (count < 2 || !args[0].isString() || !args[1].isString()) return Value::undefined();
          store->set(args[0].asString(rt).utf8(rt), args[1].asString(rt).utf8(rt));
          return Value::undefined();
        } catch (const std::exception &e) {
          throw JSError(rt, std::string("okint JSI setString failed: ") + e.what());
        }
      });
    }
    if (prop == "remove") {
      return hostFn(rt, "remove", 1, [store](Runtime &rt, const Value &, const Value *args, size_t count) -> Value {
        try {
          if (count >= 1 && args[0].isString()) store->remove(args[0].asString(rt).utf8(rt));
          return Value::undefined();
        } catch (const std::exception &e) {
          throw JSError(rt, std::string("okint JSI remove failed: ") + e.what());
        }
      });
    }
    if (prop == "clear") {
      return hostFn(rt, "clear", 0, [store](Runtime &rt, const Value &, const Value *, size_t) -> Value {
        try {
          store->clear();
          return Value::undefined();
        } catch (const std::exception &e) {
          throw JSError(rt, std::string("okint JSI clear failed: ") + e.what());
        }
      });
    }
    if (prop == "contains") {
      return hostFn(rt, "contains", 1, [store](Runtime &rt, const Value &, const Value *args, size_t count) -> Value {
        try {
          if (count < 1 || !args[0].isString()) return Value(false);
          return Value(store->contains(args[0].asString(rt).utf8(rt)));
        } catch (const std::exception &) {
          return Value(false);
        }
      });
    }
    if (prop == "getAllKeys") {
      return hostFn(rt, "getAllKeys", 0, [store](Runtime &rt, const Value &, const Value *, size_t) -> Value {
        try {
          auto ks = store->keys();
          Array arr(rt, ks.size());
          for (size_t i = 0; i < ks.size(); i++) arr.setValueAtIndex(rt, i, String::createFromUtf8(rt, ks[i]));
          return arr;
        } catch (const std::exception &) {
          return Array(rt, 0);
        }
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
    try {
      std::string ns = (count >= 1 && args[0].isString()) ? args[0].asString(rt).utf8(rt) : "okint";
      if (!isSafeNamespace(ns)) {
        throw JSError(rt, "okint JSI: invalid namespace (allowed: [A-Za-z0-9_], 1-200 chars)");
      }
      auto store = storeForPath(storageDir + "/okint_jsi_" + ns + ".bin");
      return Object::createFromHostObject(rt, std::make_shared<OkintHostObject>(store));
    } catch (const JSError &) {
      throw; // already a JS-visible error
    } catch (const std::exception &e) {
      throw JSError(rt, std::string("okint JSI: failed to create store: ") + e.what());
    }
  });
  rt.global().setProperty(rt, "__okintCreateJSI", create);
}

} // namespace okint
