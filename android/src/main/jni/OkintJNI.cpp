#include <jni.h>
#include <jsi/jsi.h>
#include <string>

#include "OkintJSI.h"

extern "C" JNIEXPORT void JNICALL
Java_com_okint_rnstorage_OkintRnStorageModule_nativeInstallJSI(
    JNIEnv *env, jobject /* thiz */, jlong jsiPtr, jstring dir) {
  if (jsiPtr == 0) return;
  auto *runtime = reinterpret_cast<facebook::jsi::Runtime *>(jsiPtr);
  const char *d = env->GetStringUTFChars(dir, nullptr);
  okint::install(*runtime, std::string(d ? d : ""));
  if (d) env->ReleaseStringUTFChars(dir, d);
}
