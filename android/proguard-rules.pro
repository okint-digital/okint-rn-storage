# okint-rn-storage — consumer ProGuard/R8 rules.
# Keep the module + its JNI entry point so autolinking and the native
# System.loadLibrary("okint") / nativeInstallJSI binding survive minification.

-keep class com.okint.rnstorage.** { *; }
-keepclasseswithmembernames class com.okint.rnstorage.** {
  native <methods>;
}
