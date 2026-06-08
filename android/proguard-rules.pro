# okint-rn-storage — consumer ProGuard/R8 rules.
# Tink (used by androidx.security EncryptedSharedPreferences) relies on
# reflection-based protobuf parsing of its keyset. Without these keeps, R8 can
# strip classes and break keyset loading at runtime (surfacing as corruption).

-keep class com.google.crypto.tink.** { *; }
-keep class com.google.crypto.tink.shaded.protobuf.** { *; }
-keepclassmembers class * extends com.google.crypto.tink.shaded.protobuf.GeneratedMessageLite {
  <fields>;
}
-dontwarn com.google.crypto.tink.**
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**

# AndroidX Security crypto
-keep class androidx.security.crypto.** { *; }
-dontwarn androidx.security.crypto.**

# Our module (autolinking / reflection by RN)
-keep class com.okint.rnstorage.** { *; }
