# HexRDP ProGuard Rules

# Keep application class
-keep class com.gotohex.rdp.** { *; }

# Hilt
-keepnames @dagger.hilt.android.lifecycle.HiltViewModel class * extends androidx.lifecycle.ViewModel

# Room
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-keepclassmembers @androidx.room.Entity class * { *; }

# Gson
-keepattributes Signature
-keepattributes *Annotation*
-dontwarn sun.misc.**
-keep class com.google.gson.** { *; }

# Kotlin Coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}

# BouncyCastle - needed for TLS/NLA
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Compose
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**

# Coil
-dontwarn coil.**

# General Android
-keepattributes *Annotation*
-keepattributes SourceFile,LineNumberTable
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
