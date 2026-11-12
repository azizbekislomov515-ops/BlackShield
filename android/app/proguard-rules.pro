# App-specific R8 rules. Libraries (Hilt, Room, Retrofit, kotlinx.serialization, WorkManager)
# ship their own consumer rules; :core:scanner keeps its JNI methods.

# Keep line numbers so release stack traces stay readable after retracing.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
