# App-specific R8 rules. Libraries (Hilt, Room, Retrofit, kotlinx.serialization, WorkManager)
# ship their own consumer rules; :core:scanner keeps its JNI methods.

# Keep line numbers so release stack traces stay readable after retracing.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Release builds log nothing: Timber has no tree outside debug builds, and these rules also remove the calls
# (and the strings they would build) from the code.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static boolean isLoggable(java.lang.String, int);
}
-assumenosideeffects class timber.log.Timber$Forest {
    public void v(...);
    public void d(...);
    public void i(...);
    public void w(...);
    public void e(...);
    public void wtf(...);
}
