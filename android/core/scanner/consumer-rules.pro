# JNI looks up native methods by class and method name, so neither may be renamed.
-keepclasseswithmembernames,includedescriptorclasses class com.blackshield.core.scanner.** {
    native <methods>;
}
