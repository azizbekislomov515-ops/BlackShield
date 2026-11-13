package com.blackshield.core.scanner.analysis.manifest

enum class ComponentKind { ACTIVITY, ACTIVITY_ALIAS, SERVICE, RECEIVER, PROVIDER }

data class IntentFilterSpec(
    val actions: List<String> = emptyList(),
    val categories: List<String> = emptyList(),
    val schemes: List<String> = emptyList(),
    val hosts: List<String> = emptyList(),
    val priority: Int = 0
)

/** A component as declared in the manifest. Booleans are null when absent or a resource reference. */
data class ManifestComponent(
    val kind: ComponentKind,
    /** Fully qualified class name, resolved like the platform does. */
    val name: String,
    val exported: Boolean? = null,
    val enabled: Boolean? = null,
    val permission: String? = null,
    /** For an activity-alias: the activity it launches. */
    val targetActivity: String? = null,
    val intentFilters: List<IntentFilterSpec> = emptyList()
) {
    val isLauncher: Boolean
        get() = (kind == ComponentKind.ACTIVITY || kind == ComponentKind.ACTIVITY_ALIAS) &&
            intentFilters.any { MAIN in it.actions && LAUNCHER in it.categories }

    private companion object {
        const val MAIN = "android.intent.action.MAIN"
        const val LAUNCHER = "android.intent.category.LAUNCHER"
    }
}

/** What BlackShield reads from AndroidManifest.xml: mainly what PackageManager does not expose (intent filters). */
data class ManifestInfo(
    val packageName: String,
    val minSdk: Int? = null,
    val targetSdk: Int? = null,
    val usesPermissions: Set<String> = emptySet(),
    /** `<application android:name>`: the Application subclass, where packers put their loader. */
    val applicationClass: String? = null,
    val debuggable: Boolean? = null,
    val components: List<ManifestComponent> = emptyList()
)
