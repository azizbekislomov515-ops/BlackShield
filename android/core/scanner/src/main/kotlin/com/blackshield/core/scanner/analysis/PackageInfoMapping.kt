package com.blackshield.core.scanner.analysis

import android.content.pm.ComponentInfo
import android.content.pm.PackageInfo
import android.content.pm.Signature
import android.os.Build
import com.blackshield.core.scanner.analysis.manifest.ComponentKind
import com.blackshield.core.scanner.analysis.manifest.IntentFilterSpec

// Mapping from PackageManager's PackageInfo to the analysis model.

/** Components as PackageManager resolves them, with intent filters from the parsed manifest. */
internal fun PackageInfo.components(filters: Map<String, List<IntentFilterSpec>>): List<AppComponent> = buildList {
    fun add(kind: ComponentKind, info: ComponentInfo, permission: String?) {
        add(AppComponent(kind, info.name, info.exported, permission, filters[info.name].orEmpty()))
    }
    activities.orEmpty().forEach { activity ->
        val kind = if (activity.targetActivity != null) ComponentKind.ACTIVITY_ALIAS else ComponentKind.ACTIVITY
        add(kind, activity, activity.permission)
    }
    services.orEmpty().forEach { add(ComponentKind.SERVICE, it, it.permission) }
    receivers.orEmpty().forEach { add(ComponentKind.RECEIVER, it, it.permission) }
    providers.orEmpty().forEach { add(ComponentKind.PROVIDER, it, it.readPermission ?: it.writePermission) }
}

internal fun PackageInfo.grantedPermissions(): Set<String> {
    val names = requestedPermissions.orEmpty()
    val flags = requestedPermissionsFlags ?: IntArray(0)
    return names.indices
        .filter { it < flags.size && flags[it] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0 }
        .mapTo(HashSet()) { names[it] }
}

/** The certificates the current APK is signed with (after any key rotation). */
internal fun PackageInfo.signingCertificates(): List<SigningCertificate> {
    val signatures: Array<Signature>? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            signingInfo?.apkContentsSigners
        } else {
            @Suppress("DEPRECATION")
            signatures
        }
    return signatures.orEmpty().map { SigningCertificates.describe(it.toByteArray()) }
}

internal fun PackageInfo.mergeComponentsFrom(part: PackageInfo) {
    part.activities?.let { activities = it }
    part.services?.let { services = it }
    part.receivers?.let { receivers = it }
    part.providers?.let { providers = it }
}
