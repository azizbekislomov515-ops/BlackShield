package com.blackshield.core.network.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * A crash report, sent only when the user turned crash reports on. Class names and stack frames only: no exception
 * messages, no device or user identifiers (the backend rejects anything else; see docs/privacy.md).
 */
@Serializable
data class CrashReportRequest(
    @SerialName("app_version") val appVersion: String,
    @SerialName("version_code") val versionCode: Int,
    @SerialName("android_sdk") val androidSdk: Int,
    @SerialName("occurred_at") val occurredAt: String,
    /** Outermost exception class first, then each cause. */
    val exceptions: List<String>,
    /** Frames of the root cause, top first, e.g. "com.blackshield.app.a.b(SourceFile:12)". */
    val frames: List<String>
)
