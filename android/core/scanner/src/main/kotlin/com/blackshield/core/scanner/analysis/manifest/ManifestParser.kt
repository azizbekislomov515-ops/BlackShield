package com.blackshield.core.scanner.analysis.manifest

/**
 * Builds [ManifestInfo] from a binary AndroidManifest.xml.
 *
 * Mirrors how the platform reads the manifest, so a manifest crafted to look different to analysis
 * tools is read the way Android reads it:
 *
 * - `android:` attributes are identified by resource ID (the resource map), not by their name
 *   string, which packers rename. The name is only a fallback when there is no resource map.
 * - Elements count only at their proper place (an `<activity>` outside `<application>` is
 *   ignored); only the first `<application>` is read.
 * - Class names are resolved like the framework: `.Foo` and `Foo` are relative to the package.
 */
object ManifestParser {
    private const val ANDROID_NS = "http://schemas.android.com/apk/res/android"
    private const val MAX_DEPTH = 64

    // Element depths: manifest (1) > application (2) > component (3) > intent-filter (4) > action (5).
    private const val COMPONENT_DEPTH = 3
    private const val FILTER_DEPTH = 4
    private const val FILTER_ITEM_DEPTH = 5

    private val COMPONENT_TAGS =
        mapOf(
            "activity" to ComponentKind.ACTIVITY,
            "activity-alias" to ComponentKind.ACTIVITY_ALIAS,
            "service" to ComponentKind.SERVICE,
            "receiver" to ComponentKind.RECEIVER,
            "provider" to ComponentKind.PROVIDER
        )

    /** @throws ManifestParseException if the data is not a readable binary manifest. */
    // Deliberately broad: the safety net must catch whatever a parser bug on hostile input throws.
    @Suppress("TooGenericExceptionCaught")
    fun parse(bytes: ByteArray): ManifestInfo = try {
        Builder().apply { BinaryXmlReader(bytes).events().forEach(::accept) }.build()
    } catch (e: ManifestParseException) {
        throw e
    } catch (e: RuntimeException) {
        // A malformed file must never crash a scan (that would let malware evade detection): any parser bug on
        // hostile input (out-of-bounds read, overflow) is reported as an unreadable manifest instead.
        throw ManifestParseException("malformed manifest (${e.javaClass.simpleName})", e)
    }

    private class Builder {
        private val path = ArrayList<String>()
        private var packageName: String? = null
        private var minSdk: Int? = null
        private var targetSdk: Int? = null
        private val permissions = LinkedHashSet<String>()
        private var applicationClass: String? = null
        private var debuggable: Boolean? = null
        private var applicationsSeen = 0
        private val components = ArrayList<ManifestComponent>()

        private var component: ManifestComponent? = null
        private var filters = ArrayList<IntentFilterSpec>()
        private var filter: IntentFilterSpec? = null

        fun accept(event: XmlEvent) {
            when (event) {
                is XmlEvent.StartElement -> start(event)
                is XmlEvent.EndElement -> end()
            }
        }

        private fun start(element: XmlEvent.StartElement) {
            path += element.name
            if (path.size > MAX_DEPTH) throw ManifestParseException("elements nested too deeply")
            val attrs = Attributes(element.attributes)
            when (path.joinToString("/")) {
                "manifest" -> packageName = attrs.plain("package")

                "manifest/uses-sdk" -> {
                    minSdk = attrs.int(android.R.attr.minSdkVersion, "minSdkVersion")
                    targetSdk = attrs.int(android.R.attr.targetSdkVersion, "targetSdkVersion")
                }

                "manifest/uses-permission", "manifest/uses-permission-sdk-23" ->
                    attrs.text(android.R.attr.name, "name")?.let(permissions::add)

                "manifest/application" -> if (++applicationsSeen == 1) {
                    applicationClass = attrs.text(android.R.attr.name, "name")?.let(::className)
                    debuggable = attrs.bool(android.R.attr.debuggable, "debuggable")
                }

                else -> startNested(element.name, attrs)
            }
        }

        private fun startNested(tag: String, attrs: Attributes) {
            val inFirstApplication = applicationsSeen == 1 && path.getOrNull(1) == "application"
            when {
                !inFirstApplication -> Unit

                path.size == COMPONENT_DEPTH && tag in COMPONENT_TAGS -> {
                    val name = attrs.text(android.R.attr.name, "name")?.let(::className)
                    component = name?.let {
                        ManifestComponent(
                            kind = COMPONENT_TAGS.getValue(tag),
                            name = it,
                            exported = attrs.bool(android.R.attr.exported, "exported"),
                            enabled = attrs.bool(android.R.attr.enabled, "enabled"),
                            permission = attrs.text(android.R.attr.permission, "permission"),
                            targetActivity =
                                attrs.text(android.R.attr.targetActivity, "targetActivity")?.let(::className)
                        )
                    }
                    filters = ArrayList()
                }

                path.size == FILTER_DEPTH && tag == "intent-filter" && component != null ->
                    filter = IntentFilterSpec(priority = attrs.int(android.R.attr.priority, "priority") ?: 0)

                path.size == FILTER_ITEM_DEPTH && filter != null -> filter = filter?.let { addToFilter(it, tag, attrs) }
            }
        }

        private fun addToFilter(spec: IntentFilterSpec, tag: String, attrs: Attributes): IntentFilterSpec = when (tag) {
            "action" -> attrs.text(android.R.attr.name, "name")?.let { spec.copy(actions = spec.actions + it) } ?: spec

            "category" -> attrs.text(android.R.attr.name, "name")?.let { spec.copy(categories = spec.categories + it) }
                ?: spec

            "data" -> spec.copy(
                schemes = spec.schemes + listOfNotNull(attrs.text(android.R.attr.scheme, "scheme")),
                hosts = spec.hosts + listOfNotNull(attrs.text(android.R.attr.host, "host"))
            )

            else -> spec
        }

        private fun end() {
            when (path.size) {
                FILTER_DEPTH -> filter?.let(filters::add).also { filter = null }

                COMPONENT_DEPTH -> {
                    component?.let { components += it.copy(intentFilters = filters.toList()) }
                    component = null
                }
            }
            if (path.isNotEmpty()) path.removeAt(path.lastIndex)
        }

        /** PackageParser.buildClassName: `.Foo` and `Foo` are relative to the package. */
        private fun className(name: String): String? {
            val trimmed = name.trim()
            val pkg = packageName.orEmpty()
            return when {
                trimmed.isEmpty() -> null
                trimmed.startsWith('.') -> pkg + trimmed
                '.' !in trimmed -> "$pkg.$trimmed"
                else -> trimmed
            }
        }

        fun build(): ManifestInfo = ManifestInfo(
            packageName = packageName ?: throw ManifestParseException("no <manifest package>"),
            minSdk = minSdk,
            targetSdk = targetSdk,
            usesPermissions = permissions,
            applicationClass = applicationClass,
            debuggable = debuggable,
            components = components
        )
    }

    private class Attributes(private val all: List<XmlAttribute>) {
        /** By resource ID when the manifest has a resource map; by name only as a fallback. */
        private fun find(resourceId: Int, name: String): XmlAttribute? = all.firstOrNull { it.resourceId == resourceId }
            ?: all.firstOrNull { it.resourceId == null && it.namespace == ANDROID_NS && it.name == name }

        fun text(resourceId: Int, name: String): String? =
            (find(resourceId, name)?.value as? AttributeValue.Text)?.value?.takeIf { it.isNotBlank() }

        fun bool(resourceId: Int, name: String): Boolean? =
            (find(resourceId, name)?.value as? AttributeValue.Bool)?.value

        fun int(resourceId: Int, name: String): Int? = when (val value = find(resourceId, name)?.value) {
            is AttributeValue.Integer -> value.value
            is AttributeValue.Text -> value.value.trim().toIntOrNull()
            else -> null
        }

        /** Attributes without a namespace, such as `<manifest package>`. */
        fun plain(name: String): String? =
            (all.firstOrNull { it.namespace == null && it.name == name }?.value as? AttributeValue.Text)?.value
    }
}
