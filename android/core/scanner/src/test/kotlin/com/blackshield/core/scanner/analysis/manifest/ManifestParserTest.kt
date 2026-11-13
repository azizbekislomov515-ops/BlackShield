package com.blackshield.core.scanner.analysis.manifest

import com.blackshield.core.scanner.analysis.manifest.AxmlBuilder.Attr
import com.blackshield.core.scanner.analysis.manifest.AxmlBuilder.Element
import com.blackshield.core.scanner.analysis.manifest.AxmlBuilder.Value
import java.util.Random
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ManifestParserTest {
    private fun fixture(name: String): ByteArray =
        checkNotNull(javaClass.getResourceAsStream("/manifests/$name.axml")) { "missing fixture $name" }.readBytes()

    @Test
    fun `reads an aapt2-compiled manifest`() {
        val info = ManifestParser.parse(fixture("suspicious"))

        assertEquals("com.example.fixture", info.packageName)
        assertEquals(21, info.minSdk)
        assertEquals(22, info.targetSdk)
        assertEquals(
            setOf(
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.REQUEST_INSTALL_PACKAGES"
            ),
            info.usesPermissions
        )
        assertEquals("com.stub.StubApp", info.applicationClass)
        assertEquals(
            listOf(
                ComponentKind.ACTIVITY to "com.example.fixture.MainActivity",
                ComponentKind.ACTIVITY_ALIAS to "com.example.fixture.LinkAlias",
                ComponentKind.SERVICE to "com.example.fixture.svc.Watcher",
                ComponentKind.RECEIVER to "a.b",
                ComponentKind.RECEIVER to "com.example.fixture.Admin",
                ComponentKind.PROVIDER to "com.example.fixture.Files"
            ),
            info.components.map { it.kind to it.name }
        )
    }

    @Test
    fun `reads component attributes and intent filters`() {
        val byName = ManifestParser.parse(fixture("suspicious")).components.associateBy {
            it.name.substringAfterLast('.')
        }

        val main = byName.getValue("MainActivity")
        assertTrue(main.isLauncher)
        assertEquals(true, main.exported)
        assertNull(main.enabled)

        val alias = byName.getValue("LinkAlias")
        assertFalse("a VIEW filter is not a launcher", alias.isLauncher)
        assertEquals(false, alias.enabled)
        assertEquals("com.example.fixture.MainActivity", alias.targetActivity)
        val view = alias.intentFilters.single()
        assertEquals(listOf("android.intent.action.VIEW"), view.actions)
        assertEquals(listOf("android.intent.category.DEFAULT", "android.intent.category.BROWSABLE"), view.categories)
        assertEquals(listOf("https"), view.schemes)
        assertEquals(listOf("example.com"), view.hosts)

        val watcher = byName.getValue("Watcher")
        assertEquals("android.permission.BIND_ACCESSIBILITY_SERVICE", watcher.permission)
        assertEquals(false, watcher.exported)
        assertEquals(
            listOf("android.accessibilityservice.AccessibilityService"),
            watcher.intentFilters.single().actions
        )

        val sms = byName.getValue("b")
        assertEquals(999, sms.intentFilters.single().priority)
        assertEquals(listOf("android.provider.Telephony.SMS_RECEIVED"), sms.intentFilters.single().actions)

        assertEquals("android.permission.BIND_DEVICE_ADMIN", byName.getValue("Admin").permission)
        assertTrue(byName.getValue("Files").intentFilters.isEmpty())
    }

    @Test
    fun `reads a minimal manifest`() {
        val info = ManifestParser.parse(fixture("minimal"))

        assertEquals("org.example.minimal", info.packageName)
        assertEquals(35, info.targetSdk)
        assertTrue(info.usesPermissions.isEmpty())
        assertNull(info.applicationClass)
        assertTrue(info.components.single().isLauncher)
    }

    @Test
    fun `reads UTF-8 and UTF-16 string pools the same way, including long strings`() {
        val longName = "com.example." + "x".repeat(300) + ".Main"
        val manifest = manifest(component("activity", longName, launcher = true))

        for (utf8 in listOf(true, false)) {
            val info = ManifestParser.parse(AxmlBuilder(utf8).build(manifest))
            assertEquals("utf8=$utf8", longName, info.components.single().name)
            assertTrue(info.components.single().isLauncher)
        }
    }

    @Test
    fun `identifies android attributes by resource ID, not by their name string`() {
        // Packers rename attribute strings to confuse tools; the platform only looks at the resource ID.
        val activity =
            Element(
                "activity",
                listOf(
                    Attr("name", Value.Str("com.decoy.Fake"), resourceId = null), // name string only: ignored
                    Attr("zz1", Value.Str(".Real"), resourceId = android.R.attr.name),
                    Attr("zz2", Value.Bool(true), resourceId = android.R.attr.exported)
                )
            )
        val component = ManifestParser.parse(AxmlBuilder().build(manifest(activity))).components.single()

        assertEquals("com.example.app.Real", component.name)
        assertEquals(true, component.exported)
    }

    @Test
    fun `falls back to attribute names when there is no resource map`() {
        val activity = Element("activity", listOf(Attr("name", Value.Str("Main"), resourceId = null)))

        assertEquals(
            "com.example.app.Main",
            ManifestParser.parse(AxmlBuilder().build(manifest(activity))).components.single().name
        )
    }

    @Test
    fun `resource references are unknown, not guessed`() {
        val activity =
            Element(
                "activity",
                listOf(
                    Attr("name", Value.Str(".Main"), resourceId = android.R.attr.name),
                    Attr("exported", Value.Ref(0x7f050001), resourceId = android.R.attr.exported)
                )
            )

        assertNull(ManifestParser.parse(AxmlBuilder().build(manifest(activity))).components.single().exported)
    }

    @Test
    fun `ignores components outside the first application`() {
        val root =
            Element(
                "manifest",
                listOf(Attr("package", Value.Str("com.example.app"), android = false)),
                listOf(
                    component("activity", ".Stray", launcher = true), // directly under <manifest>
                    Element("application", children = listOf(component("service", ".Real"))),
                    Element("application", children = listOf(component("service", ".Second")))
                )
            )

        assertEquals(
            listOf("com.example.app.Real"),
            ManifestParser.parse(AxmlBuilder().build(root)).components.map {
                it.name
            }
        )
    }

    @Test
    fun `components without a name are skipped`() {
        val nameless =
            Element("receiver", listOf(Attr("exported", Value.Bool(true), resourceId = android.R.attr.exported)))

        assertTrue(ManifestParser.parse(AxmlBuilder().build(manifest(nameless))).components.isEmpty())
    }

    @Test
    fun `rejects data that is not binary XML`() {
        assertThrows(ManifestParseException::class.java) { ManifestParser.parse("<manifest/>".toByteArray()) }
        assertThrows(ManifestParseException::class.java) { ManifestParser.parse(ByteArray(0)) }
        val noPackage = Element("manifest", children = listOf(Element("application")))
        assertThrows(ManifestParseException::class.java) { ManifestParser.parse(AxmlBuilder().build(noPackage)) }
    }

    @Test
    fun `truncated manifests fail cleanly at every length`() {
        val bytes = fixture("suspicious")
        for (length in 0 until bytes.size) {
            assertParsesOrRejects(bytes.copyOf(length))
        }
    }

    @Test
    fun `corrupted manifests never fail with anything but ManifestParseException`() {
        val original = fixture("suspicious")
        val random = Random(20261113) // fixed seed: deterministic
        repeat(5_000) {
            val bytes = original.copyOf()
            repeat(1 + random.nextInt(8)) { bytes[random.nextInt(bytes.size)] = random.nextInt(256).toByte() }
            assertParsesOrRejects(bytes)
        }
    }

    private fun assertParsesOrRejects(bytes: ByteArray) {
        try {
            ManifestParser.parse(bytes)
        } catch (expected: ManifestParseException) {
            // A controlled rejection is fine; any other exception type is a parser bug.
        }
    }

    private companion object {
        fun manifest(vararg components: Element) = Element(
            "manifest",
            listOf(Attr("package", Value.Str("com.example.app"), android = false)),
            listOf(Element("application", children = components.toList()))
        )

        fun component(tag: String, name: String, launcher: Boolean = false) = Element(
            tag,
            listOf(Attr("name", Value.Str(name), resourceId = android.R.attr.name)),
            if (launcher) {
                listOf(
                    Element(
                        "intent-filter",
                        children =
                            listOf(
                                Element(
                                    "action",
                                    listOf(
                                        Attr(
                                            "name",
                                            Value.Str("android.intent.action.MAIN"),
                                            resourceId = android.R.attr.name
                                        )
                                    )
                                ),
                                Element(
                                    "category",
                                    listOf(
                                        Attr(
                                            "name",
                                            Value.Str("android.intent.category.LAUNCHER"),
                                            resourceId = android.R.attr.name
                                        )
                                    )
                                )
                            )
                    )
                )
            } else {
                emptyList()
            }
        )
    }
}
