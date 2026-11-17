package com.blackshield.app.crash

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CrashReportsTest {
    /** The same shapes the backend accepts (backend/app/api/v1/schemas.py); anything else is rejected there. */
    private val className = Regex("^[A-Za-z_$][A-Za-z0-9_$.]{0,199}$")
    private val frame = Regex("^[A-Za-z0-9_$.<>-]{1,200}\\([A-Za-z0-9_$. -]{0,100}(:\\d{1,7})?\\)$")

    @Test
    fun reportHoldsClassNamesAndFramesButNoMessages() {
        val secret = "/storage/emulated/0/Download/passport-scan.jpg"
        val crash = IllegalStateException("could not open $secret", IOException("denied: $secret"))

        val report = CrashReports.report(crash, at = 0)

        assertEquals(listOf("java.lang.IllegalStateException", "java.io.IOException"), report.exceptions)
        assertTrue(report.frames.isNotEmpty())
        val everything = report.toString()
        assertFalse("messages must never be sent", everything.contains("passport"))
        assertFalse(everything.contains("denied"))
        report.exceptions.forEach { assertTrue(it, className.matches(it)) }
        report.frames.forEach { assertTrue(it, frame.matches(it)) }
    }

    @Test
    fun framesAreSanitizedToTheAcceptedShape() {
        val cases = listOf(
            StackTraceElement("com.example.Foo", "bar", "Foo.kt", 12) to "com.example.Foo.bar(Foo.kt:12)",
            StackTraceElement("a.b", "c", null, -1) to "a.b.c(Unknown Source)",
            StackTraceElement("java.lang.Thread", "run", "Thread.java", -2) to "java.lang.Thread.run(Native Method)",
            StackTraceElement("com.example.Weird Name", "do it!", "My File(1).kt", 3) to
                "com.example.WeirdName.doit(My File1.kt:3)"
        )
        for ((element, expected) in cases) {
            val actual = CrashReports.frame(element)
            assertEquals(expected, actual)
            assertTrue(actual, frame.matches(actual))
        }
    }

    @Test
    fun deepCauseChainsAreCapped() {
        var crash: Throwable = RuntimeException("root")
        repeat(20) { crash = RuntimeException("wrap $it", crash) }

        assertEquals(8, CrashReports.report(crash, at = 0).exceptions.size)
    }
}
