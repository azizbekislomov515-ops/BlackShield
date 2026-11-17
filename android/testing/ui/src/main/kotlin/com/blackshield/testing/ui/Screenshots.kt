package com.blackshield.testing.ui

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.util.Log
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.captureToImage
import androidx.test.core.graphics.writeToTestStorage
import androidx.test.platform.app.InstrumentationRegistry
import kotlin.math.abs
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue

/**
 * Screenshot tests against goldens in the module's `src/androidTest/assets/screenshots/`.
 *
 * Goldens are recorded on the reference emulator (docs/testing.md). On a device whose screen gives a different image
 * size the comparison is skipped, not failed. Record or refresh them with the instrumentation argument
 * `recordScreenshots=true`; the captures land in `build/outputs/connected_android_test_additional_output`.
 */
object Screenshots {
    private const val TAG = "Screenshots"
    private const val ASSET_DIR = "screenshots"
    private const val RECORD_ARGUMENT = "recordScreenshots"

    /** A pixel counts as changed when a channel moves by more than this (anti-aliasing noise stays below). */
    private const val CHANNEL_TOLERANCE = 24

    /** Share of changed pixels a match may have (text rendering differs a little between runs). */
    private const val MAX_CHANGED_RATIO = 0.004
    private const val PERCENT = 100

    fun assertMatchesGolden(node: SemanticsNodeInteraction, name: String) {
        val actual = node.captureToImage().asAndroidBitmap()
        val recording = InstrumentationRegistry.getArguments().getString(RECORD_ARGUMENT) == "true"
        val golden = golden(name)
        if (recording || golden == null) {
            save(actual, name)
            if (golden == null && !recording) {
                fail(
                    "No golden for '$name'. The capture was saved as $name.png; " +
                        "copy it to src/androidTest/assets/$ASSET_DIR/"
                )
            }
            return
        }
        assumeTrue(
            "golden '$name' is ${golden.width}x${golden.height}, " +
                "this device renders ${actual.width}x${actual.height}",
            golden.width == actual.width && golden.height == actual.height
        )
        val changed = changedRatio(golden, actual)
        if (changed > MAX_CHANGED_RATIO) {
            save(actual, "$name.actual")
            fail(
                "'$name' differs from its golden in ${"%.2f".format(
                    changed * PERCENT
                )}% of pixels (saved $name.actual.png)"
            )
        }
    }

    private fun golden(name: String): Bitmap? = runCatching {
        InstrumentationRegistry.getInstrumentation().context.assets.open(
            "$ASSET_DIR/$name.png"
        ).use(BitmapFactory::decodeStream)
    }.getOrNull()

    /** Saved through the test storage service as `<name>.png`. */
    private fun save(bitmap: Bitmap, name: String) {
        bitmap.writeToTestStorage(name)
        Log.i(TAG, "saved $name.png")
    }

    private fun changedRatio(expected: Bitmap, actual: Bitmap): Double {
        val size = expected.width * expected.height
        val a = IntArray(size).also { expected.getPixels(it, 0, expected.width, 0, 0, expected.width, expected.height) }
        val b = IntArray(size).also { actual.getPixels(it, 0, actual.width, 0, 0, actual.width, actual.height) }
        val changed = a.indices.count { i -> differs(a[i], b[i]) }
        return changed.toDouble() / size
    }

    private fun differs(x: Int, y: Int): Boolean = abs(Color.red(x) - Color.red(y)) > CHANNEL_TOLERANCE ||
        abs(Color.green(x) - Color.green(y)) > CHANNEL_TOLERANCE ||
        abs(Color.blue(x) - Color.blue(y)) > CHANNEL_TOLERANCE
}
