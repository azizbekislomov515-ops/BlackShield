package com.blackshield.core.designsystem.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// "Obsidian Aegis": near-black surfaces, one neon-green accent, cyan for information, red for danger.
private val DarkColors =
    darkColorScheme(
        primary = Color(0xFF00E29E),
        onPrimary = Color(0xFF00382A),
        primaryContainer = Color(0xFF00F2AA),
        onPrimaryContainer = Color(0xFF002114),
        secondary = Color(0xFF9AECFF),
        onSecondary = Color(0xFF00363F),
        secondaryContainer = Color(0xFF004E5A),
        onSecondaryContainer = Color(0xFFA5EEFF),
        tertiary = Color(0xFFFFB3AD),
        onTertiary = Color(0xFF68000A),
        tertiaryContainer = Color(0xFF93000A),
        onTertiaryContainer = Color(0xFFFFDAD6),
        error = Color(0xFFFFB4AB),
        onError = Color(0xFF690005),
        errorContainer = Color(0xFF93000A),
        onErrorContainer = Color(0xFFFFDAD6),
        background = Color(0xFF0F131C),
        onBackground = Color(0xFFDFE2EF),
        surface = Color(0xFF0F131C),
        onSurface = Color(0xFFDFE2EF),
        surfaceVariant = Color(0xFF31353F),
        onSurfaceVariant = Color(0xFFB9C6BF),
        surfaceContainerLowest = Color(0xFF0A0E17),
        surfaceContainerLow = Color(0xFF181B25),
        surfaceContainer = Color(0xFF1C1F29),
        surfaceContainerHigh = Color(0xFF262A34),
        surfaceContainerHighest = Color(0xFF31353F),
        outline = Color(0xFF84958A),
        outlineVariant = Color(0xFF3B4A41),
        inverseSurface = Color(0xFFDFE2EF),
        inverseOnSurface = Color(0xFF2C303A),
        inversePrimary = Color(0xFF006C4A)
    )

// The same identity for daylight: the accent darkens so text on white keeps a 4.5:1 contrast.
private val LightColors =
    lightColorScheme(
        primary = Color(0xFF006C4A),
        onPrimary = Color(0xFFFFFFFF),
        primaryContainer = Color(0xFF6FFBC4),
        onPrimaryContainer = Color(0xFF002114),
        secondary = Color(0xFF00677A),
        onSecondary = Color(0xFFFFFFFF),
        secondaryContainer = Color(0xFFB2EBFF),
        onSecondaryContainer = Color(0xFF001F26),
        tertiary = Color(0xFFB3261E),
        onTertiary = Color(0xFFFFFFFF),
        tertiaryContainer = Color(0xFFFFDAD6),
        onTertiaryContainer = Color(0xFF410004),
        error = Color(0xFFBA1A1A),
        onError = Color(0xFFFFFFFF),
        errorContainer = Color(0xFFFFDAD6),
        onErrorContainer = Color(0xFF410002),
        background = Color(0xFFF6F8FC),
        onBackground = Color(0xFF171C22),
        surface = Color(0xFFF6F8FC),
        onSurface = Color(0xFF171C22),
        surfaceVariant = Color(0xFFDDE4E1),
        onSurfaceVariant = Color(0xFF404944),
        surfaceContainerLowest = Color(0xFFFFFFFF),
        surfaceContainerLow = Color(0xFFF0F3F7),
        surfaceContainer = Color(0xFFEAEEF2),
        surfaceContainerHigh = Color(0xFFE4E8EC),
        surfaceContainerHighest = Color(0xFFDEE3E7),
        outline = Color(0xFF707973),
        outlineVariant = Color(0xFFBFC9C3),
        inverseSurface = Color(0xFF2C3137),
        inverseOnSurface = Color(0xFFEDF1F5),
        inversePrimary = Color(0xFF00E29E)
    )

/** Status colors that Material's scheme has no slot for. */
@Immutable
data class StatusColors(val safe: Color, val onSafe: Color, val caution: Color, val danger: Color, val info: Color)

private val DarkStatus =
    StatusColors(
        safe = Color(0xFF00E29E),
        onSafe = Color(0xFF00382A),
        caution = Color(0xFFFFC857),
        danger = Color(0xFFFF8A80),
        info = Color(0xFF5BE3FF)
    )

private val LightStatus =
    StatusColors(
        safe = Color(0xFF006C4A),
        onSafe = Color(0xFFFFFFFF),
        caution = Color(0xFF8A5A00),
        danger = Color(0xFFB3261E),
        info = Color(0xFF00677A)
    )

val LocalStatusColors = staticCompositionLocalOf { DarkStatus }

/** Labels in the "telemetry" style of the design: small, spaced, monospaced capitals. */
val LabelMono =
    TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        letterSpacing = 0.6.sp
    )

/** Large figures (counts, versions). */
val MetricMono = TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, fontSize = 18.sp)

private val Base = Typography()

private val AppTypography =
    Typography(
        headlineLarge = Base.headlineLarge.copy(fontWeight = FontWeight.Bold, letterSpacing = (-0.5).sp),
        headlineMedium = Base.headlineMedium.copy(fontWeight = FontWeight.Bold, letterSpacing = (-0.4).sp),
        headlineSmall = Base.headlineSmall.copy(fontWeight = FontWeight.SemiBold, letterSpacing = (-0.3).sp),
        titleLarge = Base.titleLarge.copy(fontWeight = FontWeight.SemiBold, letterSpacing = (-0.2).sp),
        titleMedium = Base.titleMedium.copy(fontWeight = FontWeight.SemiBold),
        labelSmall = LabelMono
    )

private val AppShapes =
    Shapes(
        extraSmall = androidx.compose.foundation.shape.RoundedCornerShape(4.dp),
        small = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
        medium = androidx.compose.foundation.shape.RoundedCornerShape(12.dp),
        large = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
        extraLarge = androidx.compose.foundation.shape.RoundedCornerShape(24.dp)
    )

@Composable
fun BlackShieldTheme(darkTheme: Boolean, content: @Composable () -> Unit) {
    val colors: ColorScheme = if (darkTheme) DarkColors else LightColors
    CompositionLocalProvider(LocalStatusColors provides if (darkTheme) DarkStatus else LightStatus) {
        MaterialTheme(colorScheme = colors, typography = AppTypography, shapes = AppShapes, content = content)
    }
}

/** Shortcut for [LocalStatusColors]. */
object BsTheme {
    val status: StatusColors
        @Composable get() = LocalStatusColors.current
}
