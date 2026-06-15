package com.gotohex.rdp.ui.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import com.gotohex.rdp.R

// ─────────────────────────────────────────────────────────────────────────────
// Fonts (issue #7) — bundled, space/sci-fi-themed external fonts:
//   • Orbitron      — geometric display font for headings (English/Latin)
//   • Rajdhani      — clean technical sans for body text (English/Latin)
//   • Share Tech Mono — console/HUD monospace for labels and readouts
//   • Tajawal       — modern geometric Arabic typeface
//
// Each Latin family lists Tajawal as a fallback so Arabic text typed/rendered
// while a Latin font is active still gets a matching, theme-appropriate face
// instead of silently dropping to the system default. See res/font/*.xml for
// the exact files to download and where to place them.
// ─────────────────────────────────────────────────────────────────────────────

private val DisplayFontFamily = FontFamily(
    Font(R.font.orbitron_medium,   weight = FontWeight.Medium),
    Font(R.font.orbitron_semibold, weight = FontWeight.SemiBold),
    Font(R.font.orbitron_bold,     weight = FontWeight.Bold),
    Font(R.font.tajawal_medium,    weight = FontWeight.Medium),
    Font(R.font.tajawal_bold,      weight = FontWeight.Bold),
)

private val BodyFontFamily = FontFamily(
    Font(R.font.rajdhani_regular,  weight = FontWeight.Normal),
    Font(R.font.rajdhani_medium,   weight = FontWeight.Medium),
    Font(R.font.rajdhani_semibold, weight = FontWeight.SemiBold),
    Font(R.font.tajawal_regular,   weight = FontWeight.Normal),
    Font(R.font.tajawal_medium,    weight = FontWeight.Medium),
)

private val MonoFontFamily = FontFamily(
    Font(R.font.share_tech_mono, weight = FontWeight.Normal),
    Font(R.font.share_tech_mono, weight = FontWeight.Medium),
    Font(R.font.tajawal_regular, weight = FontWeight.Normal),
)

val SpaceTypography = Typography(
    displayLarge = TextStyle(
        fontFamily = DisplayFontFamily,
        fontWeight = FontWeight.Bold,
        fontSize = 57.sp,
        lineHeight = 64.sp,
        letterSpacing = (-0.25).sp
    ),
    displayMedium = TextStyle(
        fontFamily = DisplayFontFamily,
        fontWeight = FontWeight.Bold,
        fontSize = 45.sp,
        lineHeight = 52.sp,
        letterSpacing = 0.sp
    ),
    headlineLarge = TextStyle(
        fontFamily = DisplayFontFamily,
        fontWeight = FontWeight.SemiBold,
        fontSize = 32.sp,
        lineHeight = 40.sp,
        letterSpacing = 0.sp
    ),
    headlineMedium = TextStyle(
        fontFamily = DisplayFontFamily,
        fontWeight = FontWeight.SemiBold,
        fontSize = 28.sp,
        lineHeight = 36.sp,
        letterSpacing = 0.sp
    ),
    headlineSmall = TextStyle(
        fontFamily = DisplayFontFamily,
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
        lineHeight = 32.sp,
        letterSpacing = 0.sp
    ),
    titleLarge = TextStyle(
        fontFamily = DisplayFontFamily,
        fontWeight = FontWeight.SemiBold,
        fontSize = 22.sp,
        lineHeight = 28.sp,
        letterSpacing = 0.15.sp
    ),
    titleMedium = TextStyle(
        fontFamily = BodyFontFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 16.sp,
        lineHeight = 24.sp,
        letterSpacing = 0.15.sp
    ),
    titleSmall = TextStyle(
        fontFamily = BodyFontFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        lineHeight = 20.sp,
        letterSpacing = 0.1.sp
    ),
    bodyLarge = TextStyle(
        fontFamily = BodyFontFamily,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
        letterSpacing = 0.5.sp
    ),
    bodyMedium = TextStyle(
        fontFamily = BodyFontFamily,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
        letterSpacing = 0.25.sp
    ),
    bodySmall = TextStyle(
        fontFamily = BodyFontFamily,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.4.sp
    ),
    labelLarge = TextStyle(
        fontFamily = BodyFontFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        lineHeight = 20.sp,
        letterSpacing = 0.1.sp
    ),
    labelMedium = TextStyle(
        fontFamily = MonoFontFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.5.sp
    ),
    labelSmall = TextStyle(
        fontFamily = MonoFontFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.5.sp
    ),
)

/**
 * Root theme for the app.
 *
 * @param darkTheme whether dark mode is active (already resolved from settings/system)
 * @param themeVariant "space" | "nebula" | "aurora" — controls the accent/background palette.
 *        Fixes issue: changing the theme in Settings previously had no visible effect because
 *        this value was never read; now it drives [LocalSpaceColors] and the Material color scheme.
 */
@Composable
fun HexRDPTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    themeVariant: String = "space",
    content: @Composable () -> Unit
) {
    val spaceColors = spaceColorsFor(themeVariant, darkTheme)
    val colorScheme = materialColorSchemeFor(spaceColors)

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.background.toArgb()
            window.navigationBarColor = colorScheme.background.toArgb()
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !darkTheme
                isAppearanceLightNavigationBars = !darkTheme
            }
        }
    }

    CompositionLocalProvider(LocalSpaceColors provides spaceColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = SpaceTypography,
            content = content
        )
    }
}
