package com.gotohex.rdp.ui.theme

import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * Semantic, theme-aware color palette.
 *
 * Every screen in the app reads colors from [LocalSpaceColors] (directly or via the
 * backward-compatible aliases further below). This is what lets:
 *  - Dark mode AND Light mode look correct and comfortable (issue #1)
 *  - Switching the "theme" (Space / Nebula / Aurora) actually change the UI (issue #2)
 */
data class SpaceColors(
    val isDark: Boolean,
    val background: Color,
    val backgroundGradient: List<Color>,
    val surface: Color,
    val surfaceElevated: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val accent: Color,
    val accentSecondary: Color,
    val success: Color,
    val warning: Color,
    val danger: Color,
    val border: Color,
    val cardGradient: List<Color>,
    val cursorColor: Color,
)

// ── Status colors shared across most palettes ────────────────────────────────
private val DarkSuccess = Color(0xFF00FFB3L)
private val DarkWarning = Color(0xFFFFAB00L)
private val DarkDanger  = Color(0xFFFF2D78L)
private val LightSuccess = Color(0xFF1E8E5AL)
private val LightWarning = Color(0xFFB36B00L)
private val LightDanger  = Color(0xFFD6336CL)

// ── Space (default deep-space / cyan) ─────────────────────────────────────────
private val SpaceDark = SpaceColors(
    isDark = true,
    background        = Color(0xFF050A18L),
    backgroundGradient = listOf(Color(0xFF050A18L), Color(0xFF0D1B3EL), Color(0xFF1A0A2EL)),
    surface           = Color(0xFF172038L),
    surfaceElevated   = Color(0xFF0F1729L),
    textPrimary       = Color(0xFFE8EAF6L),
    textSecondary     = Color(0xFF99A2C4L),
    accent            = Color(0xFF00E5FFL),
    accentSecondary   = Color(0xFF2979FFL),
    success           = DarkSuccess,
    warning           = DarkWarning,
    danger            = DarkDanger,
    border            = Color(0xFF273259L),
    cardGradient      = listOf(Color(0xFF172038L), Color(0xFF0F1729L)),
    cursorColor       = Color(0xFF00E5FFL),
)

private val SpaceLight = SpaceColors(
    isDark = false,
    background        = Color(0xFFF3F6FCL),
    backgroundGradient = listOf(Color(0xFFF3F6FCL), Color(0xFFE9EFFCL)),
    surface           = Color(0xFFFFFFFFL),
    surfaceElevated   = Color(0xFFFFFFFFL),
    textPrimary       = Color(0xFF161B2EL),
    textSecondary     = Color(0xFF5C6478L),
    accent            = Color(0xFF0B6FD6L),
    accentSecondary   = Color(0xFF00838FL),
    success           = LightSuccess,
    warning           = LightWarning,
    danger            = LightDanger,
    border            = Color(0xFFDDE3F0L),
    cardGradient      = listOf(Color(0xFFFFFFFFL), Color(0xFFF0F4FCL)),
    cursorColor       = Color(0xFF0B6FD6L),
)

// ── Nebula (violet / magenta) ──────────────────────────────────────────────────
private val NebulaDark = SpaceColors(
    isDark = true,
    background        = Color(0xFF0B0717L),
    backgroundGradient = listOf(Color(0xFF0B0717L), Color(0xFF1B0E33L), Color(0xFF2A0F33L)),
    surface           = Color(0xFF20153DL),
    surfaceElevated   = Color(0xFF160F2BL),
    textPrimary       = Color(0xFFF1E9FFL),
    textSecondary     = Color(0xFFAA9CC8L),
    accent            = Color(0xFFB388FFL),
    accentSecondary   = Color(0xFFFF5FA8L),
    success           = DarkSuccess,
    warning           = DarkWarning,
    danger            = Color(0xFFFF4D6DL),
    border            = Color(0xFF35244FL),
    cardGradient      = listOf(Color(0xFF20153DL), Color(0xFF160F2BL)),
    cursorColor       = Color(0xFFB388FFL),
)

private val NebulaLight = SpaceColors(
    isDark = false,
    background        = Color(0xFFF8F4FFL),
    backgroundGradient = listOf(Color(0xFFF8F4FFL), Color(0xFFF0E6FFL)),
    surface           = Color(0xFFFFFFFFL),
    surfaceElevated   = Color(0xFFFFFFFFL),
    textPrimary       = Color(0xFF2A1B47L),
    textSecondary     = Color(0xFF7A6896L),
    accent            = Color(0xFF7C3AEDL),
    accentSecondary   = Color(0xFFD6336CL),
    success           = LightSuccess,
    warning           = LightWarning,
    danger            = LightDanger,
    border            = Color(0xFFE5D9F7L),
    cardGradient      = listOf(Color(0xFFFFFFFFL), Color(0xFFF5ECFFL)),
    cursorColor       = Color(0xFF7C3AEDL),
)

// ── Aurora (green / teal) ───────────────────────────────────────────────────────
private val AuroraDark = SpaceColors(
    isDark = true,
    background        = Color(0xFF04120FL),
    backgroundGradient = listOf(Color(0xFF04120FL), Color(0xFF0B221CL), Color(0xFF06222EL)),
    surface           = Color(0xFF102C24L),
    surfaceElevated   = Color(0xFF0B221CL),
    textPrimary       = Color(0xFFE3FFF6L),
    textSecondary     = Color(0xFF8FBCAEL),
    accent            = Color(0xFF00F5A0L),
    accentSecondary   = Color(0xFF00B8D9L),
    success           = Color(0xFF00F5A0L),
    warning           = DarkWarning,
    danger            = Color(0xFFFF5C7CL),
    border            = Color(0xFF1F4438L),
    cardGradient      = listOf(Color(0xFF102C24L), Color(0xFF0B221CL)),
    cursorColor       = Color(0xFF00F5A0L),
)

private val AuroraLight = SpaceColors(
    isDark = false,
    background        = Color(0xFFF1FBF6L),
    backgroundGradient = listOf(Color(0xFFF1FBF6L), Color(0xFFE4F7EEL)),
    surface           = Color(0xFFFFFFFFL),
    surfaceElevated   = Color(0xFFFFFFFFL),
    textPrimary       = Color(0xFF0E2A22L),
    textSecondary     = Color(0xFF5D8377L),
    accent            = Color(0xFF00875FL),
    accentSecondary   = Color(0xFF007596L),
    success           = LightSuccess,
    warning           = LightWarning,
    danger            = LightDanger,
    border            = Color(0xFFD6EDE3L),
    cardGradient      = listOf(Color(0xFFFFFFFFL), Color(0xFFEBFBF4L)),
    cursorColor       = Color(0xFF00875FL),
)

/** Resolve the active palette from the user's "theme" + "dark mode" settings. */
fun spaceColorsFor(themeVariant: String, darkTheme: Boolean): SpaceColors {
    return when (themeVariant) {
        "nebula" -> if (darkTheme) NebulaDark else NebulaLight
        "aurora" -> if (darkTheme) AuroraDark else AuroraLight
        else     -> if (darkTheme) SpaceDark else SpaceLight
    }
}

val LocalSpaceColors = staticCompositionLocalOf { SpaceDark }

/** Material3 ColorScheme derived from a [SpaceColors] palette, used for system widgets. */
fun materialColorSchemeFor(colors: SpaceColors) = if (colors.isDark) {
    darkColorScheme(
        primary = colors.accent,
        onPrimary = colors.background,
        primaryContainer = colors.surface,
        onPrimaryContainer = colors.textPrimary,
        secondary = colors.accentSecondary,
        onSecondary = colors.textPrimary,
        background = colors.background,
        onBackground = colors.textPrimary,
        surface = colors.surfaceElevated,
        onSurface = colors.textPrimary,
        surfaceVariant = colors.surface,
        onSurfaceVariant = colors.textSecondary,
        error = colors.danger,
        onError = colors.background,
        outline = colors.border,
        outlineVariant = colors.border,
        scrim = Color(0x99000000L),
    )
} else {
    lightColorScheme(
        primary = colors.accent,
        onPrimary = Color.White,
        primaryContainer = colors.surface,
        onPrimaryContainer = colors.textPrimary,
        secondary = colors.accentSecondary,
        onSecondary = Color.White,
        background = colors.background,
        onBackground = colors.textPrimary,
        surface = colors.surfaceElevated,
        onSurface = colors.textPrimary,
        surfaceVariant = colors.surface,
        onSurfaceVariant = colors.textSecondary,
        error = colors.danger,
        onError = Color.White,
        outline = colors.border,
        outlineVariant = colors.border,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Backward-compatible color aliases.
//
// All existing screens reference these names (StarDust, PulsarCyan, ...).
// By turning them into @Composable property getters backed by LocalSpaceColors,
// every existing usage automatically becomes theme- and variant-aware without
// having to touch every call site.
// ─────────────────────────────────────────────────────────────────────────────

val StarDust: Color          @Composable get() = LocalSpaceColors.current.textPrimary
val CometTail: Color         @Composable get() = LocalSpaceColors.current.textSecondary
val PulsarCyan: Color        @Composable get() = LocalSpaceColors.current.accent
val QuantumBlue: Color       @Composable get() = LocalSpaceColors.current.accentSecondary
val PlasmaGreen: Color       @Composable get() = LocalSpaceColors.current.success
val NovaPink: Color          @Composable get() = LocalSpaceColors.current.danger
val SolarFlare: Color        @Composable get() = LocalSpaceColors.current.warning
val HorizonGray: Color        @Composable get() = LocalSpaceColors.current.border
val DeepSpace: Color          @Composable get() = LocalSpaceColors.current.background
val NebulaSurface: Color      @Composable get() = LocalSpaceColors.current.surface
val StarfieldSurface: Color   @Composable get() = LocalSpaceColors.current.surfaceElevated
val GradientCardStart: Color  @Composable get() = LocalSpaceColors.current.cardGradient[0]
val GradientCardEnd: Color    @Composable get() = LocalSpaceColors.current.cardGradient[1]
val ConnectedGreen: Color     @Composable get() = LocalSpaceColors.current.success
val ConnectingAmber: Color    @Composable get() = LocalSpaceColors.current.warning
val DisconnectedGray: Color   @Composable get() = LocalSpaceColors.current.textSecondary
val ErrorRed: Color           @Composable get() = LocalSpaceColors.current.danger
