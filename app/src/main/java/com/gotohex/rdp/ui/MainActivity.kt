package com.gotohex.rdp.ui

import android.content.res.Configuration
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.animation.*
import androidx.compose.animation.core.tween
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.gotohex.rdp.ui.components.LocalSoundManager
import com.gotohex.rdp.ui.screens.HomeScreen
import com.gotohex.rdp.ui.screens.SettingsScreen
import com.gotohex.rdp.ui.theme.HexRDPTheme
import dagger.hilt.android.AndroidEntryPoint
import java.util.Locale

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        // ── Fix theme/language flash on restart (issue #5) ────────────────
        // AppSettings (dark mode, theme variant, language...) are loaded
        // asynchronously from DataStore. Previously the very first Compose
        // frame rendered with AppSettings() defaults (dark mode + "space"
        // theme) before the real saved settings arrived a moment later,
        // producing a visible flash to the wrong theme on every cold start.
        //
        // installSplashScreen() keeps the native splash (which already uses
        // the app's dark background, see themes.xml) on screen until
        // `settingsLoaded` becomes true — i.e. until the first real value has
        // been read from DataStore — so Compose only ever renders with the
        // user's actual saved theme/language. No flash, regardless of how
        // long DataStore takes.
        val splashScreen = installSplashScreen()
        var settingsLoaded = false
        splashScreen.setKeepOnScreenCondition { !settingsLoaded }

        super.onCreate(savedInstanceState)

        setContent {
            val uiState by viewModel.uiState.collectAsState()
            val settings = uiState.settings

            LaunchedEffect(uiState.isLoading) {
                if (!uiState.isLoading) settingsLoaded = true
            }

            // While the real settings are still loading, don't render anything —
            // the native splash screen (kept on-screen above) covers this gap.
            if (uiState.isLoading) return@setContent

            // ── Dark mode (issue #2 fix) ──────────────────────────────────────
            // Previously this checked `settings.language` instead of the actual
            // dark-mode setting, so toggling the switch in Settings never had any
            // effect. The dark-mode toggle is a direct on/off, so just use it.
            val isDark = settings.isDarkMode

            // ── Language (issues #3 and #9 fix) ───────────────────────────────
            // Wrap the content in a Context whose Configuration locale matches the
            // user's chosen language, and provide the matching layout direction.
            // This makes string resources (stringResource) and RTL/LTR layout
            // update immediately when the language is changed, and — because the
            // language choice is persisted in DataStore via AppSettingsRepository —
            // it is restored automatically the next time the app is launched.
            val baseContext = LocalContext.current
            val targetLocale = when (settings.language) {
                "ar" -> Locale("ar")
                "en" -> Locale("en")
                else -> null // "system" -> keep device locale, no override
            }

            val localizedContext = remember(targetLocale) {
                if (targetLocale == null) {
                    baseContext
                } else {
                    val config = Configuration(baseContext.resources.configuration)
                    config.setLocale(targetLocale)
                    baseContext.createConfigurationContext(config)
                }
            }

            val layoutDirection = when {
                targetLocale != null -> if (targetLocale.language == "ar") LayoutDirection.Rtl else LayoutDirection.Ltr
                else -> LocalLayoutDirection.current
            }

            CompositionLocalProvider(
                LocalContext provides localizedContext,
                LocalConfiguration provides localizedContext.resources.configuration,
                LocalLayoutDirection provides layoutDirection,
                LocalSoundManager provides viewModel.soundManager,
            ) {
                HexRDPTheme(darkTheme = isDark, themeVariant = settings.themeVariant) {
                    val navController = rememberNavController()
                    // "Forward" (Home -> Settings) always slides in from the
                    // trailing edge and "back" from the leading edge, which
                    // Compose's slideInHorizontally/slideOutHorizontally with a
                    // fixed pixel direction does NOT do automatically — under
                    // LayoutDirection.Rtl the same fraction needs to be negated
                    // so the motion matches the swipe-to-open gesture direction
                    // added on HomeScreen (issue #10).
                    val rtl = layoutDirection == LayoutDirection.Rtl
                    val dir = if (rtl) -1 else 1
                    NavHost(
                        navController = navController,
                        startDestination = "home",
                        enterTransition = {
                            slideInHorizontally(animationSpec = tween(320)) { dir * it / 4 } + fadeIn(tween(320))
                        },
                        exitTransition = {
                            slideOutHorizontally(animationSpec = tween(320)) { -dir * it / 4 } + fadeOut(tween(320))
                        },
                        popEnterTransition = {
                            slideInHorizontally(animationSpec = tween(320)) { -dir * it / 4 } + fadeIn(tween(320))
                        },
                        popExitTransition = {
                            slideOutHorizontally(animationSpec = tween(320)) { dir * it / 4 } + fadeOut(tween(320))
                        }
                    ) {
                        composable("home") {
                            HomeScreen(navController = navController, viewModel = viewModel)
                        }
                        composable("settings") {
                            SettingsScreen(navController = navController, viewModel = viewModel)
                        }
                    }
                }
            }
        }
    }
}
