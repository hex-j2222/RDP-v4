package com.gotohex.rdp.data.repository

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.*
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "hex_rdp_settings")

data class AppSettings(
    val isDarkMode: Boolean = true,
    val language: String = "system", // "en", "ar", "system"
    val themeVariant: String = "space", // "space", "nebula", "aurora"
    val cursorStyle: String = "default", // "default", "crosshair", "dot", "arrow"
    val cursorSize: Int = 24,
    val showCursorOnTouch: Boolean = true,
    val touchpadSensitivity: Float = 1.0f,
    val scrollSensitivity: Float = 1.0f,
    val showSubscribePopup: Boolean = true,
    val lastSubscribePromptTime: Long = 0L,
    val subscribePromptIntervalDays: Int = 3,
    val hasShownFirstLaunch: Boolean = false,
    val hapticFeedback: Boolean = true,
    val keepScreenOn: Boolean = true,
    val autoReconnect: Boolean = true,
    val autoReconnectAttempts: Int = 3,
    val compressionQuality: Int = 75, // 0-100 for JPEG
    val showFpsCounter: Boolean = false,
    // "auto" = match device screen, otherwise "WxH" e.g. "1280x720"
    val defaultResolution: String = "auto",
    val sessionToolbarVisible: Boolean = true,
    val sessionExtraKeysVisible: Boolean = true,
    val runInBackground: Boolean = true,
    val soundEnabled: Boolean = true,
)

@Singleton
class AppSettingsRepository @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private object Keys {
        val IS_DARK_MODE = booleanPreferencesKey("is_dark_mode")
        val LANGUAGE = stringPreferencesKey("language")
        val THEME_VARIANT = stringPreferencesKey("theme_variant")
        val CURSOR_STYLE = stringPreferencesKey("cursor_style")
        val CURSOR_SIZE = intPreferencesKey("cursor_size")
        val SHOW_CURSOR_ON_TOUCH = booleanPreferencesKey("show_cursor_on_touch")
        val TOUCHPAD_SENSITIVITY = floatPreferencesKey("touchpad_sensitivity")
        val SCROLL_SENSITIVITY = floatPreferencesKey("scroll_sensitivity")
        val SHOW_SUBSCRIBE_POPUP = booleanPreferencesKey("show_subscribe_popup")
        val LAST_SUBSCRIBE_PROMPT = longPreferencesKey("last_subscribe_prompt")
        val SUBSCRIBE_INTERVAL_DAYS = intPreferencesKey("subscribe_interval_days")
        val HAS_SHOWN_FIRST_LAUNCH = booleanPreferencesKey("has_shown_first_launch")
        val HAPTIC_FEEDBACK = booleanPreferencesKey("haptic_feedback")
        val KEEP_SCREEN_ON = booleanPreferencesKey("keep_screen_on")
        val AUTO_RECONNECT = booleanPreferencesKey("auto_reconnect")
        val AUTO_RECONNECT_ATTEMPTS = intPreferencesKey("auto_reconnect_attempts")
        val COMPRESSION_QUALITY = intPreferencesKey("compression_quality")
        val SHOW_FPS_COUNTER = booleanPreferencesKey("show_fps_counter")
        val DEFAULT_RESOLUTION = stringPreferencesKey("default_resolution")
        val SESSION_TOOLBAR_VISIBLE = booleanPreferencesKey("session_toolbar_visible")
        val SESSION_EXTRA_KEYS_VISIBLE = booleanPreferencesKey("session_extra_keys_visible")
        val RUN_IN_BACKGROUND = booleanPreferencesKey("run_in_background")
        val SOUND_ENABLED = booleanPreferencesKey("sound_enabled")
    }

    val settingsFlow: Flow<AppSettings> = context.dataStore.data
        .catch { exception ->
            if (exception is IOException) emit(emptyPreferences())
            else throw exception
        }
        .map { prefs ->
            AppSettings(
                isDarkMode = prefs[Keys.IS_DARK_MODE] ?: true,
                language = prefs[Keys.LANGUAGE] ?: "system",
                themeVariant = prefs[Keys.THEME_VARIANT] ?: "space",
                cursorStyle = prefs[Keys.CURSOR_STYLE] ?: "default",
                cursorSize = prefs[Keys.CURSOR_SIZE] ?: 24,
                showCursorOnTouch = prefs[Keys.SHOW_CURSOR_ON_TOUCH] ?: true,
                touchpadSensitivity = prefs[Keys.TOUCHPAD_SENSITIVITY] ?: 1.0f,
                scrollSensitivity = prefs[Keys.SCROLL_SENSITIVITY] ?: 1.0f,
                showSubscribePopup = prefs[Keys.SHOW_SUBSCRIBE_POPUP] ?: true,
                lastSubscribePromptTime = prefs[Keys.LAST_SUBSCRIBE_PROMPT] ?: 0L,
                subscribePromptIntervalDays = prefs[Keys.SUBSCRIBE_INTERVAL_DAYS] ?: 3,
                hasShownFirstLaunch = prefs[Keys.HAS_SHOWN_FIRST_LAUNCH] ?: false,
                hapticFeedback = prefs[Keys.HAPTIC_FEEDBACK] ?: true,
                keepScreenOn = prefs[Keys.KEEP_SCREEN_ON] ?: true,
                autoReconnect = prefs[Keys.AUTO_RECONNECT] ?: true,
                autoReconnectAttempts = prefs[Keys.AUTO_RECONNECT_ATTEMPTS] ?: 3,
                compressionQuality = prefs[Keys.COMPRESSION_QUALITY] ?: 75,
                showFpsCounter = prefs[Keys.SHOW_FPS_COUNTER] ?: false,
                defaultResolution = prefs[Keys.DEFAULT_RESOLUTION] ?: "auto",
                sessionToolbarVisible = prefs[Keys.SESSION_TOOLBAR_VISIBLE] ?: true,
                sessionExtraKeysVisible = prefs[Keys.SESSION_EXTRA_KEYS_VISIBLE] ?: true,
                runInBackground = prefs[Keys.RUN_IN_BACKGROUND] ?: true,
                soundEnabled = prefs[Keys.SOUND_ENABLED] ?: true,
            )
        }

    suspend fun updateDarkMode(enabled: Boolean) = update { it[Keys.IS_DARK_MODE] = enabled }
    suspend fun updateLanguage(lang: String) = update { it[Keys.LANGUAGE] = lang }
    suspend fun updateThemeVariant(theme: String) = update { it[Keys.THEME_VARIANT] = theme }
    suspend fun updateCursorStyle(style: String) = update { it[Keys.CURSOR_STYLE] = style }
    suspend fun updateCursorSize(size: Int) = update { it[Keys.CURSOR_SIZE] = size }
    suspend fun updateTouchpadSensitivity(v: Float) = update { it[Keys.TOUCHPAD_SENSITIVITY] = v }
    suspend fun updateScrollSensitivity(v: Float) = update { it[Keys.SCROLL_SENSITIVITY] = v }
    suspend fun markSubscribePromptShown() = update {
        it[Keys.LAST_SUBSCRIBE_PROMPT] = System.currentTimeMillis()
    }
    suspend fun markFirstLaunchShown() = update { it[Keys.HAS_SHOWN_FIRST_LAUNCH] = true }
    suspend fun updateHapticFeedback(v: Boolean) = update { it[Keys.HAPTIC_FEEDBACK] = v }
    suspend fun updateKeepScreenOn(v: Boolean) = update { it[Keys.KEEP_SCREEN_ON] = v }
    suspend fun updateAutoReconnect(v: Boolean) = update { it[Keys.AUTO_RECONNECT] = v }
    suspend fun updateCompressionQuality(v: Int) = update { it[Keys.COMPRESSION_QUALITY] = v }
    suspend fun updateShowFps(v: Boolean) = update { it[Keys.SHOW_FPS_COUNTER] = v }
    suspend fun updateDefaultResolution(v: String) = update { it[Keys.DEFAULT_RESOLUTION] = v }
    suspend fun updateSessionToolbarVisible(v: Boolean) = update { it[Keys.SESSION_TOOLBAR_VISIBLE] = v }
    suspend fun updateSessionExtraKeysVisible(v: Boolean) = update { it[Keys.SESSION_EXTRA_KEYS_VISIBLE] = v }
    suspend fun updateRunInBackground(v: Boolean) = update { it[Keys.RUN_IN_BACKGROUND] = v }
    suspend fun updateSoundEnabled(v: Boolean) = update { it[Keys.SOUND_ENABLED] = v }

    private suspend fun update(block: (MutablePreferences) -> Unit) {
        context.dataStore.edit(block)
    }
}
