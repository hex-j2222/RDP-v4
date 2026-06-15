package com.gotohex.rdp.audio

import android.content.Context
import android.media.AudioAttributes
import android.media.SoundPool
import com.gotohex.rdp.R
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Lightweight UI sound-effect player (issue #9).
 *
 * All sounds are short, synthetic tones bundled in res/raw/ — no external
 * assets, no licensing concerns, near-zero memory footprint (loaded once via
 * SoundPool and reused for the app's lifetime).
 *
 * Respects the user's "Sound Effects" toggle in Settings — when disabled,
 * [play] becomes a no-op so callers don't need to check the setting
 * themselves every time.
 */
@Singleton
class SoundManager @Inject constructor(
    @ApplicationContext private val context: Context
) {
    enum class Sound { TAP, TOGGLE, SUCCESS, ERROR, SWIPE, CONNECT }

    /** Updated by the Settings screen via [setEnabled]. Defaults to enabled. */
    @Volatile
    var enabled: Boolean = true

    private val soundPool: SoundPool = SoundPool.Builder()
        .setMaxStreams(4)
        .setAudioAttributes(
            AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_ASSISTANCE_SONIFICATION)
                .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                .build()
        )
        .build()

    private val soundIds: Map<Sound, Int> = mapOf(
        Sound.TAP     to soundPool.load(context, R.raw.sfx_tap, 1),
        Sound.TOGGLE  to soundPool.load(context, R.raw.sfx_toggle, 1),
        Sound.SUCCESS to soundPool.load(context, R.raw.sfx_success, 1),
        Sound.ERROR   to soundPool.load(context, R.raw.sfx_error, 1),
        Sound.SWIPE   to soundPool.load(context, R.raw.sfx_swipe, 1),
        Sound.CONNECT to soundPool.load(context, R.raw.sfx_connect, 1),
    )

    fun setEnabled(value: Boolean) {
        enabled = value
    }

    /** Plays [sound] at [volume] (0f..1f) if sound effects are enabled. */
    fun play(sound: Sound, volume: Float = 0.5f) {
        if (!enabled) return
        val id = soundIds[sound] ?: return
        soundPool.play(id, volume, volume, 0, 0, 1f)
    }

    fun release() {
        soundPool.release()
    }
}
