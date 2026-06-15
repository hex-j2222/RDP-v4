package com.gotohex.rdp.util

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import java.io.File
import java.io.FileOutputStream

/**
 * Persists a small thumbnail of the last frame seen during an RDP session,
 * keyed by profile ID, so the profile list (issue #11) can show "what the
 * system looked like last time" as a faint background blended into the
 * connection card.
 *
 * Thumbnails are stored as JPEG in the app's cache directory (safe to be
 * cleared by the OS at any time — purely decorative, never required for
 * correct operation).
 */
object LastFrameStore {

    private const val DIR_NAME = "last_frames"
    private const val MAX_DIMENSION = 480 // thumbnail size is plenty for a blurred/dimmed card background
    private const val JPEG_QUALITY = 70

    private fun dir(context: Context): File =
        File(context.cacheDir, DIR_NAME).apply { if (!exists()) mkdirs() }

    private fun fileFor(context: Context, profileId: String): File =
        File(dir(context), "$profileId.jpg")

    /**
     * Downscales [bitmap] to a small thumbnail and saves it for [profileId].
     * Safe to call from a background thread. Any failure is swallowed —
     * this is a purely cosmetic feature and must never affect the session.
     */
    fun save(context: Context, profileId: String, bitmap: Bitmap) {
        try {
            val scale = MAX_DIMENSION.toFloat() / maxOf(bitmap.width, bitmap.height)
            val thumb = if (scale < 1f) {
                Bitmap.createScaledBitmap(
                    bitmap,
                    (bitmap.width * scale).toInt().coerceAtLeast(1),
                    (bitmap.height * scale).toInt().coerceAtLeast(1),
                    true
                )
            } else {
                bitmap
            }
            FileOutputStream(fileFor(context, profileId)).use { out ->
                thumb.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, out)
            }
            if (thumb !== bitmap) thumb.recycle()
        } catch (_: Exception) {
            // Best-effort only.
        }
    }

    /** Returns the saved thumbnail for [profileId], or null if none exists / failed to load. */
    fun load(context: Context, profileId: String): Bitmap? {
        return try {
            val f = fileFor(context, profileId)
            if (!f.exists()) return null
            BitmapFactory.decodeFile(f.absolutePath)
        } catch (_: Exception) {
            null
        }
    }

    fun exists(context: Context, profileId: String): Boolean =
        fileFor(context, profileId).exists()
}
