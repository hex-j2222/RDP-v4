package com.gotohex.rdp.rdp.codec

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Log
import com.gotohex.rdp.data.model.RdpPerformance
import com.gotohex.rdp.rdp.protocol.RdpFrameUpdate
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Adaptive RDP Bitmap Decoder
 * Handles multiple compression formats based on network quality:
 * - Raw bitmap (no compression) - for LAN
 * - RLE compressed bitmap - for WiFi
 * - JPEG bitmap - for slow connections
 * - RemoteFX (simplified) - for modern servers
 *
 * FIXES APPLIED (v4.2):
 * FIX-G  decodeRleBitmap(): The previous implementation had three bugs
 *         that made it produce a blank (all-zero) pixel array:
 *         (a) Regular run (0x00): column index was computed as `i % width`
 *             but `i` was the run-index, not the absolute pixel column, so
 *             consecutive runs never advanced past column 0. Now uses a
 *             flat pixel-index cursor that advances correctly across rows.
 *         (b) Literal run (0x40): bytes were read from the stream but pixels
 *             were never written to the output array. Now converts each read
 *             literal pixel with pixelToArgb() and stores it.
 *         (c) End-of-scanline (0xF0): row counter decremented even when the
 *             cursor had not reached the end of the row, leaving partial rows.
 *             Now the cursor is snapped to the row boundary on EOL.
 *
 * FIX-H  decodeRawBitmap(): 8 bpp (256-colour palette) mode was
 *         unhandled and fell through to `return null`. Servers that
 *         negotiate LOW_BANDWIDTH or older XP/2003 targets can send 8 bpp
 *         frames. Added a greyscale fallback so the frame is at least
 *         displayed; a proper palette would need the Palette Update PDU.
 */
class RdpBitmapDecoder {

    companion object {
        private const val TAG = "BitmapDecoder"

        // Bitmap compression types
        const val BITMAP_COMPRESSION_NONE    = 0x00
        const val BITMAP_COMPRESSION_RLE     = 0x01
        const val BITMAP_COMPRESSION_JPEG    = 0x04
        const val BITMAP_COMPRESSION_REMOTEFX = 0x08

        // Update types
        const val UPDATE_TYPE_ORDERS       = 0x0000
        const val UPDATE_TYPE_BITMAP       = 0x0001
        const val UPDATE_TYPE_PALETTE      = 0x0002
        const val UPDATE_TYPE_SYNCHRONIZE  = 0x0003
    }

    /**
     * Decode incoming RDP data PDU into frame updates
     */
    fun decode(data: ByteArray, screenWidth: Int, screenHeight: Int, performance: Int): List<RdpFrameUpdate> {
        if (data.size < 4) return emptyList()
        val frames = mutableListOf<RdpFrameUpdate>()

        try {
            val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
            val updateType = buf.short.toInt() and 0xFFFF

            when (updateType) {
                UPDATE_TYPE_BITMAP    -> decodeBitmapUpdate(buf, frames, performance)
                UPDATE_TYPE_ORDERS    -> decodeOrdersUpdate(buf, frames, screenWidth, screenHeight)
                UPDATE_TYPE_SYNCHRONIZE -> { /* no-op */ }
                else -> Log.v(TAG, "Unknown update type: 0x${updateType.toString(16)}")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Decode error: ${e.message}")
        }

        return frames
    }

    private fun decodeBitmapUpdate(buf: ByteBuffer, frames: MutableList<RdpFrameUpdate>, performance: Int) {
        if (buf.remaining() < 2) return
        val numRectangles = buf.short.toInt() and 0xFFFF

        repeat(numRectangles) {
            if (buf.remaining() < 18) return@repeat
            try {
                val destLeft   = buf.short.toInt() and 0xFFFF
                val destTop    = buf.short.toInt() and 0xFFFF
                val destRight  = buf.short.toInt() and 0xFFFF
                val destBottom = buf.short.toInt() and 0xFFFF
                val width         = buf.short.toInt() and 0xFFFF
                val height        = buf.short.toInt() and 0xFFFF
                val bitsPerPixel  = buf.short.toInt() and 0xFFFF
                val flags         = buf.short.toInt() and 0xFFFF
                val bitmapLength  = buf.short.toInt() and 0xFFFF

                if (bitmapLength <= 0 || buf.remaining() < bitmapLength) return@repeat
                val bitmapData = ByteArray(bitmapLength)
                buf.get(bitmapData)

                val isCompressed = (flags and 0x0001) != 0
                val isJpeg       = (flags and 0x0008) != 0

                val pixels = when {
                    isJpeg       -> decodeJpegBitmap(bitmapData, width, height)
                    isCompressed -> decodeRleBitmap(bitmapData, width, height, bitsPerPixel)
                    else         -> decodeRawBitmap(bitmapData, width, height, bitsPerPixel)
                }

                if (pixels != null) {
                    // Always report the *actual* decoded bitmap dimensions, not the
                    // destination rectangle, to avoid ArrayIndexOutOfBoundsException
                    // in Bitmap.setPixels() when dest and bitmap sizes differ.
                    frames.add(
                        RdpFrameUpdate(
                            x = destLeft,
                            y = destTop,
                            width = width,
                            height = height,
                            pixels = pixels
                        )
                    )
                }
            } catch (e: Exception) {
                Log.w(TAG, "Rectangle decode error: ${e.message}")
            }
        }
    }

    private fun decodeOrdersUpdate(
        buf: ByteBuffer,
        frames: MutableList<RdpFrameUpdate>,
        screenWidth: Int,
        screenHeight: Int
    ) {
        if (buf.remaining() < 4) return
        buf.short // pad2octets
        buf.short // numberOrders — we do not process drawing orders yet
        // A refresh rect / suppress output PDU would be sent from the session
        // activity to request a full-screen repaint when orders are unsupported.
    }

    /**
     * Decode raw (uncompressed) bitmap.
     * FIX-H: Added 8 bpp greyscale fallback (was returning null, causing blank frames
     * on XP/2003 targets and LOW_BANDWIDTH mode).
     */
    private fun decodeRawBitmap(data: ByteArray, width: Int, height: Int, bpp: Int): IntArray? {
        if (width <= 0 || height <= 0) return null
        val pixels = IntArray(width * height)

        when (bpp) {
            32 -> {
                val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
                for (row in height - 1 downTo 0) {
                    for (col in 0 until width) {
                        if (buf.remaining() < 4) break
                        val b = buf.get().toInt() and 0xFF
                        val g = buf.get().toInt() and 0xFF
                        val r = buf.get().toInt() and 0xFF
                        buf.get() // alpha/padding
                        pixels[row * width + col] = 0xFF000000.toInt() or (r shl 16) or (g shl 8) or b
                    }
                }
            }
            24 -> {
                val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
                for (row in height - 1 downTo 0) {
                    for (col in 0 until width) {
                        if (buf.remaining() < 3) break
                        val b = buf.get().toInt() and 0xFF
                        val g = buf.get().toInt() and 0xFF
                        val r = buf.get().toInt() and 0xFF
                        pixels[row * width + col] = 0xFF000000.toInt() or (r shl 16) or (g shl 8) or b
                    }
                    val rowBytes = 3 * width
                    val padding = if (rowBytes % 4 == 0) 0 else 4 - (rowBytes % 4)
                    repeat(padding) { if (buf.remaining() > 0) buf.get() }
                }
            }
            16 -> {
                val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
                for (row in height - 1 downTo 0) {
                    for (col in 0 until width) {
                        if (buf.remaining() < 2) break
                        val pixel16 = buf.short.toInt() and 0xFFFF
                        val r = ((pixel16 shr 11) and 0x1F) * 255 / 31
                        val g = ((pixel16 shr 5)  and 0x3F) * 255 / 63
                        val b = ( pixel16          and 0x1F) * 255 / 31
                        pixels[row * width + col] = 0xFF000000.toInt() or (r shl 16) or (g shl 8) or b
                    }
                }
            }
            8 -> {
                // FIX-H: 8 bpp palette mode — palette is carried in a separate
                // Palette Update PDU which we don't yet track; render as greyscale
                // so the frame is visible rather than discarded.
                val buf = ByteBuffer.wrap(data)
                for (row in height - 1 downTo 0) {
                    for (col in 0 until width) {
                        if (!buf.hasRemaining()) break
                        val v = buf.get().toInt() and 0xFF
                        pixels[row * width + col] = 0xFF000000.toInt() or (v shl 16) or (v shl 8) or v
                    }
                }
            }
            else -> return null
        }

        return pixels
    }

    /**
     * Decode RLE compressed bitmap (MS-RDPBCGR Interleaved RLE).
     *
     * FIX-G: Rewrote cursor management. Previous bugs:
     * (a) Regular run: col = i % width — wrong; must be absolute pixel position.
     * (b) Literal run: bytes read but pixels never stored.
     * (c) EOL (0xF0): row decremented without flushing partial row cursor.
     */
    private fun decodeRleBitmap(data: ByteArray, width: Int, height: Int, bpp: Int): IntArray? {
        if (width <= 0 || height <= 0) return null
        val pixels = IntArray(width * height)
        val bytesPerPixel = maxOf(bpp / 8, 1)

        try {
            val src = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
            // RDP bitmaps are bottom-up: start writing from the last row.
            var row = height - 1
            var col = 0

            fun writePixel(pixelBytes: ByteArray) {
                if (row < 0) return
                pixels[row * width + col] = pixelToArgb(pixelBytes, bpp)
                col++
                if (col >= width) { col = 0; row-- }
            }

            while (src.hasRemaining() && row >= 0) {
                val code = src.get().toInt() and 0xFF
                val orderType = code and 0xF0
                val nibble    = code and 0x0F

                // Run length: if low nibble is non-zero → length = nibble
                // else next byte gives (length - 16) → length = nextByte + 16
                val runLength: Int = when {
                    nibble != 0       -> nibble
                    src.hasRemaining() -> (src.get().toInt() and 0xFF) + 16
                    else               -> break
                }

                when (orderType) {
                    0x00 -> {
                        // Regular run: one pixel value repeated runLength times
                        if (src.remaining() < bytesPerPixel) break
                        val pixelBytes = ByteArray(bytesPerPixel)
                        src.get(pixelBytes)
                        repeat(runLength) { writePixel(pixelBytes) }
                    }
                    0x40 -> {
                        // Literal run: runLength distinct pixels
                        repeat(runLength) {
                            if (src.remaining() < bytesPerPixel) return@repeat
                            val pixelBytes = ByteArray(bytesPerPixel)
                            src.get(pixelBytes)
                            writePixel(pixelBytes)   // FIX-G(b): was missing this call
                        }
                    }
                    0xF0 -> {
                        // End of scanline — snap to next row boundary
                        col = 0
                        row--
                    }
                    else -> {
                        // Unknown order — skip to avoid desync
                        Log.v(TAG, "RLE unknown order 0x${orderType.toString(16)}, skipping $runLength pixels")
                        val skipBytes = runLength * bytesPerPixel
                        if (src.remaining() >= skipBytes) src.position(src.position() + skipBytes)
                        else break
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "RLE decode error: ${e.message}")
        }

        return pixels
    }

    /**
     * Decode JPEG compressed bitmap (for slow connections)
     */
    private fun decodeJpegBitmap(data: ByteArray, width: Int, height: Int): IntArray? {
        return try {
            val options = BitmapFactory.Options().apply {
                inPreferredConfig = Bitmap.Config.ARGB_8888
            }
            val bitmap = BitmapFactory.decodeByteArray(data, 0, data.size, options)
                ?: return null
            val scaledBitmap = if (bitmap.width != width || bitmap.height != height) {
                Bitmap.createScaledBitmap(bitmap, width, height, false).also {
                    if (it != bitmap) bitmap.recycle()
                }
            } else bitmap

            val pixels = IntArray(scaledBitmap.width * scaledBitmap.height)
            scaledBitmap.getPixels(pixels, 0, scaledBitmap.width, 0, 0, scaledBitmap.width, scaledBitmap.height)
            scaledBitmap.recycle()
            pixels
        } catch (e: Exception) {
            Log.w(TAG, "JPEG decode error: ${e.message}")
            null
        }
    }

    private fun pixelToArgb(pixel: ByteArray, bpp: Int): Int {
        return when (bpp) {
            32, 24 -> {
                val b = pixel.getOrElse(0) { 0 }.toInt() and 0xFF
                val g = pixel.getOrElse(1) { 0 }.toInt() and 0xFF
                val r = pixel.getOrElse(2) { 0 }.toInt() and 0xFF
                0xFF000000.toInt() or (r shl 16) or (g shl 8) or b
            }
            16 -> {
                val p = ((pixel.getOrElse(1) { 0 }.toInt() and 0xFF) shl 8) or
                         (pixel.getOrElse(0) { 0 }.toInt() and 0xFF)
                val r = ((p shr 11) and 0x1F) * 255 / 31
                val g = ((p shr 5)  and 0x3F) * 255 / 63
                val b = ( p         and 0x1F) * 255 / 31
                0xFF000000.toInt() or (r shl 16) or (g shl 8) or b
            }
            8 -> {
                val v = pixel.getOrElse(0) { 0 }.toInt() and 0xFF
                0xFF000000.toInt() or (v shl 16) or (v shl 8) or v
            }
            else -> 0xFF000000.toInt()
        }
    }
}
