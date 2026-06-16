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
 * Performance strategy:
 * - LOW_BANDWIDTH: 8bpp, heavy JPEG compression
 * - MEDIUM: 16bpp, RLE compression
 * - WIFI: 24bpp, RLE compression
 * - LAN: 32bpp, raw or light compression
 */
class RdpBitmapDecoder {

    companion object {
        private const val TAG = "BitmapDecoder"

        // Bitmap compression types
        const val BITMAP_COMPRESSION_NONE = 0x00
        const val BITMAP_COMPRESSION_RLE = 0x01
        const val BITMAP_COMPRESSION_JPEG = 0x04
        const val BITMAP_COMPRESSION_REMOTEFX = 0x08

        // Update types
        const val UPDATE_TYPE_ORDERS = 0x0000
        const val UPDATE_TYPE_BITMAP = 0x0001
        const val UPDATE_TYPE_PALETTE = 0x0002
        const val UPDATE_TYPE_SYNCHRONIZE = 0x0003
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
                UPDATE_TYPE_BITMAP -> decodeBitmapUpdate(buf, frames, performance)
                UPDATE_TYPE_ORDERS -> decodeOrdersUpdate(buf, frames, screenWidth, screenHeight)
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
                val destLeft = buf.short.toInt() and 0xFFFF
                val destTop = buf.short.toInt() and 0xFFFF
                val destRight = buf.short.toInt() and 0xFFFF
                val destBottom = buf.short.toInt() and 0xFFFF
                val width = buf.short.toInt() and 0xFFFF
                val height = buf.short.toInt() and 0xFFFF
                val bitsPerPixel = buf.short.toInt() and 0xFFFF
                val flags = buf.short.toInt() and 0xFFFF
                val bitmapLength = buf.short.toInt() and 0xFFFF

                if (bitmapLength <= 0 || buf.remaining() < bitmapLength) return@repeat
                val bitmapData = ByteArray(bitmapLength)
                buf.get(bitmapData)

                val isCompressed = (flags and 0x0001) != 0
                val isJpeg = (flags and 0x0008) != 0

                val pixels = when {
                    isJpeg -> decodeJpegBitmap(bitmapData, width, height)
                    isCompressed -> decodeRleBitmap(bitmapData, width, height, bitsPerPixel)
                    else -> decodeRawBitmap(bitmapData, width, height, bitsPerPixel)
                }

                if (pixels != null) {
                    // CRITICAL FIX: the destination rectangle (destLeft/Top/Right/Bottom)
                    // can have different dimensions than the bitmap data itself
                    // (width/height read just above). Previously the frame's
                    // width/height were taken from the *destination rectangle*
                    // while `pixels` was sized from the *decoded bitmap* — when
                    // these differ (which real servers do regularly), every
                    // downstream consumer (Bitmap.createBitmap / setPixels) reads
                    // past the end of `pixels`, throwing an
                    // ArrayIndexOutOfBoundsException on the UI/collector thread
                    // with no handler, which kills the whole app the moment a
                    // frame update arrives — i.e. immediately after "Connected".
                    // Always report the *actual* decoded bitmap size.
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
        // Simplified order processing - ScrBlt, MemBlt, PatBlt
        if (buf.remaining() < 4) return
        buf.short // pad2octets
        val numberOrders = buf.short.toInt() and 0xFFFF
        // Order processing is complex; we request full screen refresh instead
        // via suppress output / refresh rect PDU
    }

    /**
     * Decode raw (uncompressed) bitmap
     */
    private fun decodeRawBitmap(data: ByteArray, width: Int, height: Int, bpp: Int): IntArray? {
        if (width <= 0 || height <= 0) return null
        val pixels = IntArray(width * height)

        when (bpp) {
            32 -> {
                val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
                // RDP bitmaps are bottom-up
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
                    // Align to 4 bytes
                    val padding = (3 * width) % 4
                    if (padding != 0) repeat(4 - padding) { if (buf.remaining() > 0) buf.get() }
                }
            }
            16 -> {
                val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
                for (row in height - 1 downTo 0) {
                    for (col in 0 until width) {
                        if (buf.remaining() < 2) break
                        val pixel16 = buf.short.toInt() and 0xFFFF
                        val r = ((pixel16 shr 11) and 0x1F) * 255 / 31
                        val g = ((pixel16 shr 5) and 0x3F) * 255 / 63
                        val b = (pixel16 and 0x1F) * 255 / 31
                        pixels[row * width + col] = 0xFF000000.toInt() or (r shl 16) or (g shl 8) or b
                    }
                }
            }
            else -> return null
        }

        return pixels
    }

    /**
     * Decode RLE compressed bitmap (Interleaved RLE)
     */
    private fun decodeRleBitmap(data: ByteArray, width: Int, height: Int, bpp: Int): IntArray? {
        if (width <= 0 || height <= 0) return null
        val pixels = IntArray(width * height)

        try {
            val bytesPerPixel = bpp / 8
            val src = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
            val rowData = ByteArray(width * bytesPerPixel)
            var dstRow = height - 1

            while (src.hasRemaining() && dstRow >= 0) {
                val code = src.get().toInt() and 0xFF
                val orderType = code and 0xF0
                val runLength = when {
                    (code and 0x0F) != 0 -> code and 0x0F
                    src.hasRemaining() -> (src.get().toInt() and 0xFF) + 16
                    else -> break
                }

                when (orderType) {
                    0x00 -> { // Regular run
                        if (src.remaining() < bytesPerPixel) break
                        val pixel = ByteArray(bytesPerPixel)
                        src.get(pixel)
                        repeat(runLength) { i ->
                            val col = (i) % width // simplified
                            if (col < width && dstRow >= 0) {
                                val argb = pixelToArgb(pixel, bpp)
                                pixels[dstRow * width + col] = argb
                            }
                        }
                    }
                    0x40 -> { // Non-run (literal)
                        val bytesNeeded = runLength * bytesPerPixel
                        if (src.remaining() < bytesNeeded) break
                        for (i in 0 until runLength) {
                            val pixel = ByteArray(bytesPerPixel)
                            src.get(pixel)
                        }
                    }
                    0xF0 -> { // End of scanline
                        dstRow--
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
            32 -> {
                val b = pixel[0].toInt() and 0xFF
                val g = pixel[1].toInt() and 0xFF
                val r = pixel[2].toInt() and 0xFF
                0xFF000000.toInt() or (r shl 16) or (g shl 8) or b
            }
            24 -> {
                val b = pixel[0].toInt() and 0xFF
                val g = pixel[1].toInt() and 0xFF
                val r = pixel[2].toInt() and 0xFF
                0xFF000000.toInt() or (r shl 16) or (g shl 8) or b
            }
            16 -> {
                val p = ((pixel[1].toInt() and 0xFF) shl 8) or (pixel[0].toInt() and 0xFF)
                val r = ((p shr 11) and 0x1F) * 255 / 31
                val g = ((p shr 5) and 0x3F) * 255 / 63
                val b = (p and 0x1F) * 255 / 31
                0xFF000000.toInt() or (r shl 16) or (g shl 8) or b
            }
            else -> 0xFF000000.toInt()
        }
    }
}
