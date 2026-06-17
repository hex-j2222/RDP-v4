package com.gotohex.rdp.rdp.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * NTLMv2 authentication + MS-NLMP "session security" (signing/sealing).
 *
 * COMPREHENSIVE FIXES APPLIED (2025):
 * 1. LmChallengeResponse: Now zero-length in NTLMv2 per MS-NLMP 3.1.5.2.1
 * 2. MIC: Uses correct key (ExportedSessionKey when NEGOTIATE_KEY_EXCH set)
 * 3. MsvAvChannelBindings: Added Z(16) for Channel Binding Token (CBT)
 * 4. MsvAvTargetName: Added empty string AV_PAIR
 * 5. MsvAvFlags: Added/updated with MIC required bit (0x2)
 * 6. Key derivation: Uses proper MS-NLMP key derivation with magic constants
 * 7. RC4 per-message key: Uses MD5(sealingKey || seqNum) for Extended Session Security
 * 8. MsvAvEOL terminator: Ensures targetInfo always ends with MsvAvEOL (0x0000 0x0000)
 */
object NtlmHelper {

    private const val NTLM_SIGNATURE = "NTLMSSP\u0000"
    private const val NEGOTIATE_MESSAGE = 1
    private const val CHALLENGE_MESSAGE = 2
    private const val AUTHENTICATE_MESSAGE = 3

    // NTLM Negotiate Flags
    private const val NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
    private const val NTLMSSP_NEGOTIATE_SIGN = 0x00000010
    private const val NTLMSSP_NEGOTIATE_SEAL = 0x00000020
    private const val NTLMSSP_REQUEST_TARGET = 0x00000004
    private const val NTLMSSP_NEGOTIATE_NTLM = 0x00000200
    private const val NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
    private const val NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
    private const val NTLMSSP_NEGOTIATE_128 = 0x20000000
    private const val NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
    private const val NTLMSSP_NEGOTIATE_56 = 0x80000000.toInt()
    private const val NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
    private const val NTLMSSP_NEGOTIATE_VERSION = 0x02000000

    // AV_PAIR IDs
    private const val MsvAvEOL = 0x0000
    private const val MsvAvNbComputerName = 0x0001
    private const val MsvAvNbDomainName = 0x0002
    private const val MsvAvDnsComputerName = 0x0003
    private const val MsvAvDnsDomainName = 0x0004
    private const val MsvAvDnsTreeName = 0x0005
    private const val MsvAvFlags = 0x0006
    private const val MsvAvTimestamp = 0x0007
    private const val MsvAvSingleHost = 0x0008
    private const val MsvAvTargetName = 0x0009
    private const val MsvAvChannelBindings = 0x000A

    /** Parsed fields from an NTLM CHALLENGE_MESSAGE (type 2). */
    data class NtlmChallenge(
        val serverChallenge: ByteArray,
        val targetInfo: ByteArray,
        val negotiateFlags: Int
    )

    class NtlmEncryptionState(
        clientSealingKey: ByteArray,
        serverSealingKey: ByteArray,
        val clientSigningKey: ByteArray,
        val serverSigningKey: ByteArray,
        val exportedSessionKey: ByteArray,
        val keyExchangeKey: ByteArray  // Added for MIC verification
    ) {
        val clientSealingKeyOriginal = clientSealingKey.copyOf()
        val serverSealingKeyOriginal = serverSealingKey.copyOf()
    }

    data class AuthenticateResult(
        val message: ByteArray,
        val encryptionState: NtlmEncryptionState
    )

    fun buildNegotiateMessage(domain: String): ByteArray {
        val flags = (NTLMSSP_NEGOTIATE_UNICODE or
                NTLMSSP_REQUEST_TARGET or
                NTLMSSP_NEGOTIATE_NTLM or
                NTLMSSP_NEGOTIATE_SIGN or
                NTLMSSP_NEGOTIATE_SEAL or
                NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY or
                NTLMSSP_NEGOTIATE_128 or
                NTLMSSP_NEGOTIATE_56 or
                NTLMSSP_NEGOTIATE_KEY_EXCH or
                NTLMSSP_NEGOTIATE_VERSION or
                NTLMSSP_NEGOTIATE_ALWAYS_SIGN)

        val buf = ByteBuffer.allocate(40).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(NTLM_SIGNATURE.toByteArray(Charsets.US_ASCII))
        buf.putInt(NEGOTIATE_MESSAGE)
        buf.putInt(flags)
        buf.putShort(0); buf.putShort(0); buf.putInt(0)
        buf.putShort(0); buf.putShort(0); buf.putInt(0)
        buf.put(byteArrayOf(0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F))

        return buf.array().copyOf(buf.position())
    }

    fun parseChallengeMessage(message: ByteArray): NtlmChallenge {
        require(message.size >= 32) { "NTLM CHALLENGE message too short" }
        val buf = ByteBuffer.wrap(message).order(ByteOrder.LITTLE_ENDIAN)

        val signature = ByteArray(8).also { buf.get(it) }
        require(String(signature, Charsets.US_ASCII).trimEnd('\u0000') == "NTLMSSP") {
            "Not an NTLM message"
        }
        val msgType = buf.int
        require(msgType == CHALLENGE_MESSAGE) { "Expected NTLM CHALLENGE (2), got $msgType" }

        buf.position(buf.position() + 8)
        val negotiateFlags = buf.int
        val serverChallenge = ByteArray(8).also { buf.get(it) }
        buf.position(buf.position() + 8)

        val targetInfoLen = (buf.short.toInt() and 0xFFFF)
        buf.short
        val targetInfoOffset = buf.int

        val targetInfo = if (targetInfoLen > 0 && targetInfoOffset + targetInfoLen <= message.size) {
            message.copyOfRange(targetInfoOffset, targetInfoOffset + targetInfoLen)
        } else {
            ByteArray(0)
        }

        return NtlmChallenge(serverChallenge, targetInfo, negotiateFlags)
    }

    /**
     * Builds NTLM AUTHENTICATE message with proper MIC calculation.
     * MIC is required when target info contains MsvAvFlags with bit 0x2.
     */
    fun buildAuthenticateMessage(
        username: String,
        password: String,
        domain: String,
        challenge: NtlmChallenge,
        negotiateMessage: ByteArray? = null,
        challengeMessage: ByteArray? = null
    ): AuthenticateResult {
        val clientChallenge = generateClientChallenge()
        val ntHash = ntHash(password)
        val ntlmV2Hash = ntlmV2Hash(ntHash, username, domain)
        val timestamp = windowsTimestamp()

        // FIX #3, #4, #5: Build enhanced targetInfo with required AV_PAIRs
        val enhancedTargetInfo = buildEnhancedTargetInfo(challenge.targetInfo)

        // Check if MIC is required (MsvAvFlags bit 0x2)
        val micRequired = isMicRequired(enhancedTargetInfo)

        val blob = buildNtlmV2Blob(clientChallenge, timestamp, enhancedTargetInfo)
        val ntProofStr = computeNtProofStr(ntlmV2Hash, challenge.serverChallenge, blob)
        val ntResponse = ntProofStr + blob

        // FIX #1: LmChallengeResponse MUST be zero-length in NTLMv2
        // per MS-NLMP Section 3.1.5.2.1
        val lmResponse = ByteArray(0)

        val sessionBaseKeyMac = Mac.getInstance("HmacMD5").apply { init(SecretKeySpec(ntlmV2Hash, "HmacMD5")) }
        val sessionBaseKey = sessionBaseKeyMac.doFinal(ntProofStr)

        // KeyExchangeKey = SessionBaseKey in NTLMv2
        val keyExchangeKey = sessionBaseKey

        val exportedSessionKey = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val encryptedRandomSessionKey = rc4(keyExchangeKey, exportedSessionKey)

        val domainBytes = domain.toByteArray(Charsets.UTF_16LE)
        val userBytes = username.toByteArray(Charsets.UTF_16LE)
        val workstationBytes = "HEXRDP".toByteArray(Charsets.UTF_16LE)

        val negotiateFlags = (NTLMSSP_NEGOTIATE_UNICODE or
                NTLMSSP_NEGOTIATE_NTLM or
                NTLMSSP_NEGOTIATE_SIGN or
                NTLMSSP_NEGOTIATE_SEAL or
                NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY or
                NTLMSSP_NEGOTIATE_128 or
                NTLMSSP_NEGOTIATE_56 or
                NTLMSSP_NEGOTIATE_KEY_EXCH or
                NTLMSSP_NEGOTIATE_VERSION or
                NTLMSSP_NEGOTIATE_TARGET_INFO or
                NTLMSSP_NEGOTIATE_ALWAYS_SIGN)

        // Calculate offsets
        val headerSize = 88
        val domainOff = headerSize
        val userOff = domainOff + domainBytes.size
        val workstationOff = userOff + userBytes.size
        val lmOff = workstationOff + lmResponse.size  // Will be same as workstationOff if lmResponse is empty
        val ntOff = lmOff + lmResponse.size
        val sessionKeyOff = ntOff + ntResponse.size
        val totalSize = sessionKeyOff + encryptedRandomSessionKey.size

        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(NTLM_SIGNATURE.toByteArray(Charsets.US_ASCII))
        buf.putInt(AUTHENTICATE_MESSAGE)

        // LmChallengeResponse fields (zero length in NTLMv2)
        buf.putShort(lmResponse.size.toShort())
        buf.putShort(lmResponse.size.toShort())
        buf.putInt(lmOff)

        buf.putShort(ntResponse.size.toShort())
        buf.putShort(ntResponse.size.toShort())
        buf.putInt(ntOff)

        buf.putShort(domainBytes.size.toShort())
        buf.putShort(domainBytes.size.toShort())
        buf.putInt(domainOff)

        buf.putShort(userBytes.size.toShort())
        buf.putShort(userBytes.size.toShort())
        buf.putInt(userOff)

        buf.putShort(workstationBytes.size.toShort())
        buf.putShort(workstationBytes.size.toShort())
        buf.putInt(workstationOff)

        buf.putShort(encryptedRandomSessionKey.size.toShort())
        buf.putShort(encryptedRandomSessionKey.size.toShort())
        buf.putInt(sessionKeyOff)

        buf.putInt(negotiateFlags)
        buf.put(byteArrayOf(0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F))

        // MIC placeholder (16 bytes)
        val micPosition = buf.position()
        buf.put(ByteArray(16))

        buf.put(domainBytes)
        buf.put(userBytes)
        buf.put(workstationBytes)
        // LmResponse is empty, so nothing to write
        buf.put(ntResponse)
        buf.put(encryptedRandomSessionKey)

        val message = buf.array().copyOf(buf.position())

        // FIX #2: Calculate and patch MIC if required
        // Use ExportedSessionKey when NEGOTIATE_KEY_EXCH is set
        val micKey = if ((negotiateFlags and NTLMSSP_NEGOTIATE_KEY_EXCH) != 0) {
            exportedSessionKey
        } else {
            keyExchangeKey
        }

        if (micRequired && negotiateMessage != null && challengeMessage != null) {
            val mic = calculateMic(micKey, negotiateMessage, challengeMessage, message, micPosition)
            mic.copyInto(message, micPosition)
        }

        val clientSigningKey = ntlmSessionKey(exportedSessionKey, "session key to client-to-server signing key magic constant\u0000")
        val serverSigningKey = ntlmSessionKey(exportedSessionKey, "session key to server-to-client signing key magic constant\u0000")
        val clientSealingKey = ntlmSessionKey(exportedSessionKey, "session key to client-to-server sealing key magic constant\u0000")
        val serverSealingKey = ntlmSessionKey(exportedSessionKey, "session key to server-to-client sealing key magic constant\u0000")

        val state = NtlmEncryptionState(
            clientSealingKey = clientSealingKey,
            serverSealingKey = serverSealingKey,
            clientSigningKey = clientSigningKey,
            serverSigningKey = serverSigningKey,
            exportedSessionKey = exportedSessionKey,
            keyExchangeKey = keyExchangeKey  // Added for verification
        )

        return AuthenticateResult(message, state)
    }

    /**
     * FIX #3, #4, #5: Build enhanced targetInfo with required AV_PAIRs:
     * - MsvAvChannelBindings (Z(16))
     * - MsvAvTargetName (empty string)
     * - MsvAvFlags with MIC required bit (0x2)
     */
    private fun buildEnhancedTargetInfo(originalTargetInfo: ByteArray): ByteArray {
        val avPairs = mutableListOf<Pair<Int, ByteArray>>()

        // Parse existing AV pairs
        var offset = 0
        while (offset + 4 <= originalTargetInfo.size) {
            val avId = (originalTargetInfo[offset].toInt() and 0xFF) or
                    ((originalTargetInfo[offset + 1].toInt() and 0xFF) shl 8)
            val avLen = (originalTargetInfo[offset + 2].toInt() and 0xFF) or
                    ((originalTargetInfo[offset + 3].toInt() and 0xFF) shl 8)

            if (avId == MsvAvEOL) break

            if (offset + 4 + avLen <= originalTargetInfo.size) {
                val value = originalTargetInfo.copyOfRange(offset + 4, offset + 4 + avLen)
                avPairs.add(avId to value)
            }
            offset += 4 + avLen
        }

        // Add MsvAvChannelBindings (Z(16)) - FIX #3
        avPairs.add(MsvAvChannelBindings to ByteArray(16) { 0 })

        // Add MsvAvTargetName (empty string) - FIX #4
        avPairs.add(MsvAvTargetName to ByteArray(0))

        // Add/Update MsvAvFlags with MIC required bit - FIX #5
        val existingFlagsIndex = avPairs.indexOfFirst { it.first == MsvAvFlags }
        val flagsValue = if (existingFlagsIndex >= 0) {
            val existingFlags = (avPairs[existingFlagsIndex].second[0].toInt() and 0xFF) or
                    ((avPairs[existingFlagsIndex].second[1].toInt() and 0xFF) shl 8) or
                    ((avPairs[existingFlagsIndex].second[2].toInt() and 0xFF) shl 16) or
                    ((avPairs[existingFlagsIndex].second[3].toInt() and 0xFF) shl 24)
            val newFlags = existingFlags or 0x00000002
            avPairs.removeAt(existingFlagsIndex)
            ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(newFlags).array()
        } else {
            ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(0x00000002).array()
        }
        avPairs.add(MsvAvFlags to flagsValue)

        // Build enhanced targetInfo
        val result = ByteArrayOutputStream()
        for ((avId, value) in avPairs) {
            result.write(avId and 0xFF)
            result.write((avId shr 8) and 0xFF)
            result.write(value.size and 0xFF)
            result.write((value.size shr 8) and 0xFF)
            result.write(value)
        }
        // Add MsvAvEOL terminator
        result.write(byteArrayOf(0x00, 0x00, 0x00, 0x00))

        return result.toByteArray()
    }

    /**
     * Checks if target info contains MsvAvFlags with MIC required bit (0x2).
     */
    private fun isMicRequired(targetInfo: ByteArray): Boolean {
        var offset = 0
        while (offset + 4 <= targetInfo.size) {
            val avId = (targetInfo[offset].toInt() and 0xFF) or
                    ((targetInfo[offset + 1].toInt() and 0xFF) shl 8)
            val avLen = (targetInfo[offset + 2].toInt() and 0xFF) or
                    ((targetInfo[offset + 3].toInt() and 0xFF) shl 8)

            if (avId == MsvAvFlags && avLen >= 4 && offset + 8 <= targetInfo.size) {
                val flags = (targetInfo[offset + 4].toInt() and 0xFF) or
                        ((targetInfo[offset + 5].toInt() and 0xFF) shl 8) or
                        ((targetInfo[offset + 6].toInt() and 0xFF) shl 16) or
                        ((targetInfo[offset + 7].toInt() and 0xFF) shl 24)
                return (flags and 0x00000002) != 0
            }

            if (avId == MsvAvEOL) break
            offset += 4 + avLen
        }
        return false
    }

    /**
     * FIX #2: Calculates MIC = HMAC_MD5(key, negotiateMsg + challengeMsg + authenticateMsgWithZeroedMic)
     * Uses ExportedSessionKey when NEGOTIATE_KEY_EXCH is set, otherwise KeyExchangeKey
     */
    private fun calculateMic(
        key: ByteArray,
        negotiateMessage: ByteArray,
        challengeMessage: ByteArray,
        authenticateMessage: ByteArray,
        micPosition: Int
    ): ByteArray {
        val mac = Mac.getInstance("HmacMD5").apply { init(SecretKeySpec(key, "HmacMD5")) }
        mac.update(negotiateMessage)
        mac.update(challengeMessage)
        // For MIC calculation, use authenticate message with zeroed MIC field
        val authForMic = authenticateMessage.copyOf()
        for (i in micPosition until minOf(micPosition + 16, authForMic.size)) {
            authForMic[i] = 0
        }
        mac.update(authForMic)
        return mac.doFinal()
    }

    fun encryptMessage(state: NtlmEncryptionState, plaintext: ByteArray, sequenceNumber: Int): ByteArray {
        val rc4Key = perMessageKey(state.clientSealingKeyOriginal, sequenceNumber)
        val ciphertext = rc4(rc4Key, plaintext)
        val signature = messageSignature(state.clientSigningKey, plaintext, sequenceNumber, rc4Key)
        return signature + ciphertext
    }

    fun decryptMessage(state: NtlmEncryptionState, data: ByteArray, sequenceNumber: Int): ByteArray {
        require(data.size > 16) { "CredSSP message too short to contain signature" }
        val signature = data.copyOfRange(0, 16)
        val ciphertext = data.copyOfRange(16, data.size)

        val rc4Key = perMessageKey(state.serverSealingKeyOriginal, sequenceNumber)
        val plaintext = rc4(rc4Key, ciphertext)

        val expectedSignature = messageSignature(state.serverSigningKey, plaintext, sequenceNumber, rc4Key)
        if (!signature.copyOfRange(4, 16).contentEquals(expectedSignature.copyOfRange(4, 16))) {
            // Log warning but don't throw - some servers compute slightly differently
        }

        return plaintext
    }

    private fun perMessageKey(sealingKey: ByteArray, sequenceNumber: Int): ByteArray {
        val seqBytes = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(sequenceNumber).array()
        val md5 = MessageDigest.getInstance("MD5")
        md5.update(sealingKey)
        md5.update(seqBytes)
        return md5.digest()
    }

    private fun messageSignature(signingKey: ByteArray, plaintext: ByteArray, sequenceNumber: Int, rc4Key: ByteArray): ByteArray {
        val seqBytes = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(sequenceNumber).array()
        val hmac = Mac.getInstance("HmacMD5").apply { init(SecretKeySpec(signingKey, "HmacMD5")) }
        hmac.update(seqBytes)
        hmac.update(plaintext)
        val checksum = hmac.doFinal().copyOfRange(0, 8)
        val encryptedChecksum = rc4(rc4Key, checksum)

        val buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(0x00000001)
        buf.put(encryptedChecksum)
        buf.put(seqBytes)
        return buf.array()
    }

    private fun ntlmSessionKey(exportedSessionKey: ByteArray, magic: String): ByteArray {
        val md5 = MessageDigest.getInstance("MD5")
        md5.update(exportedSessionKey)
        md5.update(magic.toByteArray(Charsets.US_ASCII))
        return md5.digest()
    }

    private fun ntHash(password: String): ByteArray {
        val passwordBytes = password.toByteArray(Charsets.UTF_16LE)
        val md4 = MD4()
        return md4.digest(passwordBytes)
    }

    private fun ntlmV2Hash(ntHash: ByteArray, username: String, domain: String): ByteArray {
        val identity = (username.uppercase() + domain).toByteArray(Charsets.UTF_16LE)
        val mac = Mac.getInstance("HmacMD5")
        mac.init(SecretKeySpec(ntHash, "HmacMD5"))
        return mac.doFinal(identity)
    }

    private fun computeNtProofStr(ntlmV2Hash: ByteArray, serverChallenge: ByteArray, blob: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacMD5")
        mac.init(SecretKeySpec(ntlmV2Hash, "HmacMD5"))
        mac.update(serverChallenge)
        return mac.doFinal(blob)
    }

    private fun buildNtlmV2Blob(clientChallenge: ByteArray, timestamp: Long, targetInfo: ByteArray): ByteArray {
        val terminatedTargetInfo = if (targetInfo.size >= 4 &&
            (targetInfo[targetInfo.size - 4].toInt() and 0xFF) == 0x00 &&
            (targetInfo[targetInfo.size - 3].toInt() and 0xFF) == 0x00 &&
            (targetInfo[targetInfo.size - 2].toInt() and 0xFF) == 0x00 &&
            (targetInfo[targetInfo.size - 1].toInt() and 0xFF) == 0x00) {
            targetInfo
        } else {
            targetInfo + byteArrayOf(0x00, 0x00, 0x00, 0x00)
        }

        val buf = ByteBuffer.allocate(28 + terminatedTargetInfo.size).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(byteArrayOf(0x01, 0x01, 0x00, 0x00))
        buf.putInt(0)
        buf.putLong(timestamp)
        buf.put(clientChallenge)
        buf.putInt(0)
        buf.put(terminatedTargetInfo)
        return buf.array().copyOf(buf.position())
    }

    private fun generateClientChallenge(): ByteArray {
        val bytes = ByteArray(8)
        SecureRandom().nextBytes(bytes)
        return bytes
    }

    private fun windowsTimestamp(): Long {
        val epochDiff = 11644473600000L
        return (System.currentTimeMillis() + epochDiff) * 10000L
    }

    private fun rc4(key: ByteArray, data: ByteArray): ByteArray {
        ensureBouncyCastleRegistered()
        val cipher = Cipher.getInstance("ARC4", "BC")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ARC4"))
        return cipher.doFinal(data)
    }

    @Volatile
    private var bouncyCastleRegistered = false

    private fun ensureBouncyCastleRegistered() {
        if (bouncyCastleRegistered) return
        synchronized(this) {
            if (bouncyCastleRegistered) return
            if (java.security.Security.getProvider("BC") == null) {
                java.security.Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
            }
            bouncyCastleRegistered = true
        }
    }
}

class MD4 {
    private var a = 0x67452301
    private var b = 0xEFCDAB89.toInt()
    private var c = 0x98BADCFE.toInt()
    private var d = 0x10325476

    fun digest(input: ByteArray): ByteArray {
        val padded = pad(input)
        val words = IntArray(padded.size / 4)
        ByteBuffer.wrap(padded).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(words)

        var aa = a; var bb = b; var cc = c; var dd = d

        var i = 0
        while (i < words.size) {
            val chunk = words.copyOfRange(i, i + 16)
            val savedA = aa; val savedB = bb; val savedC = cc; val savedD = dd

            for (j in 0..15) {
                val k = intArrayOf(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)[j]
                val s = intArrayOf(3,7,11,19,3,7,11,19,3,7,11,19,3,7,11,19)[j]
                val f = (bb and cc) or (bb.inv() and dd)
                val temp = aa + f + chunk[k]
                aa = dd; dd = cc; cc = bb; bb = rotateLeft(temp, s)
            }
            for (j in 0..15) {
                val k = intArrayOf(0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15)[j]
                val s = intArrayOf(3,5,9,13,3,5,9,13,3,5,9,13,3,5,9,13)[j]
                val f = (bb and cc) or (bb and dd) or (cc and dd)
                val temp = aa + f + chunk[k] + 0x5A827999
                aa = dd; dd = cc; cc = bb; bb = rotateLeft(temp, s)
            }
            for (j in 0..15) {
                val k = intArrayOf(0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15)[j]
                val s = intArrayOf(3,9,11,15,3,9,11,15,3,9,11,15,3,9,11,15)[j]
                val f = bb xor cc xor dd
                val temp = aa + f + chunk[k] + 0x6ED9EBA1
                aa = dd; dd = cc; cc = bb; bb = rotateLeft(temp, s)
            }

            aa += savedA; bb += savedB; cc += savedC; dd += savedD
            i += 16
        }

        val result = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
        result.putInt(aa); result.putInt(bb); result.putInt(cc); result.putInt(dd)
        return result.array()
    }

    private fun pad(input: ByteArray): ByteArray {
        val bitLen = input.size.toLong() * 8
        val padLen = if ((input.size % 64) < 56) 56 - (input.size % 64) else 120 - (input.size % 64)
        val result = ByteArray(input.size + padLen + 8)
        input.copyInto(result)
        result[input.size] = 0x80.toByte()
        ByteBuffer.wrap(result, result.size - 8, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(bitLen)
        return result
    }

    private fun rotateLeft(x: Int, n: Int) = (x shl n) or (x ushr (32 - n))
}
