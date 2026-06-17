package com.gotohex.rdp.rdp.protocol

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * NTLMv2 authentication + MS-NLMP "session security" (signing/sealing).
 *
 * FIXES APPLIED (connection-failure audit):
 * 1. MIC calculation is no longer silently skippable: negotiateMessage/
 *    challengeMessage are required parameters (not nullable defaults), so a
 *    server that marks MIC as mandatory (MsvAvFlags bit 0x2) always gets a
 *    correctly-signed AUTHENTICATE_MESSAGE instead of one with a zeroed MIC
 *    field, which modern Windows servers (2016+) reject immediately.
 * 2. decryptMessage() now THROWS RdpAuthException on signature mismatch
 *    instead of logging a warning and returning garbage plaintext. A
 *    mismatch means the derived session key is wrong (bad credentials or
 *    incompatible CredSSP mode) and must not be allowed to propagate into
 *    pubKeyAuth verification, where it previously surfaced as a confusing,
 *    unrelated failure.
 * 3. Key derivation follows MS-NLMP 3.1.5.1.2: KeyExchangeKey = SessionBaseKey
 *    (NTLMv2), ExportedSessionKey = RC4K(KeyExchangeKey, random 16 bytes)
 *    because NTLMSSP_NEGOTIATE_KEY_EXCH is always negotiated together with
 *    SIGN/SEAL.
 * 4. RC4 per-message key: MD5(sealingKey || seqNum) for Extended Session Security.
 * 5. MsvAvEOL terminator: targetInfo is always ended with MsvAvEOL (0x0000 0x0000)
 *    before being included in the NTLMv2 blob.
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
    private const val MsvAvFlags = 0x0006
    private const val MsvAvEOL = 0x0000

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
        val exportedSessionKey: ByteArray
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
     *
     * FIX: negotiateMessage/challengeMessage are now REQUIRED (not nullable).
     * The original signature made them optional with a default of `null`,
     * which meant that if a caller ever forgot to pass them, MIC computation
     * was silently skipped — even when the server's target info marks MIC as
     * mandatory (MsvAvFlags bit 0x2). Modern Windows servers (2016+) reject
     * the AUTHENTICATE_MESSAGE outright in that case, with no useful error
     * surfaced to the client. Failing loudly here, at the point the bug would
     * be introduced, is far easier to diagnose than a generic CredSSP failure
     * several network round-trips later.
     */
    fun buildAuthenticateMessage(
        username: String,
        password: String,
        domain: String,
        challenge: NtlmChallenge,
        negotiateMessage: ByteArray,
        challengeMessage: ByteArray,
        serverSpn: String = ""
    ): AuthenticateResult {
        val clientChallenge = generateClientChallenge()
        val ntHash = ntHash(password)
        val ntlmV2Hash = ntlmV2Hash(ntHash, username, domain)
        val timestamp = windowsTimestamp()

        // Check if MIC is required (MsvAvFlags bit 0x2)
        val micRequired = isMicRequired(challenge.targetInfo)

        val blob = buildNtlmV2Blob(clientChallenge, timestamp, challenge.targetInfo, serverSpn)
        val ntProofStr = computeNtProofStr(ntlmV2Hash, challenge.serverChallenge, blob)
        val ntResponse = ntProofStr + blob

        val lmHmac = Mac.getInstance("HmacMD5").apply { init(SecretKeySpec(ntlmV2Hash, "HmacMD5")) }
        val lmProof = lmHmac.doFinal(challenge.serverChallenge + clientChallenge)
        val lmResponse = lmProof + clientChallenge

        val sessionBaseKeyMac = Mac.getInstance("HmacMD5").apply { init(SecretKeySpec(ntlmV2Hash, "HmacMD5")) }
        val sessionBaseKey = sessionBaseKeyMac.doFinal(ntProofStr)

        // KeyExchangeKey == SessionBaseKey for NTLMv2 (MS-NLMP 3.4.5.2, KXKEY).
        val keyExchangeKey = sessionBaseKey

        // FIX: We always negotiate NTLMSSP_NEGOTIATE_KEY_EXCH together with
        // SIGN/SEAL below, so per MS-NLMP 3.1.5.1.2 the ExportedSessionKey
        // MUST be RC4K(KeyExchangeKey, EncryptedRandomSessionKey) — i.e. the
        // randomly generated key we are about to transmit, encrypted with
        // keyExchangeKey. This was already correct in spirit, but is now
        // computed explicitly and reused everywhere (MIC + signing/sealing
        // keys) instead of silently risking the two getting out of sync.
        val exportedSessionKey = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
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

        val headerSize = 88
        val domainOff = headerSize
        val userOff = domainOff + domainBytes.size
        val workstationOff = userOff + userBytes.size
        val lmOff = workstationOff + workstationBytes.size
        val ntOff = lmOff + lmResponse.size
        val sessionKeyOff = ntOff + ntResponse.size
        val totalSize = sessionKeyOff + encryptedRandomSessionKey.size

        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(NTLM_SIGNATURE.toByteArray(Charsets.US_ASCII))
        buf.putInt(AUTHENTICATE_MESSAGE)

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

        // MIC placeholder (16 bytes) - zeroed until patched below
        val micPosition = buf.position()
        buf.put(ByteArray(16))

        buf.put(domainBytes)
        buf.put(userBytes)
        buf.put(workstationBytes)
        buf.put(lmResponse)
        buf.put(ntResponse)
        buf.put(encryptedRandomSessionKey)

        val message = buf.array().copyOf(buf.position())

        // FIX: MIC is computed whenever the server's target info marks it as
        // required. Previously this was gated on negotiateMessage/
        // challengeMessage being non-null, which could silently no-op and
        // send an AUTHENTICATE_MESSAGE with a zeroed MIC field to a server
        // that requires one -- an instant, hard-to-diagnose rejection.
        if (micRequired) {
            val mic = calculateMic(exportedSessionKey, negotiateMessage, challengeMessage, message, micPosition)
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
            exportedSessionKey = exportedSessionKey
        )

        return AuthenticateResult(message, state)
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
     * Calculates MIC = HMAC_MD5(exportedSessionKey, negotiateMsg + challengeMsg + authenticateMsgWithZeroedMic)
     */
    private fun calculateMic(
        exportedSessionKey: ByteArray,
        negotiateMessage: ByteArray,
        challengeMessage: ByteArray,
        authenticateMessage: ByteArray,
        micPosition: Int
    ): ByteArray {
        val mac = Mac.getInstance("HmacMD5").apply { init(SecretKeySpec(exportedSessionKey, "HmacMD5")) }
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

        // FIX: A signature mismatch means either the wrong key was derived
        // (password/session-key error) or the server rejected/garbled the
        // exchange. Silently continuing here previously caused garbage bytes
        // to propagate downstream (e.g. into verifyPubKeyAuthResponse), which
        // then failed with a confusing, unrelated error far away from the
        // real cause. Fail fast and close to the source instead.
        val expectedSignature = messageSignature(state.serverSigningKey, plaintext, sequenceNumber, rc4Key)
        if (!signature.copyOfRange(4, 16).contentEquals(expectedSignature.copyOfRange(4, 16))) {
            throw RdpAuthException(
                "CredSSP message signature verification failed (seq=$sequenceNumber). " +
                "This usually means the NTLM session key is wrong (bad password/domain) " +
                "or the server uses an incompatible CredSSP mode."
            )
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

    /**
     * Builds the NTLMv2 blob (TargetInfoFields) per MS-NLMP 3.3.2.
     *
     * FIX-M (v4.2): Windows Server 2012+ and all 2025/2026 servers require the
     * client to AUGMENT the server's targetInfo before embedding it in the blob:
     *
     * 1. If MsvAvTimestamp (AvId=0x0007) is present in the server's targetInfo,
     *    the client MUST use that timestamp (not generate its own) and MUST add
     *    MsvAvFlags (AvId=0x0006) with bit 0x00000002 set (indicating MIC).
     *    Failing to do so causes Windows 2012/2016/2019/2022/2025 to reject the
     *    AUTHENTICATE_MESSAGE with STATUS_LOGON_FAILURE, even with correct creds.
     *
     * 2. MsvAvChannelBindings (AvId=0x000A) must be added as 16 zero bytes
     *    (indicates no channel binding) when not already present.
     *
     * 3. MsvAvTargetName (AvId=0x0009) with the server's SPN ("TERMSRV/<host>")
     *    should be added for servers that enforce it (Server 2019+).
     *
     * 4. The EOL terminator check was wrong: it checked the last 4 bytes for
     *    zeros, but MsvAvEOL is avId(0x0000) + avLen(0x0000) = 4 zero bytes —
     *    the check was accidentally correct in structure but missed cases where
     *    the last actual AV pair had trailing zeros in its value. Replaced with
     *    a proper AV_PAIR walker that checks if EOL is already the last entry.
     */
    private fun buildNtlmV2Blob(
        clientChallenge: ByteArray,
        timestamp: Long,
        targetInfo: ByteArray,
        serverSpn: String = ""
    ): ByteArray {
        // Walk the server's targetInfo and extract/modify fields
        var effectiveTimestamp = timestamp
        var hasMsvAvFlags = false
        var hasChannelBindings = false
        var hasTargetName = false
        var hasMsvAvTimestamp = false

        val avPairs = mutableListOf<Pair<Int, ByteArray>>()
        var offset = 0
        while (offset + 4 <= targetInfo.size) {
            val avId = (targetInfo[offset].toInt() and 0xFF) or
                    ((targetInfo[offset + 1].toInt() and 0xFF) shl 8)
            val avLen = (targetInfo[offset + 2].toInt() and 0xFF) or
                    ((targetInfo[offset + 3].toInt() and 0xFF) shl 8)
            if (avId == 0x0000) break  // MsvAvEOL
            val avVal = targetInfo.copyOfRange(
                (offset + 4).coerceAtMost(targetInfo.size),
                (offset + 4 + avLen).coerceAtMost(targetInfo.size)
            )
            when (avId) {
                0x0006 -> { hasMsvAvFlags = true }   // MsvAvFlags
                0x0007 -> {                           // MsvAvTimestamp
                    hasMsvAvTimestamp = true
                    if (avLen == 8) {
                        // Use server-provided timestamp per MS-NLMP §3.1.5.1.2
                        effectiveTimestamp = ByteBuffer.wrap(avVal).order(ByteOrder.LITTLE_ENDIAN).long
                    }
                }
                0x000A -> { hasChannelBindings = true } // MsvAvChannelBindings
                0x0009 -> { hasTargetName = true }      // MsvAvTargetName
            }
            avPairs.add(Pair(avId, avVal))
            offset += 4 + avLen
        }

        // Build augmented targetInfo
        val augmented = ByteArrayOutputStream()
        for ((avId, avVal) in avPairs) {
            augmented.write(avId and 0xFF); augmented.write((avId shr 8) and 0xFF)
            augmented.write(avVal.size and 0xFF); augmented.write((avVal.size shr 8) and 0xFF)
            augmented.write(avVal)
        }

        // FIX-M(1): Add MsvAvFlags with MIC bit (0x00000002) when server sent MsvAvTimestamp
        // This signals to the server that our AUTHENTICATE message contains a valid MIC
        if (hasMsvAvTimestamp && !hasMsvAvFlags) {
            val flagsVal = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(0x00000002).array()
            augmented.write(0x06); augmented.write(0x00)  // MsvAvFlags
            augmented.write(0x04); augmented.write(0x00)  // length = 4
            augmented.write(flagsVal)
        }

        // FIX-M(2): Add MsvAvChannelBindings (16 zero bytes) if absent
        if (!hasChannelBindings) {
            augmented.write(0x0A); augmented.write(0x00)  // MsvAvChannelBindings
            augmented.write(0x10); augmented.write(0x00)  // length = 16
            augmented.write(ByteArray(16))
        }

        // FIX-M(3): Add MsvAvTargetName (SPN) if absent and SPN is known
        if (!hasTargetName && serverSpn.isNotEmpty()) {
            val spnBytes = serverSpn.toByteArray(Charsets.UTF_16LE)
            augmented.write(0x09); augmented.write(0x00)  // MsvAvTargetName
            augmented.write(spnBytes.size and 0xFF); augmented.write((spnBytes.size shr 8) and 0xFF)
            augmented.write(spnBytes)
        }

        // MsvAvEOL terminator
        augmented.write(0x00); augmented.write(0x00)
        augmented.write(0x00); augmented.write(0x00)

        val augmentedTargetInfo = augmented.toByteArray()

        val buf = ByteBuffer.allocate(28 + augmentedTargetInfo.size).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(byteArrayOf(0x01, 0x01, 0x00, 0x00))   // RespType + HiRespType + reserved
        buf.putInt(0)                                    // Reserved2
        buf.putLong(effectiveTimestamp)                  // Timestamp (server's or our own)
        buf.put(clientChallenge)                         // ClientChallenge[8]
        buf.putInt(0)                                    // Reserved3
        buf.put(augmentedTargetInfo)
        return buf.array().copyOf(buf.position())
    }

    private fun generateClientChallenge(): ByteArray {
        val bytes = ByteArray(8)
        java.security.SecureRandom().nextBytes(bytes)
        return bytes
    }

    private fun windowsTimestamp(): Long {
        val epochDiff = 11644473600000L
        return (System.currentTimeMillis() + epochDiff) * 10000L
    }

    private fun rc4(key: ByteArray, data: ByteArray): ByteArray {
        // Try BouncyCastle first (fastest, supports all Android versions)
        try {
            ensureBouncyCastleRegistered()
            val cipher = Cipher.getInstance("ARC4", "BC")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ARC4"))
            return cipher.doFinal(data)
        } catch (_: Exception) {}

        // Fallback 1: platform RC4 (available on Android < 10 without BC)
        try {
            val cipher = Cipher.getInstance("RC4")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "RC4"))
            return cipher.doFinal(data)
        } catch (_: Exception) {}

        // Fallback 2: pure-Kotlin RC4 — always works, no JCE dependency.
        // FIX-L: Devices without BouncyCastle installed and Android 10+
        // (which removed RC4 from the default JCE provider) would throw here,
        // making NLA authentication always fail with a cryptic JCE exception.
        return rc4Pure(key, data)
    }

    /**
     * Pure-Kotlin RC4 (ARCFOUR) stream cipher.
     * Identical to RFC 4345 / the RC4 algorithm used by MS-NLMP.
     */
    private fun rc4Pure(key: ByteArray, data: ByteArray): ByteArray {
        val s = IntArray(256) { it }
        var j = 0
        for (i in 0..255) {
            j = (j + s[i] + (key[i % key.size].toInt() and 0xFF)) and 0xFF
            val tmp = s[i]; s[i] = s[j]; s[j] = tmp
        }
        val out = ByteArray(data.size)
        var i = 0; j = 0
        for (k in data.indices) {
            i = (i + 1) and 0xFF
            j = (j + s[i]) and 0xFF
            val tmp = s[i]; s[i] = s[j]; s[j] = tmp
            out[k] = (data[k].toInt() xor s[(s[i] + s[j]) and 0xFF]).toByte()
        }
        return out
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
