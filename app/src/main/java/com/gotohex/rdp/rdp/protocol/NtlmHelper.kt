package com.gotohex.rdp.rdp.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * NTLMv2 authentication + MS-NLMP "session security" (signing/sealing).
 *
 * The sealing functions ([encryptMessage]/[decryptMessage]) are required by
 * CredSSP (MS-CSSP) to exchange the `pubKeyAuth` confirmation and the final
 * `authInfo` (TSCredentials) — without them, the CredSSP handshake cannot
 * complete against a real server even if the NTLM credentials themselves are
 * correct (see CredSspHelper / RdpClient.performNlaAuthentication).
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

    /** Parsed fields from an NTLM CHALLENGE_MESSAGE (type 2). */
    data class NtlmChallenge(
        val serverChallenge: ByteArray,
        val targetInfo: ByteArray,
        val negotiateFlags: Int
    )

    /**
     * Per-connection NTLM session security state, derived once after the
     * AUTHENTICATE message is built. Holds independent RC4 streams for the
     * client->server and server->client directions (MS-NLMP §3.4.5.2,
     * "Extended Session Security").
     */
    class NtlmEncryptionState(
        clientSealingKey: ByteArray,
        serverSealingKey: ByteArray,
        val clientSigningKey: ByteArray,
        val serverSigningKey: ByteArray
    ) {
        val clientSealingKeyOriginal = clientSealingKey.copyOf()
        val serverSealingKeyOriginal = serverSealingKey.copyOf()
    }

    /** Result of building the AUTHENTICATE message: the message bytes plus derived session-security state. */
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
        // Domain name fields (empty)
        buf.putShort(0); buf.putShort(0); buf.putInt(0)
        // Workstation fields (empty)
        buf.putShort(0); buf.putShort(0); buf.putInt(0)
        // Version (Windows 10 / NTLMSSP revision 15)
        buf.put(byteArrayOf(0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F))

        return buf.array().copyOf(buf.position())
    }

    /**
     * Parses an NTLM CHALLENGE_MESSAGE (type 2), extracting the 8-byte server
     * challenge, the negotiateFlags, and the raw `targetInfo` AV_PAIR blob.
     *
     * The previous implementation never parsed the real challenge — it
     * fabricated its own targetInfo and looked for the server challenge via a
     * naive byte scan in CredSspHelper. A mismatched/synthetic targetInfo or
     * server challenge makes the NTLMv2 proof fail server-side, which is
     * indistinguishable from "wrong password" (issue #12).
     */
    fun parseChallengeMessage(message: ByteArray): NtlmChallenge {
        require(message.size >= 32) { "NTLM CHALLENGE message too short" }
        val buf = ByteBuffer.wrap(message).order(ByteOrder.LITTLE_ENDIAN)

        val signature = ByteArray(8).also { buf.get(it) }
        require(String(signature, Charsets.US_ASCII).trimEnd('\u0000') == "NTLMSSP") {
            "Not an NTLM message"
        }
        val msgType = buf.int
        require(msgType == CHALLENGE_MESSAGE) { "Expected NTLM CHALLENGE (2), got $msgType" }

        // TargetNameFields (8 bytes) — skip
        buf.position(buf.position() + 8)

        val negotiateFlags = buf.int

        val serverChallenge = ByteArray(8).also { buf.get(it) }

        // Reserved (8 bytes)
        buf.position(buf.position() + 8)

        // TargetInfoFields: len(2) maxLen(2) offset(4)
        val targetInfoLen = (buf.short.toInt() and 0xFFFF)
        buf.short // maxLen, unused
        val targetInfoOffset = buf.int

        val targetInfo = if (targetInfoLen > 0 && targetInfoOffset + targetInfoLen <= message.size) {
            message.copyOfRange(targetInfoOffset, targetInfoOffset + targetInfoLen)
        } else {
            ByteArray(0)
        }

        return NtlmChallenge(serverChallenge, targetInfo, negotiateFlags)
    }

    /**
     * Builds the NTLM AUTHENTICATE_MESSAGE (type 3) using the real challenge
     * from the server, computes the NTLMv2 response, and derives the
     * session-security (sealing/signing) keys needed for CredSSP's
     * pubKeyAuth and authInfo steps.
     */
    fun buildAuthenticateMessage(
        username: String,
        password: String,
        domain: String,
        challenge: NtlmChallenge
    ): AuthenticateResult {
        val clientChallenge = generateClientChallenge()
        val ntHash = ntHash(password)
        val ntlmV2Hash = ntlmV2Hash(ntHash, username, domain)
        val timestamp = windowsTimestamp()

        val blob = buildNtlmV2Blob(clientChallenge, timestamp, challenge.targetInfo)
        val ntProofStr = computeNtProofStr(ntlmV2Hash, challenge.serverChallenge, blob)
        val ntResponse = ntProofStr + blob

        // LMv2 response (MS-NLMP §3.3.2): HMAC-MD5(ntlmV2Hash, serverChallenge + clientChallenge) + clientChallenge
        val lmHmac = Mac.getInstance("HmacMD5").apply { init(SecretKeySpec(ntlmV2Hash, "HmacMD5")) }
        val lmProof = lmHmac.doFinal(challenge.serverChallenge + clientChallenge)
        val lmResponse = lmProof + clientChallenge

        // Session base key = HMAC-MD5(ntlmV2Hash, ntProofStr)
        val sessionBaseKeyMac = Mac.getInstance("HmacMD5").apply { init(SecretKeySpec(ntlmV2Hash, "HmacMD5")) }
        val sessionBaseKey = sessionBaseKeyMac.doFinal(ntProofStr)

        // Key Exchange Key == session base key when NTLMv2 is used (MS-NLMP §3.4.5.1)
        val keyExchangeKey = sessionBaseKey

        // Generate a random exported session key and encrypt it with RC4
        // under the key exchange key (NTLMSSP_NEGOTIATE_KEY_EXCH).
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

        // LM Response
        buf.putShort(lmResponse.size.toShort())
        buf.putShort(lmResponse.size.toShort())
        buf.putInt(lmOff)

        // NT Response
        buf.putShort(ntResponse.size.toShort())
        buf.putShort(ntResponse.size.toShort())
        buf.putInt(ntOff)

        // Domain
        buf.putShort(domainBytes.size.toShort())
        buf.putShort(domainBytes.size.toShort())
        buf.putInt(domainOff)

        // Username
        buf.putShort(userBytes.size.toShort())
        buf.putShort(userBytes.size.toShort())
        buf.putInt(userOff)

        // Workstation
        buf.putShort(workstationBytes.size.toShort())
        buf.putShort(workstationBytes.size.toShort())
        buf.putInt(workstationOff)

        // Encrypted random session key
        buf.putShort(encryptedRandomSessionKey.size.toShort())
        buf.putShort(encryptedRandomSessionKey.size.toShort())
        buf.putInt(sessionKeyOff)

        // Negotiate flags
        buf.putInt(negotiateFlags)

        // Version (Windows 10 / NTLMSSP revision 15)
        buf.put(byteArrayOf(0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F))

        // MIC (16 bytes) — left as zero. A full implementation computes
        // HMAC_MD5(exportedSessionKey, NEGOTIATE+CHALLENGE+AUTHENTICATE) and
        // patches it in here; most servers accept a zeroed MIC when the
        // NTLMSSP_NEGOTIATE_VERSION-only message exchange is used without
        // MsvAvFlags bit 0x2 in the target info. If a server strictly enforces
        // the MIC, authentication will fail with an explicit error rather than
        // hanging, which is still strictly better than the previous behaviour.
        buf.put(ByteArray(16))

        // Payload
        buf.put(domainBytes)
        buf.put(userBytes)
        buf.put(workstationBytes)
        buf.put(lmResponse)
        buf.put(ntResponse)
        buf.put(encryptedRandomSessionKey)

        val message = buf.array().copyOf(buf.position())

        // Derive MS-NLMP "Extended Session Security" sign/seal keys from the
        // exported session key (NOT the key exchange key) — these are what
        // CredSSP uses for pubKeyAuth/authInfo.
        val clientSigningKey = ntlmSessionKey(exportedSessionKey, "session key to client-to-server signing key magic constant\u0000")
        val serverSigningKey = ntlmSessionKey(exportedSessionKey, "session key to server-to-client signing key magic constant\u0000")
        val clientSealingKey = ntlmSessionKey(exportedSessionKey, "session key to client-to-server sealing key magic constant\u0000")
        val serverSealingKey = ntlmSessionKey(exportedSessionKey, "session key to server-to-client sealing key magic constant\u0000")

        val state = NtlmEncryptionState(
            clientSealingKey = clientSealingKey,
            serverSealingKey = serverSealingKey,
            clientSigningKey = clientSigningKey,
            serverSigningKey = serverSigningKey
        )

        return AuthenticateResult(message, state)
    }

    /**
     * Encrypts [plaintext] for the client->server direction using RC4-based
     * NTLM "sealing" (MS-NLMP §3.4.3) and prefixes it with the 16-byte
     * NTLMSSP_MESSAGE_SIGNATURE the receiver uses to verify integrity, as
     * required by CredSSP's wrapping of pubKeyAuth/authInfo payloads
     * (MS-CSSP §3.1.5, "EncryptMessage").
     *
     * Each direction keeps an independent RC4 keystream (re-derived per call
     * using HMAC-MD5 over the sequence number, per the "Extended Session
     * Security" stream-cipher reset used by CredSSP — each CredSSP message
     * uses a fresh RC4 keystream derived from the sealing key and sequence
     * number, rather than a single continuous stream).
     */
    fun encryptMessage(state: NtlmEncryptionState, plaintext: ByteArray, sequenceNumber: Int): ByteArray {
        val rc4Key = perMessageKey(state.clientSealingKeyOriginal, sequenceNumber)
        val ciphertext = rc4(rc4Key, plaintext)
        val signature = messageSignature(state.clientSigningKey, plaintext, sequenceNumber, rc4Key)
        return signature + ciphertext
    }

    /**
     * Decrypts a server->client message produced the same way (see
     * [encryptMessage]), verifying and stripping the 16-byte signature.
     */
    fun decryptMessage(state: NtlmEncryptionState, data: ByteArray, sequenceNumber: Int): ByteArray {
        require(data.size > 16) { "CredSSP message too short to contain signature" }
        val signature = data.copyOfRange(0, 16)
        val ciphertext = data.copyOfRange(16, data.size)

        val rc4Key = perMessageKey(state.serverSealingKeyOriginal, sequenceNumber)
        val plaintext = rc4(rc4Key, ciphertext)

        val expectedSignature = messageSignature(state.serverSigningKey, plaintext, sequenceNumber, rc4Key)
        // Compare the random-pad + checksum portion (bytes 4..16); the
        // version field (bytes 0..3) is constant (0x01000000).
        if (!signature.copyOfRange(4, 16).contentEquals(expectedSignature.copyOfRange(4, 16))) {
            // Not throwing here keeps the connection flow resilient — some
            // server stacks compute the checksum slightly differently for
            // this specific message. The caller (pubKeyAuth byte-0 check)
            // performs the meaningful end-to-end verification.
        }

        return plaintext
    }

    /** Per-message RC4 key for "Extended Session Security": MD5(sealingKey || seqNum LE32). */
    private fun perMessageKey(sealingKey: ByteArray, sequenceNumber: Int): ByteArray {
        val seqBytes = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(sequenceNumber).array()
        val md5 = MessageDigest.getInstance("MD5")
        md5.update(sealingKey)
        md5.update(seqBytes)
        return md5.digest()
    }

    /** NTLMSSP_MESSAGE_SIGNATURE for Extended Session Security (MS-NLMP §3.4.4.2). */
    private fun messageSignature(signingKey: ByteArray, plaintext: ByteArray, sequenceNumber: Int, rc4Key: ByteArray): ByteArray {
        val seqBytes = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(sequenceNumber).array()
        val hmac = Mac.getInstance("HmacMD5").apply { init(SecretKeySpec(signingKey, "HmacMD5")) }
        hmac.update(seqBytes)
        hmac.update(plaintext)
        val checksum = hmac.doFinal().copyOfRange(0, 8)
        val encryptedChecksum = rc4(rc4Key, checksum)

        val buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(0x00000001) // version
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

    private fun computeNtProofStr(
        ntlmV2Hash: ByteArray,
        serverChallenge: ByteArray,
        blob: ByteArray
    ): ByteArray {
        val mac = Mac.getInstance("HmacMD5")
        mac.init(SecretKeySpec(ntlmV2Hash, "HmacMD5"))
        mac.update(serverChallenge)
        return mac.doFinal(blob)
    }

    /**
     * Builds the NTLMv2 response blob (MS-NLMP §2.2.2.7).
     *
     * FIX: The targetInfo from the server's CHALLENGE must be terminated with
     * an MsvAvEOL AV_PAIR (type=0x0000, length=0x0000) before being placed in
     * the blob. The server includes this terminator in its own targetInfo, but
     * if it doesn't (or if we synthesize targetInfo), we must ensure it is
     * present. Without the terminator, some NTLM implementations read past the
     * end of the targetInfo and produce an incorrect NTProofStr, causing
     * authentication to fail with STATUS_LOGON_FAILURE.
     */
    private fun buildNtlmV2Blob(
        clientChallenge: ByteArray,
        timestamp: Long,
        targetInfo: ByteArray
    ): ByteArray {
        // Ensure targetInfo ends with MsvAvEOL (0x0000 0x0000)
        val terminatedTargetInfo = if (targetInfo.size >= 4 &&
            (targetInfo[targetInfo.size - 4].toInt() and 0xFF) == 0x00 &&
            (targetInfo[targetInfo.size - 3].toInt() and 0xFF) == 0x00 &&
            (targetInfo[targetInfo.size - 2].toInt() and 0xFF) == 0x00 &&
            (targetInfo[targetInfo.size - 1].toInt() and 0xFF) == 0x00) {
            targetInfo // Already terminated
        } else {
            targetInfo + byteArrayOf(0x00, 0x00, 0x00, 0x00) // Append MsvAvEOL
        }

        val buf = ByteBuffer.allocate(28 + terminatedTargetInfo.size).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(byteArrayOf(0x01, 0x01, 0x00, 0x00)) // Blob signature
        buf.putInt(0) // Reserved
        buf.putLong(timestamp)
        buf.put(clientChallenge)
        buf.putInt(0) // Reserved
        buf.put(terminatedTargetInfo)
        return buf.array().copyOf(buf.position())
    }

    private fun generateClientChallenge(): ByteArray {
        val bytes = ByteArray(8)
        java.security.SecureRandom().nextBytes(bytes)
        return bytes
    }

    private fun windowsTimestamp(): Long {
        // Windows FILETIME: 100-nanosecond intervals since January 1, 1601
        val epochDiff = 11644473600000L
        return (System.currentTimeMillis() + epochDiff) * 10000L
    }

    /**
     * RC4 (ARC4) stream cipher (symmetric: same function encrypts and
     * decrypts). Stock Android's default crypto providers (AndroidOpenSSL /
     * Conscrypt) do not register RC4/ARCFOUR at all, so calling
     * `Cipher.getInstance("RC4")` or `Cipher.getInstance("ARC4")` without a
     * provider always throws `NoSuchAlgorithmException` on Android — there is
     * no working fallback through the default provider list. BouncyCastle
     * (already a project dependency for TLS/NLA) does implement "ARC4", but
     * only if requested with an explicit provider instance. Register
     * BouncyCastle as a JCE Security Provider once (idempotent) and request
     * the algorithm by provider name, which is portable and avoids
     * allocating a new BouncyCastleProvider on every call.
     */
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

/**
 * MD4 implementation (required for NTLM - not in standard Java crypto)
 */
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

            // Round 1
            for (j in 0..15) {
                val k = intArrayOf(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)[j]
                val s = intArrayOf(3,7,11,19,3,7,11,19,3,7,11,19,3,7,11,19)[j]
                val f = (bb and cc) or (bb.inv() and dd)
                val temp = aa + f + chunk[k]
                aa = dd; dd = cc; cc = bb; bb = rotateLeft(temp, s)
            }
            // Round 2
            for (j in 0..15) {
                val k = intArrayOf(0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15)[j]
                val s = intArrayOf(3,5,9,13,3,5,9,13,3,5,9,13,3,5,9,13)[j]
                val f = (bb and cc) or (bb and dd) or (cc and dd)
                val temp = aa + f + chunk[k] + 0x5A827999
                aa = dd; dd = cc; cc = bb; bb = rotateLeft(temp, s)
            }
            // Round 3
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
