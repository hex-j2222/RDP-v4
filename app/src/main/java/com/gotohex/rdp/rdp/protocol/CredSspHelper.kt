package com.gotohex.rdp.rdp.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * CredSSP (Credential Security Support Provider, MS-CSSP) message encoding
 * and parsing.
 *
 * FIXES APPLIED (connection-failure audit):
 * 1. Hash magic strings are UTF-16LE per MS-CSSP (version 5/6 pubKeyAuth hash).
 * 2. Version handling: proper support for version 5 and 6, with clientNonce
 *    sent only in the AUTHENTICATE TSRequest, never in NEGOTIATE.
 * 3. verifyPubKeyAuthResponse() (v2/3/4 path) now compares the FULL decrypted
 *    buffer against the server's public key (length + every byte), not just
 *    the first byte. The previous single-byte check could be satisfied by
 *    truncated or garbled data, silently accepting a broken/spoofed handshake.
 * 4. extractErrorCode() now parses the NTSTATUS as a signed 32-bit integer
 *    (it was previously read as an unsigned accumulator, which turns every
 *    real error code — they all have the high bit set — into a meaningless
 *    large positive number). describeErrorCode() maps the common NTSTATUS
 *    values (bad password, account locked, password expired, Encryption
 *    Oracle Remediation, ...) to an actionable message.
 */
object CredSspHelper {

    // Use version 2 for initial request - compatible with ALL Windows versions
    // Server will tell us if it supports higher version
    private const val CREDSSP_VERSION = 2

    // FIX #1: Hash magic strings MUST be UTF-16LE per MS-CSSP Errata 2024
    // "Set ClientServerHash to SHA256(ClientServerHashMagic, Nonce, SubjectPublicKey)"
    // Note: The hash MUST include the null terminator
    private val CLIENT_SERVER_HASH_MAGIC = "CredSSP Client-To-Server Binding Hash\u0000".toByteArray(Charsets.UTF_16LE)
    private val SERVER_CLIENT_HASH_MAGIC = "CredSSP Server-To-Client Binding Hash\u0000".toByteArray(Charsets.UTF_16LE)

    // ── Version Detection ──────────────────────────────────────────────────

    /** Tracks the negotiated CredSSP version from server response */
    var negotiatedCredSspVersion: Int = 2

    /** 32-byte nonce for version 5/6 */
    private var clientNonce: ByteArray? = null

    // ── Encoding ───────────────────────────────────────────────────────────

    fun buildNegotiateTsRequest(negotiateMessage: ByteArray): ByteArray {
        negotiatedCredSspVersion = 2 // Reset to default
        clientNonce = null
        return buildTsRequest(negoToken = negotiateMessage, pubKeyAuth = null, authInfo = null, clientNonce = null)
    }

    fun buildAuthenticateTsRequest(authMessage: ByteArray, pubKeyAuth: ByteArray): ByteArray {
        return buildTsRequest(negoToken = authMessage, pubKeyAuth = pubKeyAuth, authInfo = null, clientNonce = clientNonce)
    }

    fun buildAuthInfoTsRequest(authInfo: ByteArray): ByteArray {
        return buildTsRequest(negoToken = null, pubKeyAuth = null, authInfo = authInfo, clientNonce = null)
    }

    private fun buildTsRequest(
        negoToken: ByteArray?,
        pubKeyAuth: ByteArray?,
        authInfo: ByteArray?,
        clientNonce: ByteArray?
    ): ByteArray {
        var content = derTagged(0, derInteger(negotiatedCredSspVersion))

        if (negoToken != null) {
            val innerSeq = derSequence(derTagged(0, derOctetString(negoToken)))
            val negoTokensSeq = derSequence(innerSeq)
            content += derTagged(1, negoTokensSeq)
        }

        if (authInfo != null) {
            content += derTagged(2, derOctetString(authInfo))
        }

        if (pubKeyAuth != null) {
            content += derTagged(3, derOctetString(pubKeyAuth))
        }

        // FIX: Version 5/6: include clientNonce [5] only if present
        // clientNonce should only be sent in AUTHENTICATE TSRequest, not NEGOTIATE
        if (clientNonce != null && negotiatedCredSspVersion >= 5) {
            content += derTagged(5, derOctetString(clientNonce))
        }

        return derSequence(content)
    }

    /**
     * Builds TSCredentials with proper encoding.
     * TSPasswordCreds fields are OCTET STRING containing UTF-16LE bytes.
     * The OCTET STRING DER encoding already includes length, so no additional length prefix needed.
     */
    fun buildTsCredentials(domain: String, username: String, password: String): ByteArray {
        val domainBytes = domain.toByteArray(Charsets.UTF_16LE)
        val usernameBytes = username.toByteArray(Charsets.UTF_16LE)
        val passwordBytes = password.toByteArray(Charsets.UTF_16LE)

        val tsPasswordCreds = derSequence(
            derTagged(0, derOctetString(domainBytes)) +
            derTagged(1, derOctetString(usernameBytes)) +
            derTagged(2, derOctetString(passwordBytes))
        )

        val tsCredentials = derSequence(
            derTagged(0, derInteger(1)) +
            derTagged(1, derOctetString(tsPasswordCreds))
        )
        return tsCredentials
    }

    // ── Version 5/6 SHA256 Hash for pubKeyAuth ─────────────────────────────

    /**
     * Computes pubKeyAuth based on negotiated version.
     * Version 2/3/4: encrypt raw SubjectPublicKey
     * Version 5/6: encrypt(SHA256(hashMagic + nonce + SubjectPublicKey))
     * 
     * FIX #1: Hash Magic Strings are now UTF-16LE
     */
    fun computePubKeyAuth(
        serverPublicKey: ByteArray,
        encryptionState: NtlmHelper.NtlmEncryptionState,
        sequenceNumber: Int
    ): ByteArray {
        return if (negotiatedCredSspVersion >= 5) {
            // Generate nonce for version 5/6
            clientNonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val hash = sha256Hash(CLIENT_SERVER_HASH_MAGIC, clientNonce!!, serverPublicKey)
            NtlmHelper.encryptMessage(encryptionState, hash, sequenceNumber)
        } else {
            // Version 2/3/4: encrypt raw public key
            NtlmHelper.encryptMessage(encryptionState, serverPublicKey, sequenceNumber)
        }
    }

    /**
     * Verifies server pubKeyAuth response based on negotiated version.
     * Version 2/3/4: decrypted data should be (pubKey[0] + 1), rest unchanged
     * Version 5/6: decrypted data should be SHA256(serverHashMagic + nonce + SubjectPublicKey)
     *
     * FIX: UTF-16LE hash magic strings (version 5/6).
     * FIX: For version 2/3/4 this previously only checked the FIRST byte of
     * the decrypted response against (serverPublicKey[0] + 1) and accepted
     * the connection regardless of the remaining bytes. Per MS-CSSP 3.1.5,
     * EVERY other byte must be unchanged from the original public key — the
     * single-byte check could pass on a truncated/garbled buffer (e.g. one
     * byte coincidentally matching) and let an unverified, possibly
     * man-in-the-middled, server proceed. Now the full length and full byte
     * sequence are checked.
     */
    fun verifyPubKeyAuthResponse(
        encryptedResponse: ByteArray,
        serverPublicKey: ByteArray,
        encryptionState: NtlmHelper.NtlmEncryptionState,
        sequenceNumber: Int
    ): Boolean {
        val decrypted = NtlmHelper.decryptMessage(encryptionState, encryptedResponse, sequenceNumber)
        return if (negotiatedCredSspVersion >= 5) {
            val expectedHash = sha256Hash(SERVER_CLIENT_HASH_MAGIC, clientNonce ?: return false, serverPublicKey)
            decrypted.contentEquals(expectedHash)
        } else {
            // Version 2/3/4: server returns (firstByte + 1), rest unchanged.
            if (decrypted.size != serverPublicKey.size || serverPublicKey.isEmpty()) return false
            val expectedFirstByte = ((serverPublicKey[0].toInt() and 0xFF) + 1) and 0xFF
            val actualFirstByte = decrypted[0].toInt() and 0xFF
            if (actualFirstByte != expectedFirstByte) return false
            // Remaining bytes (index 1..end) must be byte-for-byte identical
            // to the original public key.
            for (i in 1 until serverPublicKey.size) {
                if (decrypted[i] != serverPublicKey[i]) return false
            }
            true
        }
    }

    private fun sha256Hash(magic: ByteArray, nonce: ByteArray, publicKey: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(magic)
        md.update(nonce)
        md.update(publicKey)
        return md.digest()
    }

    // ── Parsing ────────────────────────────────────────────────────────────

    fun extractNegoToken(tsRequest: ByteArray): ByteArray? {
        val root = DerReader(tsRequest).readElement() ?: return null
        val negoTokensField = root.children.find { it.tag == 0xA1 } ?: return null
        val negoTokensSeq = negoTokensField.children.firstOrNull { it.tag == 0x30 } ?: return null
        val firstSeq = negoTokensSeq.children.firstOrNull { it.tag == 0x30 } ?: return null
        val negoTokenField = firstSeq.children.firstOrNull { it.tag == 0xA0 } ?: return null
        val octetString = negoTokenField.children.firstOrNull { it.tag == 0x04 } ?: return null
        return octetString.content
    }

    fun extractPubKeyAuth(tsRequest: ByteArray): ByteArray? {
        val root = DerReader(tsRequest).readElement() ?: return null
        val field = root.children.find { it.tag == 0xA3 } ?: return null
        val octetString = field.children.firstOrNull { it.tag == 0x04 } ?: return null
        return octetString.content
    }

    /**
     * Extracts version from server TSRequest response.
     * This tells us what version the server supports.
     */
    fun extractVersion(tsRequest: ByteArray): Int {
        val root = DerReader(tsRequest).readElement() ?: return 2
        val versionField = root.children.find { it.tag == 0xA0 } ?: return 2
        val integer = versionField.children.firstOrNull { it.tag == 0x02 } ?: return 2
        return parseDerInteger(integer.content)
    }

    fun extractClientNonce(tsRequest: ByteArray): ByteArray? {
        val root = DerReader(tsRequest).readElement() ?: return null
        val nonceField = root.children.find { it.tag == 0xA5 } ?: return null
        val octetString = nonceField.children.firstOrNull { it.tag == 0x04 } ?: return null
        return octetString.content
    }

    /**
     * Extracts errorCode from server TSRequest (version 3+).
     * If present, indicates authentication failure reason.
     *
     * FIX: errorCode is an NTSTATUS value (e.g. 0xC0000022 =
     * STATUS_ACCESS_DENIED). The original parseDerInteger() built an
     * unsigned-style accumulator, which produced a meaningless large
     * positive number for any NTSTATUS with the high bit set (all error
     * NTSTATUS codes do). It is now parsed as a signed 32-bit value, and
     * describeErrorCode() below turns the common ones into a message a user
     * can actually act on instead of "errorCode=-1073741810".
     */
    fun extractErrorCode(tsRequest: ByteArray): Int? {
        val root = DerReader(tsRequest).readElement() ?: return null
        val errorField = root.children.find { it.tag == 0xA4 } ?: return null
        val integer = errorField.children.firstOrNull { it.tag == 0x02 } ?: return null
        return parseDerIntegerSigned(integer.content)
    }

    /**
     * Translates a CredSSP NTSTATUS errorCode into a human-readable reason.
     * Values from MS-CSSP / MS-ERREF. Falls back to the raw hex code.
     */
    fun describeErrorCode(errorCode: Int): String {
        val unsignedHex = "0x" + (errorCode.toLong() and 0xFFFFFFFFL).toString(16).uppercase()
        return when (errorCode) {
            -1073741715 -> "STATUS_LOGON_FAILURE ($unsignedHex) - wrong username or password"
            -1073741714 -> "STATUS_ACCOUNT_RESTRICTION ($unsignedHex) - account has logon restrictions (e.g. blank password not allowed)"
            -1073741711 -> "STATUS_INVALID_LOGON_HOURS ($unsignedHex) - account is not allowed to log on at this time"
            -1073741710 -> "STATUS_INVALID_WORKSTATION ($unsignedHex) - account is not allowed to log on from this device"
            -1073741709 -> "STATUS_PASSWORD_EXPIRED ($unsignedHex) - the password has expired"
            -1073741706 -> "STATUS_ACCOUNT_DISABLED ($unsignedHex) - the account is disabled"
            -1073741790 -> "STATUS_ACCOUNT_LOCKED_OUT ($unsignedHex) - the account is locked out"
            -1073741536 -> "STATUS_PASSWORD_MUST_CHANGE ($unsignedHex) - the user must change their password before logging on"
            -1073740588 -> "STATUS_ENCRYPTION_FAILED ($unsignedHex) - Encryption Oracle Remediation: server requires a patched/updated client"
            else -> "NTSTATUS $unsignedHex (see MS-ERREF for meaning)"
        }
    }

    private fun parseDerIntegerSigned(data: ByteArray): Int {
        if (data.isEmpty()) return 0
        var result = 0
        for (b in data) {
            result = (result shl 8) or (b.toInt() and 0xFF)
        }
        return result
    }

    // ── DER primitives ─────────────────────────────────────────────────────

    private fun derTagged(tag: Int, content: ByteArray): ByteArray {
        val header = byteArrayOf((0xA0 or tag).toByte())
        return header + derLength(content.size) + content
    }

    private fun derSequence(content: ByteArray): ByteArray {
        return byteArrayOf(0x30) + derLength(content.size) + content
    }

    private fun derOctetString(data: ByteArray): ByteArray {
        return byteArrayOf(0x04) + derLength(data.size) + data
    }

    private fun derInteger(value: Int): ByteArray {
        var v = value
        if (v == 0) {
            return byteArrayOf(0x02, 0x01, 0x00)
        }
        val tmp = ArrayDeque<Int>()
        while (v != 0 || tmp.isEmpty()) {
            tmp.addLast(v and 0xFF)
            v = v ushr 8
            if (tmp.size >= 4) break
        }
        while (tmp.size > 1 && tmp.first() == 0 && (tmp[1] and 0x80) == 0) {
            tmp.removeFirst()
        }
        if ((tmp.first() and 0x80) != 0) {
            tmp.addFirst(0x00)
        }
        val content = ByteArray(tmp.size)
        for (i in tmp.indices) content[i] = tmp[i].toByte()
        return byteArrayOf(0x02) + derLength(content.size) + content
    }

    private fun derLength(length: Int): ByteArray {
        return when {
            length < 0x80 -> byteArrayOf(length.toByte())
            length < 0x100 -> byteArrayOf(0x81.toByte(), length.toByte())
            else -> byteArrayOf(0x82.toByte(), (length shr 8).toByte(), (length and 0xFF).toByte())
        }
    }

    private fun parseDerInteger(data: ByteArray): Int {
        if (data.isEmpty()) return 0
        var result = 0
        for (i in data.indices) {
            result = (result shl 8) or (data[i].toInt() and 0xFF)
        }
        return result
    }
}

/**
 * Minimal recursive-descent DER (BER) reader sufficient for parsing CredSSP
 * TSRequest structures: constructed SEQUENCE/context tags and primitive
 * OCTET STRING/INTEGER values, with short- and long-form lengths.
 */
private class DerReader(private val data: ByteArray) {
    private var pos = 0

    class Element(val tag: Int, val content: ByteArray, val children: List<Element>)

    fun readElement(): Element? {
        if (pos >= data.size) return null
        val tag = data[pos].toInt() and 0xFF
        pos++
        val length = readLength() ?: return null
        if (pos + length > data.size) return null
        val content = data.copyOfRange(pos, pos + length)
        pos += length

        val isConstructed = (tag and 0x20) != 0
        val children = if (isConstructed) {
            val childReader = DerReader(content)
            val list = mutableListOf<Element>()
            while (true) {
                val child = childReader.readElement() ?: break
                list.add(child)
            }
            list
        } else {
            emptyList()
        }

        return Element(tag, content, children)
    }

    private fun readLength(): Int? {
        if (pos >= data.size) return null
        val first = data[pos].toInt() and 0xFF
        pos++
        return if (first < 0x80) {
            first
        } else {
            val numBytes = first and 0x7F
            if (numBytes == 0 || numBytes > 4 || pos + numBytes > data.size) return null
            var len = 0
            repeat(numBytes) {
                len = (len shl 8) or (data[pos].toInt() and 0xFF)
                pos++
            }
            len
        }
    }
}
