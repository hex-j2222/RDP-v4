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
 * COMPREHENSIVE FIX for maximum compatibility:
 * - Windows XP/7/2008/2012: Version 2 (raw public key encryption)
 * - Windows 10/11/Server 2016/2019/2022: Version 2, 5, or 6 (SHA256 hash)
 * - xrdp/Linux: TLS only (no NLA)
 *
 * Strategy:
 * 1. Start with CredSSP version 2 (most compatible)
 * 2. If server responds with version 5/6, adapt to SHA256 hash mode
 * 3. Support both raw public key (v2) and SHA256 hash (v5/6) for pubKeyAuth
 */
object CredSspHelper {

    // Use version 2 for initial request - compatible with ALL Windows versions
    // Server will tell us if it supports higher version
    private const val CREDSSP_VERSION = 2

    // Version 5/6 hash magic strings (UTF-8 with null terminator as per MS-CSSP)
    private val CLIENT_SERVER_HASH_MAGIC = "CredSSP Client-To-Server Binding Hash\u0000".toByteArray(Charsets.UTF_8)
    private val SERVER_CLIENT_HASH_MAGIC = "CredSSP Server-To-Client Binding Hash\u0000".toByteArray(Charsets.UTF_8)

    // ── Version Detection ──────────────────────────────────────────────────

    /** Tracks the negotiated CredSSP version from server response */
    var negotiatedCredSspVersion: Int = 2
        private set

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

        // Version 5/6: include clientNonce [5] if present
        if (clientNonce != null) {
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
            // Version 2/3/4: server returns (firstByte + 1), rest unchanged
            if (decrypted.isEmpty() || serverPublicKey.isEmpty()) return false
            val expectedFirstByte = ((serverPublicKey[0].toInt() and 0xFF) + 1) and 0xFF
            val actualFirstByte = decrypted[0].toInt() and 0xFF
            actualFirstByte == expectedFirstByte
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
     */
    fun extractErrorCode(tsRequest: ByteArray): Int? {
        val root = DerReader(tsRequest).readElement() ?: return null
        val errorField = root.children.find { it.tag == 0xA4 } ?: return null
        val integer = errorField.children.firstOrNull { it.tag == 0x02 } ?: return null
        return parseDerInteger(integer.content)
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
            tmp.addFirst(v and 0xFF)
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
