package com.gotohex.rdp.rdp.protocol

/**
 * CredSSP (Credential Security Support Provider, MS-CSSP) message encoding
 * and parsing.
 *
 * TSRequest ::= SEQUENCE {
 *   version    [0] INTEGER,
 *   negoTokens [1] SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING } OPTIONAL,
 *   authInfo   [2] OCTET STRING OPTIONAL,
 *   pubKeyAuth [3] OCTET STRING OPTIONAL,
 * }
 *
 * TSCredentials ::= SEQUENCE {
 *   credType    [0] INTEGER,
 *   credentials [1] OCTET STRING, -- DER-encoded TSPasswordCreds
 * }
 *
 * TSPasswordCreds ::= SEQUENCE {
 *   domainName [0] OCTET STRING,
 *   userName   [1] OCTET STRING,
 *   password   [2] OCTET STRING,
 * }
 *
 * The previous implementation used a custom non-standard 4-byte length
 * prefix and a naive "scan for the first 0x04 tag" parser, which does not
 * interoperate with any real CredSSP server and never sent pubKeyAuth /
 * authInfo at all (issue #12).
 */
object CredSspHelper {

    private const val CREDSSP_VERSION = 6

    // ── Encoding ───────────────────────────────────────────────────────────

    /** TSRequest containing only negoTokens = [ NEGOTIATE ]. */
    fun buildNegotiateTsRequest(negotiateMessage: ByteArray): ByteArray =
        buildTsRequest(negoToken = negotiateMessage, pubKeyAuth = null, authInfo = null)

    /** TSRequest containing negoTokens = [ AUTHENTICATE ] and pubKeyAuth. */
    fun buildAuthenticateTsRequest(authMessage: ByteArray, pubKeyAuth: ByteArray): ByteArray =
        buildTsRequest(negoToken = authMessage, pubKeyAuth = pubKeyAuth, authInfo = null)

    /** TSRequest containing only authInfo (encrypted TSCredentials). */
    fun buildAuthInfoTsRequest(authInfo: ByteArray): ByteArray =
        buildTsRequest(negoToken = null, pubKeyAuth = null, authInfo = authInfo)

    private fun buildTsRequest(negoToken: ByteArray?, pubKeyAuth: ByteArray?, authInfo: ByteArray?): ByteArray {
        var content = derTagged(0, derInteger(CREDSSP_VERSION))

        if (negoToken != null) {
            // negoTokens [1] SEQUENCE OF SEQUENCE { [0] OCTET STRING negoToken }
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

        return derSequence(content)
    }

    /**
     * Builds a (plaintext) TSCredentials structure containing TSPasswordCreds
     * for [domain]/[username]/[password]. The caller is responsible for
     * encrypting this with [NtlmHelper.encryptMessage] before sending it as
     * authInfo.
     */
    fun buildTsCredentials(domain: String, username: String, password: String): ByteArray {
        val tsPasswordCreds = derSequence(
            derTagged(0, derOctetString(domain.toByteArray(Charsets.UTF_16LE))) +
            derTagged(1, derOctetString(username.toByteArray(Charsets.UTF_16LE))) +
            derTagged(2, derOctetString(password.toByteArray(Charsets.UTF_16LE)))
        )
        // TSCredentials: credType [0] INTEGER (1 = password), credentials [1] OCTET STRING
        val tsCredentials = derSequence(
            derTagged(0, derInteger(1)) +
            derTagged(1, derOctetString(tsPasswordCreds))
        )
        return tsCredentials
    }

    // ── Parsing ────────────────────────────────────────────────────────────

    /**
     * Extracts the single NTLM token from `negoTokens[0].negoToken` of a
     * TSRequest (used to read the server's CHALLENGE message).
     */
    fun extractNegoToken(tsRequest: ByteArray): ByteArray? {
        val root = DerReader(tsRequest).readElement() ?: return null
        // root: SEQUENCE -> find context tag [1] (negoTokens)
        val negoTokensField = root.children.find { it.tag == 0xA1 } ?: return null
        val negoTokensSeq = negoTokensField.children.firstOrNull { it.tag == 0x30 } ?: return null
        val firstSeq = negoTokensSeq.children.firstOrNull { it.tag == 0x30 } ?: return null
        val negoTokenField = firstSeq.children.firstOrNull { it.tag == 0xA0 } ?: return null
        val octetString = negoTokenField.children.firstOrNull { it.tag == 0x04 } ?: return null
        return octetString.content
    }

    /** Extracts `pubKeyAuth` (context tag [3]) from a TSRequest. */
    fun extractPubKeyAuth(tsRequest: ByteArray): ByteArray? {
        val root = DerReader(tsRequest).readElement() ?: return null
        val field = root.children.find { it.tag == 0xA3 } ?: return null
        val octetString = field.children.firstOrNull { it.tag == 0x04 } ?: return null
        return octetString.content
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
        // Minimal-length signed big-endian encoding
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
        // Trim leading zero bytes but keep the sign bit correct for positive values
        while (tmp.size > 1 && tmp.first() == 0 && (tmp[1] and 0x80) == 0) {
            tmp.removeFirst()
        }
        // Ensure non-negative values whose high bit is set get a leading 0x00
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

        // Constructed types have bit 0x20 set in the tag (SEQUENCE = 0x30,
        // context-specific constructed = 0xA0..0xBF).
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
