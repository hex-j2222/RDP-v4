package com.gotohex.rdp.rdp.protocol

import android.util.Log
import com.gotohex.rdp.data.model.RdpCredentials
import com.gotohex.rdp.data.model.RdpPerformance
import com.gotohex.rdp.rdp.codec.RdpBitmapDecoder
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.*
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate

/**
 * Pure Kotlin RDP Protocol Client
 * Maximum compatibility: Windows XP/7/8/8.1/10/11, Server 2008-2022, xrdp/Linux
 *
 * ═══════════════════════════════════════════════════════════════════
 * FIXES APPLIED IN THIS REVISION (v5 → v6):
 *
 * BUG-A  CRITICAL: writePerLength() used BER-style length encoding
 *         (0x81/0x82 prefix) instead of FreeRDP's PER encoding.
 *         PER length >= 128 must be: 0x80|(len>>8), len&0xFF  (always 2 bytes).
 *         BER-style 0x82 produces a 3-byte field where 2 bytes are expected,
 *         shifting every subsequent byte in the GCC Conference Create Request
 *         and causing the server to reject MCS Connect Initial.
 *         Fix: rewrite writePerLength() to match per_write_length() in FreeRDP.
 *
 * BUG-B  CRITICAL: Numeric string "1" in buildGccConferenceCreateRequest()
 *         was encoded as 0x01 0x31 (raw ASCII) instead of FreeRDP's
 *         per_write_numeric_string("1",1,1) output: 0x00 0x10
 *         (per_write_length(1-1=0)=0x00, then BCD nibble (1<<4)|0=0x10).
 *         Fix: write 0x00, 0x10 directly.
 *
 * BUG-C  CRITICAL: h221 key "Duca" was missing its PER octet-string
 *         length byte. per_write_octet_string(key,4,4) must first write
 *         per_write_length(4-4=0) = 0x00, then the 4 bytes.
 *         Without this 0x00, the parser sees "Duca" as the length field,
 *         misaligning everything that follows.
 *         Fix: write 0x00 before "Duca".
 *
 * BUG-D  CRITICAL: berIntegerMinimal() encoded values 32768-65535
 *         using 2 content bytes (e.g. 65535 → 02 02 FF FF).
 *         In BER, FF FF is the signed integer -1, not 65535.
 *         FreeRDP's ber_write_integer() uses threshold < 0x8000 for 2 bytes,
 *         so 65535 (≥ 0x8000) requires 3 bytes with a leading 0x00:
 *         02 03 00 FF FF = +65535.
 *         Fix: rewrite berIntegerMinimal() to match FreeRDP thresholds.
 *
 * BUG-E  MINOR: buildClientCoreData() used putShort(1) for
 *         desktopScaleFactor and deviceScaleFactor, which are UINT32 fields.
 *         Fix: changed to putInt(1).
 *
 * BUG-F  MINOR: readMcsConnectResponse() skipped ENUMERATED by pos+=2
 *         (tag+length only), missing the value byte. Changed to pos+=3.
 *
 * ═══════════════════════════════════════════════════════════════════
 */
class RdpClient(
    private val credentials: RdpCredentials,
    private val displayWidth: Int,
    private val displayHeight: Int,
    private val performanceMode: Int = RdpPerformance.AUTO,
    private val allowFallback: Boolean = true
) {
    companion object {
        private const val TAG = "RdpClient"
        const val RDP_DEFAULT_PORT = 3389
        const val CONNECT_TIMEOUT_MS = 10_000
        const val READ_TIMEOUT_MS = 30_000

        // Protocol flags
        const val PROTOCOL_RDP       = 0x00000000
        const val PROTOCOL_SSL       = 0x00000001
        const val PROTOCOL_HYBRID    = 0x00000002
        const val PROTOCOL_HYBRID_EX = 0x00000008

        // PDU type nibbles
        const val PDU_TYPE_DEMAND_ACTIVE  = 0x11
        const val PDU_TYPE_CONFIRM_ACTIVE = 0x13
        const val PDU_TYPE_DATA           = 0x17

        // PDU type 2
        const val PDUTYPE2_SYNCHRONIZE = 0x1F
        const val PDUTYPE2_CONTROL     = 0x14
        const val PDUTYPE2_FONTLIST    = 0x27
        const val PDUTYPE2_FONTMAP     = 0x28

        // Control actions
        const val CTRLACTION_REQUEST_CONTROL = 0x0001
        const val CTRLACTION_GRANTED_CONTROL = 0x0002
        const val CTRLACTION_DETACH          = 0x0003
        const val CTRLACTION_COOPERATE       = 0x0004

        // Security header flags
        const val SEC_INFO_PKT     = 0x0040
        const val SEC_IGNORE_SEQNO = 0x0004

        // TPKT
        const val TPKT_VERSION = 0x03

        // RDP versions
        const val RDP_VERSION_5_0  = 0x00080001
        const val RDP_VERSION_5_1  = 0x00080002
        const val RDP_VERSION_5_2  = 0x00080003
        const val RDP_VERSION_6_0  = 0x00080004
        const val RDP_VERSION_8_0  = 0x00080004
        const val RDP_VERSION_8_1  = 0x00080005
        const val RDP_VERSION_10_0 = 0x00080006
        const val RDP_VERSION_10_1 = 0x00080007
        const val RDP_VERSION_10_2 = 0x00080008
        const val RDP_VERSION_10_3 = 0x00080009
        const val RDP_VERSION_10_4 = 0x0008000A
        const val RDP_VERSION_10_5 = 0x0008000B
        const val RDP_VERSION_10_6 = 0x0008000C
        const val RDP_VERSION_10_7 = 0x0008000D

        // TS_INFO_PACKET flags
        const val INFO_MOUSE             = 0x00000001
        const val INFO_DISABLECTRLALTDEL = 0x00000002
        const val INFO_AUTOLOGON         = 0x00000008
        const val INFO_UNICODE           = 0x00000040
        const val INFO_MAXIMIZESHELL     = 0x00000020
        const val INFO_LOGON_NOTIFY      = 0x00001000
        const val INFO_ENABLEWINDOWSKEY  = 0x00000100
        const val INFO_NOAUDIOPLAYBACK   = 0x00080000

        // MCS channel IDs
        const val MCS_IO_CHANNEL_ID = 1003
        const val MCS_USER_BASE     = 1001

        // Color depth
        const val RNS_UD_COLOR_4BPP  = 0xCA00
        const val RNS_UD_COLOR_8BPP  = 0xCA01
        const val RNS_UD_COLOR_16BPP = 0xCA02
        const val RNS_UD_COLOR_24BPP = 0xCA03
        const val RNS_UD_COLOR_32BPP = 0xCA04
        const val RNS_UD_SAS_DEL     = 0xAA03

        // Encryption methods
        const val ENCRYPTION_METHOD_40BIT  = 0x00000001
        const val ENCRYPTION_METHOD_128BIT = 0x00000002
        const val ENCRYPTION_METHOD_56BIT  = 0x00000008
        const val ENCRYPTION_METHOD_FIPS   = 0x00000010
    }

    private var socket: Socket? = null
    private var inputStream: DataInputStream? = null
    private var outputStream: DataOutputStream? = null
    private var connected = false

    private val _sessionState = MutableStateFlow(RdpSessionState.DISCONNECTED)
    val sessionState: StateFlow<RdpSessionState> = _sessionState.asStateFlow()

    private val _frameUpdates = MutableSharedFlow<RdpFrameUpdate>(replay = 0, extraBufferCapacity = 10)
    val frameUpdates: SharedFlow<RdpFrameUpdate> = _frameUpdates.asSharedFlow()

    private val _error = MutableSharedFlow<String>(replay = 1)
    val error: SharedFlow<String> = _error.asSharedFlow()

    private var bandwidthDetector = BandwidthDetector()
    private var currentPerformance = performanceMode
    private var frameBuffer: Array<IntArray> = Array(maxOf(displayHeight, 1)) { IntArray(maxOf(displayWidth, 1)) }

    var latencyMs: Long = 0L
        private set
    var bandwidthKbps: Int = 0
        private set

    private val clientScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // ── Per-connection state ────────────────────────────────────────────────
    private var negotiatedNla       = false
    private var negotiatedHybridEx  = false
    private var serverSelectedProtocol: Int = 0
    private var negotiationPresent  = false
    private var forceStandardRdpSecurity = false
    private var sslSocketRef: javax.net.ssl.SSLSocket? = null
    private var mcsUserId: Int = 0
    private val ioChannelId: Int = MCS_IO_CHANNEL_ID
    private var serverShareId: Int = 0x000103EA

    // ── connect() ──────────────────────────────────────────────────────────

    suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        RdpLog.clear()
        try {
            _sessionState.emit(RdpSessionState.CONNECTING)
            RdpLog.d("Connecting to ${credentials.host}:${credentials.port}")

            val sock = Socket()
            sock.connect(InetSocketAddress(credentials.host, credentials.port), CONNECT_TIMEOUT_MS)
            sock.soTimeout = READ_TIMEOUT_MS
            sock.tcpNoDelay = true
            sock.setPerformancePreferences(0, 2, 1)

            socket = sock
            inputStream  = DataInputStream(BufferedInputStream(sock.getInputStream(), 65536))
            outputStream = DataOutputStream(BufferedOutputStream(sock.getOutputStream(), 65536))

            RdpLog.d("STEP 1: TCP connected")

            sendX224ConnectionRequest()
            RdpLog.d("STEP 2: X.224 CR sent")

            try {
                if (!readX224ConnectionConfirm()) throw RdpException("X.224 connection rejected")
            } catch (e: RdpNegotiationFailure) {
                if (e.code == 2 && allowFallback) {
                    RdpLog.w("Server rejected TLS/NLA — retrying with Standard RDP Security", e)
                    cleanup()
                    val fellBack = connectWithoutNla()
                    if (fellBack) {
                        connected = true
                        RdpLog.d("STEP 10b: Connected via Standard RDP Security fallback")
                        _sessionState.emit(RdpSessionState.CONNECTED)
                        clientScope.launch { receiveLoop() }
                        return@withContext true
                    }
                    val msg = "Server only supports Standard RDP Security, and the fallback also failed."
                    RdpLog.e(msg)
                    throw RdpException(msg)
                }
                throw e
            }
            RdpLog.d("STEP 3: X.224 CC (selected=0x${serverSelectedProtocol.toString(16)}, NLA=$negotiatedNla, HybridEX=$negotiatedHybridEx)")

            if (negotiationPresent && serverSelectedProtocol != PROTOCOL_RDP) {
                upgradeTls()
                RdpLog.d("STEP 4: TLS upgraded")
            } else {
                RdpLog.d("STEP 4: Skipped TLS (Standard RDP Security)")
            }

            if (negotiatedHybridEx) {
                if (!handleEarlyUserAuthResult()) throw RdpAuthException("Early user authorization failed")
                RdpLog.d("STEP 4a: Early User Auth Result handled")
            }

            if (negotiatedNla || negotiatedHybridEx) {
                try {
                    performNlaAuthentication()
                    RdpLog.d("STEP 5: NLA complete")
                } catch (e: Exception) {
                    RdpLog.w("NLA failed: ${e.message}", e)
                    val looksLikeBadCredentials = e is RdpAuthException &&
                        (e.message?.contains("LOGON_FAILURE") == true ||
                         e.message?.contains("ACCOUNT_DISABLED") == true ||
                         e.message?.contains("ACCOUNT_LOCKED_OUT") == true ||
                         e.message?.contains("PASSWORD_EXPIRED") == true)

                    if (allowFallback && !looksLikeBadCredentials) {
                        RdpLog.w("Attempting fallback to Standard RDP Security")
                        cleanup()
                        val fellBack = connectWithoutNla()
                        if (fellBack) {
                            connected = true
                            RdpLog.d("STEP 10b: Connected via Standard RDP Security fallback")
                            _sessionState.emit(RdpSessionState.CONNECTED)
                            clientScope.launch { receiveLoop() }
                            return@withContext true
                        }
                        val fallbackMsg = "NLA failed (${e.message}), and Standard RDP Security fallback also failed."
                        RdpLog.e(fallbackMsg)
                        throw RdpAuthException(fallbackMsg)
                    }
                    val msg = "NLA authentication failed (${e.message}). Try disabling 'Use NLA Authentication'."
                    RdpLog.e(msg)
                    throw RdpAuthException(msg)
                }
            }

            sendMcsConnectInitial()
            RdpLog.d("STEP 6: MCS Connect Initial sent")

            if (!readMcsConnectResponse()) throw RdpException("MCS connection failed")
            RdpLog.d("STEP 7: MCS Connect Response received")

            performMcsDomainSetup()
            RdpLog.d("STEP 8: MCS Domain Setup complete (userId=$mcsUserId)")

            sendClientInfoPdu()
            RdpLog.d("STEP 9: Client Info sent")

            handleDemandActivePdu()
            RdpLog.d("STEP 10: Demand Active + post-connection sequence complete")

            connected = true
            _sessionState.emit(RdpSessionState.CONNECTED)
            clientScope.launch { receiveLoop() }
            true

        } catch (e: RdpAuthException) {
            RdpLog.e("Auth failed: ${e.message}", e)
            _error.emit("Authentication failed: ${e.message}\n\n--- Full trace ---\n${RdpLog.dump()}")
            _sessionState.emit(RdpSessionState.AUTH_FAILED)
            cleanup()
            false
        } catch (e: Exception) {
            RdpLog.e("Connection failed: ${e.message}", e)
            _error.emit("Connection failed: ${e.message ?: "Unknown error"}\n\n--- Full trace ---\n${RdpLog.dump()}")
            _sessionState.emit(RdpSessionState.ERROR)
            cleanup()
            false
        }
    }

    private suspend fun connectWithoutNla(): Boolean {
        return try {
            val sock = Socket()
            sock.connect(InetSocketAddress(credentials.host, credentials.port), CONNECT_TIMEOUT_MS)
            sock.soTimeout = READ_TIMEOUT_MS
            sock.tcpNoDelay = true

            socket = sock
            inputStream  = DataInputStream(BufferedInputStream(sock.getInputStream(), 65536))
            outputStream = DataOutputStream(BufferedOutputStream(sock.getOutputStream(), 65536))

            forceStandardRdpSecurity = true
            sendX224ConnectionRequest()
            RdpLog.d("FALLBACK STEP 1: X.224 CR sent (Standard RDP Security)")
            if (!readX224ConnectionConfirm()) { RdpLog.e("FALLBACK: X.224 rejected"); return false }
            RdpLog.d("FALLBACK STEP 2: X.224 CC received")

            if (negotiationPresent && serverSelectedProtocol != PROTOCOL_RDP) upgradeTls()
            RdpLog.d("FALLBACK STEP 3: TLS step done (or skipped)")

            sendMcsConnectInitial()
            if (!readMcsConnectResponse()) { RdpLog.e("FALLBACK: MCS connection failed"); return false }
            RdpLog.d("FALLBACK STEP 4: MCS connect response received")
            performMcsDomainSetup()
            RdpLog.d("FALLBACK STEP 5: MCS domain setup complete (userId=$mcsUserId)")
            sendClientInfoPdu()
            RdpLog.d("FALLBACK STEP 6: Client Info sent")
            handleDemandActivePdu()
            RdpLog.d("FALLBACK STEP 7: Demand Active sequence complete")
            true
        } catch (e: Exception) {
            RdpLog.w("Fallback connection failed: ${e.message}", e)
            false
        }
    }

    // ── X.224 ──────────────────────────────────────────────────────────────

    private fun sendX224ConnectionRequest() {
        val cookie = "Cookie: mstshash=user\r\n"
        val cookieBytes = cookie.toByteArray()

        val requestedProtocols = when {
            forceStandardRdpSecurity || !credentials.useNla -> PROTOCOL_RDP
            credentials.useNla -> PROTOCOL_SSL or PROTOCOL_HYBRID or PROTOCOL_HYBRID_EX
            else -> PROTOCOL_SSL
        }

        val negReq = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        negReq.put(0x01)
        negReq.put(0x00)
        negReq.putShort(8)
        negReq.putInt(requestedProtocols)
        val negReqBytes = negReq.array()

        val x224Length = 7 + cookieBytes.size + negReqBytes.size
        val tpktLength = 4 + x224Length

        val buf = ByteBuffer.allocate(tpktLength)
        buf.put(TPKT_VERSION.toByte())
        buf.put(0x00)
        buf.putShort(tpktLength.toShort())
        buf.put((x224Length - 1).toByte())
        buf.put(0xE0.toByte())
        buf.putShort(0x0000)
        buf.putShort(0x0000)
        buf.put(0x00)
        buf.put(cookieBytes)
        buf.put(negReqBytes)

        outputStream?.write(buf.array())
        outputStream?.flush()
        RdpLog.d("X.224 CR sent, length=$tpktLength, proto=0x${requestedProtocols.toString(16)}")
        RdpLog.hex("X.224 CR raw bytes", buf.array())
    }

    private fun readX224ConnectionConfirm(): Boolean {
        negotiatedNla       = false
        negotiatedHybridEx  = false
        serverSelectedProtocol = 0
        negotiationPresent  = false

        val header = ByteArray(4)
        inputStream?.readFully(header) ?: return false
        if (header[0] != TPKT_VERSION.toByte()) return false

        val length = ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
        if (length < 4) return false
        val data = ByteArray(length - 4)
        inputStream?.readFully(data) ?: return false
        RdpLog.hex("X.224 CC raw bytes", header + data)

        if (data.isEmpty() || (data[1].toInt() and 0xFF) != 0xD0) return false

        if (data.size >= 8) {
            val negType = data[7].toInt() and 0xFF
            when (negType) {
                0x02 -> {
                    negotiationPresent = true
                    val selected =
                        ((data.getOrElse(14) { 0 }.toInt() and 0xFF) shl 24) or
                        ((data.getOrElse(13) { 0 }.toInt() and 0xFF) shl 16) or
                        ((data.getOrElse(12) { 0 }.toInt() and 0xFF) shl  8) or
                         (data.getOrElse(11) { 0 }.toInt() and 0xFF)
                    serverSelectedProtocol = selected
                    negotiatedNla      = (selected and PROTOCOL_HYBRID) != 0
                    negotiatedHybridEx = (selected and PROTOCOL_HYBRID_EX) != 0
                    RdpLog.d("Server selected: 0x${selected.toString(16)} (NLA=$negotiatedNla, HybridEX=$negotiatedHybridEx)")
                }
                0x03 -> {
                    negotiationPresent = true
                    val failureCode = data.getOrElse(11) { 0 }.toInt() and 0xFF
                    throw RdpNegotiationFailure(failureCode, describeNegFailure(failureCode))
                }
                else -> RdpLog.w("Unrecognized X.224 negotiation type: 0x${negType.toString(16)}")
            }
        }
        return true
    }

    private fun describeNegFailure(code: Int): String = when (code) {
        1 -> "SSL_REQUIRED_BY_SERVER – enable NLA/TLS for this profile"
        2 -> "SSL_NOT_ALLOWED_BY_SERVER – disable 'Use NLA Authentication' for this profile"
        3 -> "SSL_CERT_NOT_ON_SERVER – server has no certificate configured for TLS"
        4 -> "INCONSISTENT_FLAGS – conflicting protocol flags were requested"
        5 -> "HYBRID_REQUIRED_BY_SERVER – enable 'Use NLA Authentication' for this profile"
        6 -> "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER – server requires TLS with NLA"
        else -> "Server rejected the connection (RDP_NEG_FAILURE code $code)"
    }

    // ── TLS upgrade ────────────────────────────────────────────────────────

    private fun upgradeTls() {
        val trustAllManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(trustAllManager), SecureRandom())
        val sslSocket = sslContext.socketFactory.createSocket(socket, credentials.host, credentials.port, true)
            as javax.net.ssl.SSLSocket
        sslSocket.startHandshake()
        socket     = sslSocket as Socket
        sslSocketRef = sslSocket
        inputStream  = DataInputStream(BufferedInputStream(sslSocket.getInputStream(), 65536))
        outputStream = DataOutputStream(BufferedOutputStream(sslSocket.getOutputStream(), 65536))
        RdpLog.d("TLS upgraded: ${sslSocket.session.protocol} cipher=${sslSocket.session.cipherSuite}")
    }

    // ── NLA / CredSSP ──────────────────────────────────────────────────────

    private fun serverPublicKeyDer(): ByteArray {
        val session = sslSocketRef?.session ?: throw RdpException("No TLS session")
        val cert = session.peerCertificates.firstOrNull() ?: throw RdpException("No server certificate")
        return extractSubjectPublicKey(cert.publicKey.encoded)
    }

    private fun extractSubjectPublicKey(spki: ByteArray): ByteArray {
        var pos = 0
        if (spki[pos].toInt() and 0xFF != 0x30) return spki
        pos++
        val outer = readAsn1Length(spki, pos); pos += outer.second
        if (spki[pos].toInt() and 0xFF != 0x30) return spki
        pos++
        val algo = readAsn1Length(spki, pos); pos += algo.second + algo.first
        if (spki[pos].toInt() and 0xFF != 0x03) return spki
        pos++
        val bs = readAsn1Length(spki, pos); pos += bs.second
        pos++ // skip unused-bits byte
        return spki.copyOfRange(pos, pos + bs.first - 1)
    }

    private fun readAsn1Length(data: ByteArray, offset: Int): Pair<Int, Int> {
        val first = data[offset].toInt() and 0xFF
        return if (first < 0x80) Pair(first, 1)
        else {
            val n = first and 0x7F
            var len = 0
            for (i in 0 until n) len = (len shl 8) or (data[offset + 1 + i].toInt() and 0xFF)
            Pair(len, 1 + n)
        }
    }

    private suspend fun performNlaAuthentication() {
        RdpLog.d("Starting CredSSP/NTLMv2 auth")

        val negotiateMsg = NtlmHelper.buildNegotiateMessage(credentials.domain)
        sendRaw(CredSspHelper.buildNegotiateTsRequest(negotiateMsg))
        RdpLog.d("NLA Step 1: NEGOTIATE sent")

        val challengeRequest = readRaw() ?: throw RdpAuthException("No CredSSP CHALLENGE response")
        CredSspHelper.extractErrorCode(challengeRequest)?.let { code ->
            throw RdpAuthException("Server rejected NLA negotiation: ${CredSspHelper.describeErrorCode(code)}")
        }

        val challengeMsg = CredSspHelper.extractNegoToken(challengeRequest)
            ?: throw RdpAuthException("Missing NTLM CHALLENGE token")
        val challenge = NtlmHelper.parseChallengeMessage(challengeMsg)
        RdpLog.d("NLA Step 2: CHALLENGE received")

        val serverVersion = CredSspHelper.extractVersion(challengeRequest)
        if (serverVersion >= 5) {
            CredSspHelper.negotiatedCredSspVersion = serverVersion
            RdpLog.d("CredSSP v$serverVersion (SHA256 mode, Windows 8+)")
        }

        val serverPublicKey = serverPublicKeyDer()

        val authResult = NtlmHelper.buildAuthenticateMessage(
            username       = credentials.username,
            password       = credentials.password,
            domain         = credentials.domain,
            challenge      = challenge,
            negotiateMessage  = negotiateMsg,
            challengeMessage  = challengeMsg,
            serverSpn      = "TERMSRV/${credentials.host}"
        )
        RdpLog.d("NLA: AUTHENTICATE built")

        val pubKeyAuthToken = CredSspHelper.computePubKeyAuth(serverPublicKey, authResult.encryptionState, 0)
        sendRaw(CredSspHelper.buildAuthenticateTsRequest(authResult.message, pubKeyAuthToken))
        RdpLog.d("NLA Step 3: AUTHENTICATE + pubKeyAuth sent")

        val pubKeyResponse = readRaw() ?: throw RdpAuthException(
            "No pubKeyAuth response – server closed connection after credentials " +
            "(wrong password or NLA not enabled on server)"
        )
        CredSspHelper.extractErrorCode(pubKeyResponse)?.let { code ->
            throw RdpAuthException(CredSspHelper.describeErrorCode(code))
        }

        val encryptedServerConfirm = CredSspHelper.extractPubKeyAuth(pubKeyResponse)
            ?: throw RdpAuthException("Missing pubKeyAuth confirmation")

        val verified = CredSspHelper.verifyPubKeyAuthResponse(
            encryptedResponse = encryptedServerConfirm,
            serverPublicKey   = serverPublicKey,
            encryptionState   = authResult.encryptionState,
            sequenceNumber    = 0
        )
        if (!verified) throw RdpAuthException("Server public key confirmation mismatch")
        RdpLog.d("Server pubKeyAuth verified")

        val tsCredentials = CredSspHelper.buildTsCredentials(credentials.domain, credentials.username, credentials.password)
        val encryptedCreds = NtlmHelper.encryptMessage(authResult.encryptionState, tsCredentials, 1)
        sendRaw(CredSspHelper.buildAuthInfoTsRequest(encryptedCreds))
        RdpLog.d("NLA Step 5: Encrypted credentials sent – CredSSP complete")
    }

    private fun handleEarlyUserAuthResult(): Boolean {
        return try {
            val buf = ByteArray(4)
            inputStream?.readFully(buf) ?: return true
            val result = ((buf[3].toInt() and 0xFF) shl 24) or
                         ((buf[2].toInt() and 0xFF) shl 16) or
                         ((buf[1].toInt() and 0xFF) shl  8) or
                          (buf[0].toInt() and 0xFF)
            RdpLog.d("Early User Authorization Result: 0x${result.toString(16).padStart(8, '0')}")
            result == 0x00000000
        } catch (e: Exception) {
            RdpLog.w("Early User Auth Result handling failed: ${e.message}")
            true
        }
    }

    // ── MCS ────────────────────────────────────────────────────────────────

    private fun sendMcsConnectInitial() {
        val payload = buildMcsConnectInitialPayload()
        RdpLog.hex("MCS Connect Initial payload (pre-TPKT)", payload, maxBytes = 2048)
        sendTpkt(payload)
    }

    private fun buildMcsConnectInitialPayload(): ByteArray {
        val coreData    = buildClientCoreData()
        val secData     = buildClientSecurityData()
        val netData     = buildClientNetworkData()
        val clusterData = buildClientClusterData()
        RdpLog.d("GCC userData block sizes: core=${coreData.size} sec=${secData.size} net=${netData.size} cluster=${clusterData.size} total=${coreData.size + secData.size + netData.size + clusterData.size}")
        return wrapInGccConferenceCreateRequest(coreData + secData + netData + clusterData)
    }

    /**
     * TS_UD_CS_CORE (MS-RDPBCGR §2.2.1.3.2) — 234 bytes for RDP 5.0+.
     *
     * BUG-E fix: desktopScaleFactor and deviceScaleFactor are UINT32 fields
     * (4 bytes each), not UINT16. Changed putShort(1) → putInt(1).
     */
    private fun buildClientCoreData(): ByteArray {
        val buf = ByteBuffer.allocate(256).order(ByteOrder.LITTLE_ENDIAN)

        // Header (4 bytes)
        buf.putShort(0xC001.toShort())   // type = CS_CORE
        buf.putShort(234)                // length = 234

        // Core fields
        buf.putInt(RDP_VERSION_5_0)
        buf.putShort(displayWidth.toShort())
        buf.putShort(displayHeight.toShort())
        buf.putShort(RNS_UD_COLOR_8BPP.toShort())  // colorDepth (legacy)
        buf.putShort(RNS_UD_SAS_DEL.toShort())     // SASSequence
        buf.putInt(0x00000409)           // keyboardLayout EN-US
        buf.putInt(2600)                 // clientBuild

        // clientName: 16 UTF-16LE chars = 32 bytes
        val clientName = "HEXRDP".padEnd(16, '\u0000')
        clientName.forEach { buf.putShort(it.code.toShort()) }

        buf.putInt(4)                    // keyboardType
        buf.putInt(0)                    // keyboardSubType
        buf.putInt(12)                   // keyboardFunctionKey
        repeat(64) { buf.put(0) }       // imeFileName

        buf.putShort(RNS_UD_COLOR_8BPP.toShort()) // postBeta2ColorDepth
        buf.putShort(1)                  // clientProductId
        buf.putInt(0)                    // serialNumber
        buf.putShort(0x0018.toShort())  // highColorDepth = 24 bpp
        buf.putShort(0x000F.toShort())  // supportedColorDepths (all)
        buf.putShort(0x0001.toShort())  // earlyCapabilityFlags
        repeat(64) { buf.put(0) }       // clientDigProductId
        buf.put(0)                       // connectionType
        buf.put(0)                       // pad1octet
        buf.putInt(serverSelectedProtocol) // MUST echo server's choice

        // RDP 5.0+ extended fields (offset 216–233)
        buf.putInt(0)                    // desktopPhysicalWidth  (UINT32)
        buf.putInt(0)                    // desktopPhysicalHeight (UINT32)
        buf.putShort(0)                  // desktopOrientation    (UINT16)
        buf.putInt(1)                    // desktopScaleFactor    (UINT32) ← was putShort
        buf.putInt(1)                    // deviceScaleFactor     (UINT32) ← was putShort

        // pos should be exactly 234 here
        return buf.array().copyOf(234)
    }

    private fun buildClientSecurityData(): ByteArray {
        val buf = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0xC002.toShort()); buf.putShort(12)
        val encryptionMethods = if (forceStandardRdpSecurity || serverSelectedProtocol == PROTOCOL_RDP) {
            ENCRYPTION_METHOD_40BIT or ENCRYPTION_METHOD_128BIT
        } else {
            0x00000000  // Enhanced security: no RDP-layer encryption
        }
        buf.putInt(encryptionMethods)
        buf.putInt(0x00000000)  // extEncryptionMethods
        return buf.array()
    }

    private fun buildClientNetworkData(): ByteArray {
        val buf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0xC003.toShort()); buf.putShort(8); buf.putInt(0)
        return buf.array()
    }

    private fun buildClientClusterData(): ByteArray {
        val buf = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0xC004.toShort()); buf.putShort(12)
        buf.putInt(0x0000001C)  // REDIRECTION_SUPPORTED | REDIRECTION_VERSION3
        buf.putInt(0)
        return buf.array()
    }

    /**
     * Wrap user data in MCS Connect Initial with correct BER DomainParameters
     * and GCC Conference Create Request.
     *
     * DomainParameters values match FreeRDP's mcs.c defaults:
     *   target  : maxChannelIds=34, maxUserIds=3, maxTokenIds=0,
     *             numPriorities=1, minThroughput=0, maxHeight=1,
     *             maxMCSPDUsize=65535, protocolVersion=2
     *   minimum : 1, 1, 1, 1, 0, 1, 1056, 2
     *   maximum : 65535, 64535, 65535, 1, 0, 1, 65535, 2
     */
    private fun wrapInGccConferenceCreateRequest(userData: ByteArray): ByteArray {
        val gccRequest = buildGccConferenceCreateRequest(userData)

        val targetParams  = buildDomainParameters(34,    3,     0,     1, 0, 1, 65535, 2)
        val minimumParams = buildDomainParameters(1,     1,     1,     1, 0, 1,  1056, 2)
        val maximumParams = buildDomainParameters(65535, 64535, 65535, 1, 0, 1, 65535, 2)

        // MCS Connect Initial body (BER)
        val mcsBody = byteArrayOf(
            0x04, 0x01, 0x01,           // callingDomainSelector OCTET STRING
            0x04, 0x01, 0x01,           // calledDomainSelector  OCTET STRING
            0x01, 0x01, 0xFF.toByte()   // upwardFlag BOOLEAN TRUE
        ) + targetParams + minimumParams + maximumParams +
            byteArrayOf(0x04) + berLengthBytes(gccRequest.size) + gccRequest

        // APPLICATION 101 outer wrapper (BER)
        val out = ByteArrayOutputStream()
        out.write(0x7F); out.write(0x65)
        out.write(berLengthBytes(mcsBody.size))
        out.write(mcsBody)
        return out.toByteArray()
    }

    /**
     * Build GCC Conference Create Request with correct PER encoding.
     * Matches FreeRDP gcc_write_conference_create_request() byte-for-byte.
     *
     * For userData of size N (typically ~266 bytes), the output is:
     *
     *   00                        per_write_choice(0)
     *   00 05 00 14 7C 00 01      per_write_object_identifier(t124_02_98_oid)
     *   <PER length of N+14>      per_write_length(N+14)
     *   00                        per_write_choice(0)  [createRequest]
     *   08                        per_write_selection(0x08)
     *   00 10                     per_write_numeric_string("1",1,1)
     *   00                        per_write_padding(1)
     *   01                        per_write_number_of_sets(1)
     *   C0                        per_write_choice(0xC0)
     *   00                        per_write_octet_string len(4-4=0)  ← BUG-C was missing
     *   44 75 63 61               "Duca"
     *   <PER length of N>         per_write_octet_string len(N-0)
     *   <N bytes userData>
     *
     * The "14" constant: 1+1+2+1+1+1+1+4+2 = 14 bytes of fixed overhead
     * (assumes userData >= 128 bytes so its PER length is 2 bytes).
     */
    private fun buildGccConferenceCreateRequest(userData: ByteArray): ByteArray {
        val s = ByteArrayOutputStream()

        // per_write_choice(0)
        s.write(0x00)

        // per_write_object_identifier(t124_02_98_oid)
        s.write(byteArrayOf(0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01))

        // per_write_length(userData.size + 14) — length of ConferenceCreateRequest fields
        writePerLength(s, userData.size + 14)

        // per_write_choice(0) — createRequest
        s.write(0x00)

        // per_write_selection(0x08)
        s.write(0x08)

        // per_write_numeric_string("1", 1, 1)
        // FIX BUG-B: must be 0x00 (per_write_length(1-1=0)) + 0x10 (('1'-'0')<<4)
        s.write(0x00)   // per_write_length(0)
        s.write(0x10)   // BCD nibble for digit '1'

        // per_write_padding(1)
        s.write(0x00)

        // per_write_number_of_sets(1)
        s.write(0x01)

        // per_write_choice(0xC0)
        s.write(0xC0)

        // per_write_octet_string(h221_cs_key, 4, 4)
        // FIX BUG-C: must write per_write_length(4-4=0) = 0x00 BEFORE the key bytes
        s.write(0x00)   // length prefix: 4 - 4 = 0
        s.write(byteArrayOf('D'.code.toByte(), 'u'.code.toByte(), 'c'.code.toByte(), 'a'.code.toByte()))

        // per_write_octet_string(userData, userData.size, 0)
        writePerLength(s, userData.size)
        s.write(userData)

        return s.toByteArray()
    }

    /**
     * FIX BUG-A: PER length encoding matching FreeRDP's per_write_length().
     *
     * FreeRDP rule (freerdp/codec/per.c):
     *   if (length > 127): write 0x80|(length>>8), then length&0xFF  — always 2 bytes
     *   else:              write length as a single byte
     *
     * The previous implementation used BER-style 0x81/0x82 prefixes, which
     * produce 2- or 3-byte fields that the server's PER decoder cannot accept.
     *
     * Examples:
     *   writePerLength(100) → 0x64             (1 byte,  unchanged)
     *   writePerLength(200) → 0x80 0xC8        (2 bytes, was: 0x81 0xC8)
     *   writePerLength(280) → 0x81 0x18        (2 bytes, was: 0x82 0x01 0x18)
     *   writePerLength(266) → 0x81 0x0A        (2 bytes, was: 0x82 0x01 0x0A)
     */
    private fun writePerLength(s: ByteArrayOutputStream, length: Int) {
        if (length > 0x7F) {
            s.write(0x80 or (length ushr 8))
            s.write(length and 0xFF)
        } else {
            s.write(length)
        }
    }

    /**
     * Build BER-encoded DomainParameters SEQUENCE.
     * Uses berIntegerMinimal() which matches FreeRDP's ber_write_integer().
     */
    private fun buildDomainParameters(
        maxCh: Int, maxUs: Int, maxTok: Int,
        numPri: Int, minThr: Int, maxH: Int,
        maxPDU: Int, proto: Int
    ): ByteArray {
        val body = berIntegerMinimal(maxCh)  +
                   berIntegerMinimal(maxUs)  +
                   berIntegerMinimal(maxTok) +
                   berIntegerMinimal(numPri) +
                   berIntegerMinimal(minThr) +
                   berIntegerMinimal(maxH)   +
                   berIntegerMinimal(maxPDU) +
                   berIntegerMinimal(proto)
        // SEQUENCE tag + length (length always fits in 1 byte for these values)
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    /**
     * FIX BUG-D: BER INTEGER with MINIMAL encoding matching FreeRDP's
     * ber_write_integer() (freerdp/asn1/ber.c).
     *
     * FreeRDP thresholds (all UNSIGNED to signed BER):
     *   value <  0x80     → 1 content byte  (high bit = 0, positive)
     *   value <  0x8000   → 2 content bytes (high bit of MSB = 0, positive)
     *   value <  0x800000 → 3 content bytes (prepend 0x00 if value >= 0x8000)
     *   else              → 4 content bytes
     *
     * The bug: values 32768–65535 (0x8000–0xFFFF) have their MSB's high bit
     * set, so they need a leading 0x00 to remain positive in BER.
     * The old code used 2 content bytes for 256–65535, encoding 65535 as
     * 0xFF 0xFF which is signed -1, not +65535.
     *
     * Examples:
     *   berIntegerMinimal(0)     → 02 01 00
     *   berIntegerMinimal(1)     → 02 01 01
     *   berIntegerMinimal(34)    → 02 01 22
     *   berIntegerMinimal(1056)  → 02 02 04 20
     *   berIntegerMinimal(65535) → 02 03 00 FF FF  ← was 02 02 FF FF (= -1!)
     */
    private fun berIntegerMinimal(value: Int): ByteArray = when {
        value < 0x80 ->
            byteArrayOf(0x02, 0x01, value.toByte())
        value < 0x8000 ->
            byteArrayOf(0x02, 0x02,
                (value ushr 8).toByte(),
                (value and 0xFF).toByte()
            )
        value < 0x800000 ->
            byteArrayOf(0x02, 0x03,
                (value ushr 16).toByte(),
                ((value ushr 8) and 0xFF).toByte(),
                (value and 0xFF).toByte()
            )
        else ->
            byteArrayOf(0x02, 0x04,
                (value ushr 24).toByte(),
                ((value ushr 16) and 0xFF).toByte(),
                ((value ushr 8) and 0xFF).toByte(),
                (value and 0xFF).toByte()
            )
    }

    /** BER length encoding for BER SEQUENCE/APPLICATION wrappers (not PER). */
    private fun berLengthBytes(length: Int): ByteArray = when {
        length < 0x80  -> byteArrayOf(length.toByte())
        length < 0x100 -> byteArrayOf(0x81.toByte(), length.toByte())
        else           -> byteArrayOf(0x82.toByte(), (length ushr 8).toByte(), (length and 0xFF).toByte())
    }

    /**
     * Parse MCS Connect Response (BER APPLICATION 102).
     *
     * BUG-F fix: ENUMERATED skip was pos+=2 (tag+len), missing the value byte.
     * Changed to pos+=3 (tag + len-byte + value-byte).
     *
     * The function is lenient: if userData OCTET STRING cannot be located
     * (e.g. server sends a non-standard layout), we still return true so
     * the connection attempt can continue.
     */
    private fun readMcsConnectResponse(): Boolean {
        val packet = readX224Data()
        if (packet == null) {
            RdpLog.e("MCS Connect Response: no data received — socket closed or read timeout")
            return false
        }
        RdpLog.hex("MCS Connect Response raw bytes", packet, maxBytes = 1024)
        if (packet.isEmpty()) {
            RdpLog.e("MCS Connect Response: received empty packet")
            return false
        }

        var pos = 0

        // Outer tag: APPLICATION 102 is encoded as 0x7F 0x66 (extended BER tag)
        val tag = packet[pos].toInt() and 0xFF
        when {
            tag == 0x7F -> {
                // Extended tag form
                if (pos + 1 >= packet.size) return false
                val extTag = packet[pos + 1].toInt() and 0xFF
                if (extTag != 0x66) {
                    RdpLog.w("MCS Connect Response: tag=0x7F 0x${extTag.toString(16)} (expected 0x66=102)")
                    // Be lenient: some servers may use slightly different encoding
                }
                pos += 2
            }
            tag == 0x30 || tag == 0x66 -> {
                // SEQUENCE or single-byte APPLICATION tag — lenient
                pos += 1
            }
            else -> {
                val preview = packet.take(16).joinToString(" ") { "%02X".format(it) }
                RdpLog.e("MCS Connect Response: unexpected tag=0x${tag.toString(16)} bytes=[$preview]")
                return false
            }
        }

        // BER length of MCS Connect Response body
        if (pos >= packet.size) return false
        val (_, lenBytes) = readBerLength(packet, pos)
        pos += lenBytes

        // result ENUMERATED (tag=0x0A, len=0x01, value)
        // FIX BUG-F: was pos+=2, missing value byte
        if (pos + 3 > packet.size) {
            RdpLog.d("MCS Connect Response: too short to parse ENUMERATED, accepting leniently")
            return true
        }
        if ((packet[pos].toInt() and 0xFF) != 0x0A) {
            RdpLog.d("MCS Connect Response: expected ENUMERATED(0x0A) at pos=$pos, got 0x${(packet[pos].toInt() and 0xFF).toString(16)}, accepting leniently")
            return true
        }
        val resultValue = packet[pos + 2].toInt() and 0xFF
        if (resultValue != 0) {
            RdpLog.e("MCS Connect Response: server returned result=$resultValue (non-zero = failure)")
            return false
        }
        pos += 3   // tag(1) + len(1) + value(1)

        // calledConnectId INTEGER
        if (pos + 2 <= packet.size && (packet[pos].toInt() and 0xFF) == 0x02) {
            val idLen = packet[pos + 1].toInt() and 0xFF
            pos += 2 + idLen
        }

        // domainParameters SEQUENCE
        if (pos + 2 <= packet.size && (packet[pos].toInt() and 0xFF) == 0x30) {
            val dpLen = packet[pos + 1].toInt() and 0xFF
            pos += 2 + dpLen
        }

        // userData OCTET STRING
        if (pos + 2 <= packet.size && (packet[pos].toInt() and 0xFF) == 0x04) {
            val udLen = packet[pos + 1].toInt() and 0xFF
            pos += 2
            RdpLog.d("MCS Connect Response: GCC data at offset $pos, length $udLen — OK")
            return true
        }

        RdpLog.d("MCS Connect Response: could not locate userData OCTET STRING, accepting leniently")
        return true
    }

    private fun readBerLength(data: ByteArray, offset: Int): Pair<Int, Int> {
        if (offset >= data.size) return Pair(0, 0)
        val first = data[offset].toInt() and 0xFF
        return when {
            first < 0x80 -> Pair(first, 1)
            first == 0x81 -> {
                if (offset + 1 >= data.size) return Pair(0, 0)
                Pair(data[offset + 1].toInt() and 0xFF, 2)
            }
            first == 0x82 -> {
                if (offset + 2 >= data.size) return Pair(0, 0)
                val len = ((data[offset + 1].toInt() and 0xFF) shl 8) or (data[offset + 2].toInt() and 0xFF)
                Pair(len, 3)
            }
            else -> Pair(0, 0)
        }
    }

    private fun performMcsDomainSetup() {
        sendTpkt(byteArrayOf(0x04, 0x01, 0x00, 0x01, 0x00))  // ErectDomainRequest
        sendTpkt(byteArrayOf(0x28))                            // AttachUserRequest

        val aucf = readX224Data() ?: throw RdpException("No Attach User Confirm")
        if (aucf.size < 4) throw RdpException("Malformed Attach User Confirm")
        val result = aucf[1].toInt() and 0xFF
        if (result != 0) throw RdpException("Attach User failed (result=$result)")
        mcsUserId = ((aucf[2].toInt() and 0xFF) shl 8) or (aucf[3].toInt() and 0xFF)
        RdpLog.d("MCS user ID: $mcsUserId")

        joinChannel(mcsUserId + MCS_USER_BASE)
        joinChannel(ioChannelId)
    }

    private fun joinChannel(channelId: Int) {
        val req = ByteBuffer.allocate(5).order(ByteOrder.BIG_ENDIAN)
        req.put(0x38); req.putShort(mcsUserId.toShort()); req.putShort(channelId.toShort())
        sendTpkt(req.array())
        val cjcf = readX224Data() ?: throw RdpException("No Channel Join Confirm for $channelId")
        if (cjcf.size < 2 || (cjcf[1].toInt() and 0xFF) != 0)
            throw RdpException("Channel Join failed for channel $channelId")
    }

    // ── Client Info PDU ────────────────────────────────────────────────────

    private fun sendClientInfoPdu() {
        val domainBytes = (credentials.domain   + "\u0000").toByteArray(Charsets.UTF_16LE)
        val userBytes   = (credentials.username + "\u0000").toByteArray(Charsets.UTF_16LE)
        val passBytes   = (credentials.password + "\u0000").toByteArray(Charsets.UTF_16LE)
        val shellBytes  = "\u0000".toByteArray(Charsets.UTF_16LE)
        val workBytes   = "\u0000".toByteArray(Charsets.UTF_16LE)

        val infoPacketFlags = INFO_MOUSE or
                INFO_DISABLECTRLALTDEL or
                INFO_AUTOLOGON or
                INFO_MAXIMIZESHELL or
                INFO_UNICODE or
                INFO_ENABLEWINDOWSKEY or
                INFO_LOGON_NOTIFY

        val infoPacketSize = 4 + 4 + 2 + 2 + 2 + 2 + 2 +
                domainBytes.size + userBytes.size + passBytes.size +
                shellBytes.size + workBytes.size

        val secHeader = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
        secHeader.putShort(SEC_INFO_PKT.toShort())
        secHeader.putShort(0)

        val infoBuf = ByteBuffer.allocate(infoPacketSize).order(ByteOrder.LITTLE_ENDIAN)
        infoBuf.putInt(0x00000000)
        infoBuf.putInt(infoPacketFlags)
        infoBuf.putShort((domainBytes.size - 2).toShort())
        infoBuf.putShort((userBytes.size   - 2).toShort())
        infoBuf.putShort((passBytes.size   - 2).toShort())
        infoBuf.putShort((shellBytes.size  - 2).toShort())
        infoBuf.putShort((workBytes.size   - 2).toShort())
        infoBuf.put(domainBytes)
        infoBuf.put(userBytes)
        infoBuf.put(passBytes)
        infoBuf.put(shellBytes)
        infoBuf.put(workBytes)

        val payload = secHeader.array() + infoBuf.array().copyOf(infoBuf.position())
        RdpLog.d("Client Info PDU: domain='${credentials.domain}' user='${credentials.username}' passwordLen=${credentials.password.length} totalPayloadBytes=${payload.size}")
        sendMcsSendDataRequest(payload)
    }

    // ── Demand Active + post-connection PDU burst ──────────────────────────

    private fun handleDemandActivePdu() {
        var foundDemandActive = false
        for (attempt in 0 until 10) {
            val raw = readX224Data() ?: break
            RdpLog.hex("Post-MCS PDU attempt #$attempt raw bytes", raw, maxBytes = 256)
            val payload = stripMcsSendDataIndication(raw)
            if (payload.size >= 6) {
                val pduType = payload[2].toInt() and 0xFF
                if (pduType == PDU_TYPE_DEMAND_ACTIVE) {
                    if (payload.size >= 10) {
                        serverShareId =
                            ((payload[9].toInt() and 0xFF) shl 24) or
                            ((payload[8].toInt() and 0xFF) shl 16) or
                            ((payload[7].toInt() and 0xFF) shl  8) or
                             (payload[6].toInt() and 0xFF)
                        RdpLog.d("Demand Active: shareId=0x${serverShareId.toString(16)}")
                    }
                    foundDemandActive = true
                    break
                }
            }
        }
        if (!foundDemandActive) {
            RdpLog.w("Demand Active PDU not found; using default shareId=0x${serverShareId.toString(16)}")
        }

        sendConfirmActivePdu()
        RdpLog.d("PDU burst: Confirm Active sent")

        sendSynchronizePdu()
        RdpLog.d("PDU burst: Synchronize sent")

        sendControlPdu(CTRLACTION_COOPERATE)
        RdpLog.d("PDU burst: Control COOPERATE sent")

        sendControlPdu(CTRLACTION_REQUEST_CONTROL)
        RdpLog.d("PDU burst: Control REQUEST_CONTROL sent")

        sendFontListPdu()
        RdpLog.d("PDU burst: Font List sent")

        var drained = 0
        for (i in 0 until 8) {
            val raw = try { readX224Data() } catch (e: Exception) { null }
            if (raw == null) break
            val payload = stripMcsSendDataIndication(raw)
            if (payload.size >= 3) {
                val pduType = payload[2].toInt() and 0xFF
                RdpLog.d("Post-burst server PDU type=0x${pduType.toString(16)}")
                if (pduType == PDU_TYPE_DATA) {
                    drained++
                    if (drained >= 4) break
                }
            }
        }
        RdpLog.d("Post-burst drain complete ($drained PDUs consumed)")
    }

    // ── Confirm Active PDU ─────────────────────────────────────────────────

    private fun sendConfirmActivePdu() {
        val caps       = buildCapabilitySets()
        val srcDesc    = byteArrayOf('R'.code.toByte(), 'D'.code.toByte(), 'P'.code.toByte(), 0x00)
        val numCaps    = countCapabilitySets(caps).toShort()
        val combinedLen = (caps.size + 4).toShort()
        val totalLength = 6 + 4 + 2 + 2 + 2 + srcDesc.size + 2 + 2 + caps.size

        val buf = ByteBuffer.allocate(totalLength).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(totalLength.toShort())
        buf.putShort(PDU_TYPE_CONFIRM_ACTIVE.toShort())
        buf.putShort(0x03EA.toShort())
        buf.putInt(serverShareId)
        buf.putShort(0x03EA.toShort())
        buf.putShort(srcDesc.size.toShort())
        buf.putShort(combinedLen)
        buf.put(srcDesc)
        buf.putShort(numCaps)
        buf.putShort(0)
        buf.put(caps)

        sendMcsSendDataRequest(buf.array().copyOf(buf.position()))
    }

    private fun countCapabilitySets(caps: ByteArray): Int {
        var count = 0; var pos = 0
        while (pos + 4 <= caps.size) {
            val len = ((caps[pos + 3].toInt() and 0xFF) shl 8) or (caps[pos + 2].toInt() and 0xFF)
            if (len < 4 || pos + len > caps.size) break
            count++; pos += len
        }
        return count
    }

    private fun buildCapabilitySets(): ByteArray {
        val buf = ByteBuffer.allocate(1024).order(ByteOrder.LITTLE_ENDIAN)

        // CAPSTYPE_GENERAL (0x0001) — 24 bytes
        buf.putShort(0x0001); buf.putShort(24)
        buf.putShort(1); buf.putShort(3); buf.putShort(0x0200)
        buf.putShort(0); buf.putShort(0); buf.putShort(0x0441)
        buf.putShort(0); buf.putShort(0); buf.putShort(0); buf.putShort(0)
        buf.put(1); buf.put(1)

        // CAPSTYPE_BITMAP (0x0002) — 28 bytes
        buf.putShort(0x0002); buf.putShort(28)
        buf.putShort(32); buf.putShort(1); buf.putShort(1); buf.putShort(1)
        buf.putShort(displayWidth.toShort()); buf.putShort(displayHeight.toShort())
        buf.putShort(0); buf.putShort(1); buf.putShort(1)
        buf.put(0); buf.put(0); buf.putShort(1); buf.putShort(0)

        // CAPSTYPE_ORDER (0x0003) — 88 bytes
        buf.putShort(0x0003); buf.putShort(88)
        repeat(16) { buf.put(0) }
        buf.putInt(0); buf.putShort(1); buf.putShort(20)
        buf.putShort(0); buf.putShort(1); buf.putShort(0); buf.putShort(0x002F)
        repeat(32) { buf.put(0) }
        buf.putShort(0); buf.putShort(0x0040); buf.putInt(0); buf.putInt(230400)
        buf.putShort(0); buf.putShort(0); buf.putShort(0x0409); buf.putShort(0)

        // CAPSTYPE_BITMAPCACHE_REV2 (0x0013) — 40 bytes
        buf.putShort(0x0013); buf.putShort(40)
        buf.putShort(0x0003); buf.putShort(0)
        buf.put(3); buf.put(0); buf.put(0); buf.put(0)
        buf.putInt(600); buf.putInt(0x00000078); buf.putInt(0x00000078)
        repeat(16) { buf.put(0) }

        // CAPSTYPE_POINTER (0x0008) — 10 bytes
        buf.putShort(0x0008); buf.putShort(10)
        buf.putShort(1); buf.putShort(20); buf.putShort(20)

        // CAPSTYPE_INPUT (0x000D) — 88 bytes
        buf.putShort(0x000D); buf.putShort(88)
        buf.putShort(0x0008); buf.putShort(0); buf.putInt(0x00000409)
        buf.putInt(4); buf.putInt(0); buf.putInt(12)
        repeat(64) { buf.put(0) }

        // CAPSTYPE_BRUSH (0x000F) — 8 bytes
        buf.putShort(0x000F); buf.putShort(8); buf.putInt(1)

        // CAPSTYPE_GLYPHCACHE (0x0010) — 52 bytes
        buf.putShort(0x0010); buf.putShort(52)
        repeat(10) { buf.putShort(0x0100); buf.putShort(0x0004) }
        buf.putInt(0x00000001); buf.putShort(0x0001); buf.putShort(0)

        // CAPSTYPE_OFFSCREENCACHE (0x0011) — 12 bytes
        buf.putShort(0x0011); buf.putShort(12)
        buf.putInt(7680); buf.putShort(0x0064); buf.putShort(0x0001)

        // CAPSTYPE_VIRTUALCHANNEL (0x0014) — 12 bytes
        buf.putShort(0x0014); buf.putShort(12)
        buf.putInt(0); buf.putInt(0x00020000)

        // CAPSTYPE_SOUND (0x000C) — 8 bytes
        buf.putShort(0x000C); buf.putShort(8)
        buf.putShort(0); buf.putShort(0)

        // CAPSTYPE_SURFACE_COMMANDS (0x001D) — 8 bytes
        buf.putShort(0x001D); buf.putShort(8); buf.putInt(0x00000001)

        return buf.array().copyOf(buf.position())
    }

    // ── Post-connection sync/control/font PDUs ─────────────────────────────

    private fun buildDataPdu(pduType2: Int, payload: ByteArray): ByteArray {
        val totalLength = 6 + 18 + payload.size
        val buf = ByteBuffer.allocate(totalLength).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(totalLength.toShort())
        buf.putShort(PDU_TYPE_DATA.toShort())
        buf.putShort(0x03EA.toShort())
        buf.putInt(serverShareId)
        buf.put(0); buf.put(1)
        buf.putShort((4 + payload.size).toShort())
        buf.put(pduType2.toByte()); buf.put(0); buf.putShort(0)
        buf.put(payload)
        return buf.array().copyOf(buf.position())
    }

    private fun sendSynchronizePdu() {
        val payload = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(1).putShort(mcsUserId.toShort()).array()
        sendMcsSendDataRequest(buildDataPdu(PDUTYPE2_SYNCHRONIZE, payload))
    }

    private fun sendControlPdu(action: Int) {
        val payload = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(action.toShort()).putShort(0).putInt(0).array()
        sendMcsSendDataRequest(buildDataPdu(PDUTYPE2_CONTROL, payload))
    }

    private fun sendFontListPdu() {
        val payload = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(0).putShort(0).putShort(0x0003).putShort(0x0032).array()
        sendMcsSendDataRequest(buildDataPdu(PDUTYPE2_FONTLIST, payload))
    }

    // ── Receive loop ────────────────────────────────────────────────────────

    private suspend fun receiveLoop() = withContext(Dispatchers.IO) {
        var consecutiveErrors = 0
        while (connected && isActive) {
            try {
                val packet = readTpkt() ?: break
                val pingStart = System.currentTimeMillis()
                processIncomingPdu(packet)
                latencyMs = System.currentTimeMillis() - pingStart
                consecutiveErrors = 0
                if (performanceMode == RdpPerformance.AUTO) adaptPerformance()
            } catch (e: CancellationException) { break
            } catch (e: Exception) {
                consecutiveErrors++
                RdpLog.w("Receive error ($consecutiveErrors): ${e.message}")
                if (consecutiveErrors > 5) {
                    _sessionState.emit(RdpSessionState.ERROR)
                    _error.emit("Connection lost: ${e.message}")
                    break
                }
                delay(100L * consecutiveErrors)
            }
        }
        cleanup()
    }

    private suspend fun processIncomingPdu(data: ByteArray) {
        if (data.isEmpty()) return
        val isMcsSdi = data.size >= 3 &&
                (data[0].toInt() and 0xFF) == 0x02 &&
                (data[1].toInt() and 0xFF) == 0xF0
        if (isMcsSdi) {
            val payload = stripMcsSendDataIndication(data.copyOfRange(3, data.size))
            if (payload.size >= 3) {
                val pduType = payload[2].toInt() and 0xFF
                when (pduType) {
                    PDU_TYPE_DEMAND_ACTIVE -> {
                        RdpLog.d("Reactivation: new Demand Active received")
                        handleDemandActivePdu()
                    }
                    else -> Log.v(TAG, "Unhandled MCS PDU type: 0x${pduType.toString(16)}")
                }
            }
            return
        }
        processDataPdu(data)
    }

    private suspend fun processDataPdu(data: ByteArray) {
        val decoder = RdpBitmapDecoder()
        val frames = decoder.decode(data, displayWidth, displayHeight, currentPerformance)
        for (frame in frames) _frameUpdates.emit(frame)
    }

    private fun adaptPerformance() {
        bandwidthKbps = bandwidthDetector.getCurrentKbps()
        currentPerformance = when {
            bandwidthKbps < 100  -> RdpPerformance.LOW_BANDWIDTH
            bandwidthKbps < 500  -> RdpPerformance.MEDIUM
            bandwidthKbps < 2000 -> RdpPerformance.WIFI
            else                 -> RdpPerformance.LAN
        }
    }

    // ── Input ────────────────────────────────────────────────────────────────

    fun sendMouseMove(x: Int, y: Int) {
        if (!connected) return
        val buf = ByteBuffer.allocate(7).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(0x10.toByte()); buf.putShort(0x0800.toShort())
        buf.putShort(x.toShort()); buf.putShort(y.toShort())
        sendFastPathInput(buf.array().copyOf(buf.position()))
    }

    fun sendMouseClick(x: Int, y: Int, button: MouseButton, down: Boolean) {
        if (!connected) return
        val flags: Short = when (button) {
            MouseButton.LEFT   -> if (down) (0x1000 or 0x8000) else 0x1000
            MouseButton.RIGHT  -> if (down) (0x2000 or 0x8000) else 0x2000
            MouseButton.MIDDLE -> if (down) (0x4000 or 0x8000) else 0x4000
        }.toShort()
        val buf = ByteBuffer.allocate(7).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(0x10.toByte()); buf.putShort(flags)
        buf.putShort(x.toShort()); buf.putShort(y.toShort())
        sendFastPathInput(buf.array().copyOf(buf.position()))
    }

    fun sendMouseScroll(x: Int, y: Int, delta: Int) {
        if (!connected) return
        val buf = ByteBuffer.allocate(7).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(0x10.toByte())
        buf.putShort((0x0200 or if (delta > 0) 0x0100 else 0x0000).toShort())
        buf.putShort(x.toShort()); buf.putShort(y.toShort())
        sendFastPathInput(buf.array().copyOf(buf.position()))
    }

    fun sendKeyEvent(scanCode: Int, down: Boolean, extended: Boolean = false) {
        if (!connected) return
        val eventFlags = (if (!down) 0x01 else 0x00) or (if (extended) 0x02 else 0x00)
        val eventHeader = ((0x01 shl 4) or eventFlags).toByte()
        val buf = ByteBuffer.allocate(2)
        buf.put(eventHeader); buf.put((scanCode and 0xFF).toByte())
        sendFastPathInput(buf.array().copyOf(buf.position()))
    }

    fun sendUnicodeKeyEvent(char: Char, down: Boolean) {
        if (!connected) return
        val eventFlags = if (!down) 0x01 else 0x00
        val eventHeader = ((0x04 shl 4) or eventFlags).toByte()
        val buf = ByteBuffer.allocate(3).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(eventHeader); buf.putShort(char.code.toShort())
        sendFastPathInput(buf.array().copyOf(buf.position()))
    }

    fun sendCtrlAltDel() {
        sendKeyEvent(0x1D, true)
        sendKeyEvent(0x38, true)
        sendKeyEvent(0x53, true,  extended = true)
        sendKeyEvent(0x53, false, extended = true)
        sendKeyEvent(0x38, false)
        sendKeyEvent(0x1D, false)
    }

    // ── I/O helpers ──────────────────────────────────────────────────────────

    private fun sendFastPathInput(data: ByteArray) {
        try {
            val header = ByteBuffer.allocate(4)
            header.put(0x10)
            writeFastPathLength(header, data.size + 2)
            val packet = header.array().copyOf(header.position()) + data
            synchronized(outputStream!!) { outputStream?.write(packet); outputStream?.flush() }
        } catch (e: Exception) { RdpLog.w("Failed to send input: ${e.message}") }
    }

    private fun writeFastPathLength(buf: ByteBuffer, length: Int) {
        if (length > 0x7F) buf.put((0x80 or (length shr 8)).toByte())
        buf.put((length and 0xFF).toByte())
    }

    private fun sendTpkt(data: ByteArray) {
        val x224Data = byteArrayOf(0x02, 0xF0.toByte(), 0x80.toByte()) + data
        val length = x224Data.size + 4
        val header = byteArrayOf(
            TPKT_VERSION.toByte(), 0x00,
            (length shr 8).toByte(), (length and 0xFF).toByte()
        )
        synchronized(outputStream!!) { outputStream?.write(header + x224Data); outputStream?.flush() }
    }

    private fun sendMcsSendDataRequest(data: ByteArray) {
        val header = ByteBuffer.allocate(6).order(ByteOrder.BIG_ENDIAN)
        header.put(0x64); header.putShort(mcsUserId.toShort())
        header.putShort(ioChannelId.toShort()); header.put(0x70)
        val lengthBytes = if (data.size < 0x80) byteArrayOf(data.size.toByte())
                          else byteArrayOf(
                              (0x80 or (data.size shr 8)).toByte(),
                              (data.size and 0xFF).toByte()
                          )
        sendTpkt(header.array() + lengthBytes + data)
    }

    private fun sendRaw(data: ByteArray) {
        synchronized(outputStream!!) { outputStream?.write(data); outputStream?.flush() }
    }

    private fun readRaw(): ByteArray? {
        return try {
            val tag = inputStream?.readUnsignedByte() ?: return null
            if (tag != 0x30) return null
            val firstLenByte = inputStream?.readUnsignedByte() ?: return null
            val (contentLength, lengthHeaderExtra) = when {
                firstLenByte < 0x80 -> firstLenByte to 0
                else -> {
                    val numBytes = firstLenByte and 0x7F
                    if (numBytes !in 1..4) return null
                    var len = 0
                    repeat(numBytes) { len = (len shl 8) or (inputStream?.readUnsignedByte() ?: return null) }
                    len to numBytes
                }
            }
            if (contentLength <= 0 || contentLength > 1_048_576) return null
            val content = ByteArray(contentLength)
            inputStream?.readFully(content)
            val header = if (lengthHeaderExtra == 0) byteArrayOf(0x30, firstLenByte.toByte())
            else {
                val lenBytes = ByteArray(lengthHeaderExtra)
                var rem = contentLength
                for (i in lengthHeaderExtra - 1 downTo 0) { lenBytes[i] = (rem and 0xFF).toByte(); rem = rem ushr 8 }
                byteArrayOf(0x30, firstLenByte.toByte()) + lenBytes
            }
            header + content
        } catch (e: Exception) { RdpLog.w("readRaw failed: ${e.message}"); null }
    }

    private fun readTpkt(): ByteArray? {
        return try {
            val header = ByteArray(4)
            inputStream?.readFully(header) ?: return null
            if ((header[0].toInt() and 0xFF) != TPKT_VERSION) {
                // Fast-path PDU
                val fpLen = if ((header[1].toInt() and 0x80) != 0)
                    ((header[1].toInt() and 0x7F) shl 8) or (header[2].toInt() and 0xFF)
                else header[1].toInt() and 0xFF
                val remaining = fpLen - 2
                if (remaining <= 0) return byteArrayOf(header[0])
                val data = ByteArray(remaining); inputStream?.readFully(data); return data
            }
            val length = ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
            val dataLength = length - 4
            if (dataLength <= 0) return ByteArray(0)
            val data = ByteArray(dataLength); inputStream?.readFully(data); data
        } catch (e: java.io.EOFException) {
            RdpLog.e("readTpkt: EOFException — server closed the connection (sent FIN) before any/enough bytes arrived: ${e.message}")
            null
        } catch (e: java.net.SocketTimeoutException) {
            RdpLog.e("readTpkt: SocketTimeoutException — no data arrived within ${READ_TIMEOUT_MS}ms (server went silent, did not close or respond): ${e.message}")
            null
        } catch (e: java.net.SocketException) {
            RdpLog.e("readTpkt: SocketException — connection reset/aborted: ${e.message}")
            null
        } catch (e: Exception) {
            RdpLog.e("readTpkt: unexpected ${e::class.java.simpleName}: ${e.message}", e)
            null
        }
    }

    private fun readX224Data(): ByteArray? {
        val data = readTpkt() ?: return null
        if (data.size >= 3 && (data[1].toInt() and 0xFF) == 0xF0) return data.copyOfRange(3, data.size)
        return data
    }

    private fun stripMcsSendDataIndication(data: ByteArray): ByteArray {
        if (data.size < 7) return data
        val opcode = (data[0].toInt() and 0xFF) ushr 2
        if (opcode != 26) return data
        var offset = 6
        val lenByte = data[offset].toInt() and 0xFF
        offset += if ((lenByte and 0x80) != 0) 2 else 1
        return if (offset <= data.size) data.copyOfRange(offset, data.size) else data
    }

    // ── Lifecycle ────────────────────────────────────────────────────────────

    fun disconnect() {
        connected = false
        clientScope.cancel()
        cleanup()
    }

    private fun cleanup() {
        try { outputStream?.close(); inputStream?.close(); socket?.close() }
        catch (e: Exception) { RdpLog.w("Cleanup error: ${e.message}") }
        socket = null; inputStream = null; outputStream = null
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

enum class RdpSessionState { DISCONNECTED, CONNECTING, CONNECTED, RECONNECTING, AUTH_FAILED, ERROR }
enum class MouseButton { LEFT, RIGHT, MIDDLE }

data class RdpFrameUpdate(
    val x: Int, val y: Int, val width: Int, val height: Int,
    val pixels: IntArray, val fullScreen: Boolean = false
)

class RdpException(message: String) : Exception(message)
class RdpAuthException(message: String) : Exception(message)
class RdpNegotiationFailure(val code: Int, message: String) : Exception(message)

class BandwidthDetector {
    private var lastBytes = 0L
    private var lastTime  = System.currentTimeMillis()
    fun recordBytes(bytes: Int) { lastBytes += bytes }
    fun getCurrentKbps(): Int {
        val now = System.currentTimeMillis()
        val elapsed = now - lastTime
        if (elapsed < 100) return 0
        val kbps = (lastBytes * 8 / elapsed).toInt()
        lastBytes = 0; lastTime = now
        return kbps
    }
}
