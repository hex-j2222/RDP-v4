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

// SUPPORTING TYPES
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
    private var lastTime = System.currentTimeMillis()
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


/**
 * Pure Kotlin RDP Protocol Client v5.2
 * Maximum compatibility: Windows XP/7/8/8.1/10/11, Server 2008-2022, xrdp/Linux
 *
 * FIXES v5.1 -> v5.2:
 * FIX-15: DomainParameters maxUserIds=64535 (was 65535)
 * FIX-16: GCC PER encoding rewritten to match FreeRDP
 * FIX-17: Client Core Data 216 bytes (RDP 4.0 compatible)
 * FIX-18: readTpkt/readX224Data handle Fast Path
 * FIX-19: X.224 CR with proper Cookie routingToken
 * FIX-20: clientNetworkData with cliprdr+rdpsnd channels
 * FIX-21: clientSecurityData always 12 bytes
 * FIX-22: MCS Connect Response lenient BER parsing
 * FIX-23: DomainParameters exact byte counts per FreeRDP
 * FIX-24: Client Info PDU correct flags
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

        const val PROTOCOL_RDP       = 0x00000000
        const val PROTOCOL_SSL       = 0x00000001
        const val PROTOCOL_HYBRID    = 0x00000002
        const val PROTOCOL_HYBRID_EX = 0x00000008

        const val PDU_TYPE_DEMAND_ACTIVE  = 0x11
        const val PDU_TYPE_CONFIRM_ACTIVE = 0x13
        const val PDU_TYPE_DATA           = 0x17

        const val PDUTYPE2_SYNCHRONIZE = 0x1F
        const val PDUTYPE2_CONTROL   = 0x14
        const val PDUTYPE2_FONTLIST  = 0x27
        const val PDUTYPE2_FONTMAP   = 0x28

        const val CTRLACTION_REQUEST_CONTROL = 0x0001
        const val CTRLACTION_GRANTED_CONTROL = 0x0002
        const val CTRLACTION_DETACH          = 0x0003
        const val CTRLACTION_COOPERATE       = 0x0004

        const val SEC_INFO_PKT     = 0x0040
        const val SEC_IGNORE_SEQNO = 0x0004

        const val TPKT_VERSION = 0x03

        const val RDP_VERSION_4_0  = 0x00080001
        const val RDP_VERSION_5_0  = 0x00080001
        const val RDP_VERSION_5_1  = 0x00080002
        const val RDP_VERSION_5_2  = 0x00080003
        const val RDP_VERSION_10_0 = 0x00080004
        const val RDP_VERSION_10_7 = 0x0008000D

        const val INFO_MOUSE             = 0x00000001
        const val INFO_DISABLECTRLALTDEL = 0x00000002
        const val INFO_AUTOLOGON         = 0x00000008
        const val INFO_UNICODE           = 0x00000040
        const val INFO_MAXIMIZESHELL     = 0x00000020
        const val INFO_LOGON_NOTIFY      = 0x00001000
        const val INFO_ENABLEWINDOWSKEY  = 0x00000100
        const val INFO_NOAUDIOPLAYBACK   = 0x00080000

        const val MCS_IO_CHANNEL_ID     = 1003
        const val MCS_USER_CHANNEL_BASE = 1001

        const val RNS_UD_COLOR_4BPP  = 0xCA00
        const val RNS_UD_COLOR_8BPP  = 0xCA01
        const val RNS_UD_COLOR_16BPP = 0xCA02
        const val RNS_UD_COLOR_24BPP = 0xCA03
        const val RNS_UD_COLOR_32BPP = 0xCA04
        const val RNS_UD_SAS_DEL     = 0xAA03

        const val ENCRYPTION_METHOD_40BIT  = 0x00000001
        const val ENCRYPTION_METHOD_128BIT = 0x00000002

        const val CHANNEL_CLIPRDR = "cliprdr"
        const val CHANNEL_RDPSND  = "rdpsnd"
        const val CHANNEL_RDPDR   = "rdpdr"
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

    private var negotiatedNla      = false
    private var negotiatedHybridEx = false
    private var serverSelectedProtocol: Int = 0
    private var negotiationPresent = false
    private var forceStandardRdpSecurity = false
    private var sslSocketRef: javax.net.ssl.SSLSocket? = null
    private var mcsUserId: Int = 0
    private val ioChannelId: Int = MCS_IO_CHANNEL_ID
    private var serverShareId: Int = 0x000103EA

    suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        RdpLog.clear()
        try {
            _sessionState.emit(RdpSessionState.CONNECTING)
            RdpLog.d("RDP v5.2 connecting to ${credentials.host}:${credentials.port}")

            val sock = Socket()
            sock.connect(InetSocketAddress(credentials.host, credentials.port), CONNECT_TIMEOUT_MS)
            sock.soTimeout = READ_TIMEOUT_MS
            sock.tcpNoDelay = true
            sock.setPerformancePreferences(0, 2, 1)

            socket = sock
            inputStream = DataInputStream(BufferedInputStream(sock.getInputStream(), 65536))
            outputStream = DataOutputStream(BufferedOutputStream(sock.getOutputStream(), 65536))

            RdpLog.d("STEP 1: TCP connected")

            sendX224ConnectionRequest()
            RdpLog.d("STEP 2: X.224 CR sent")

            try {
                if (!readX224ConnectionConfirm()) throw RdpException("X.224 connection rejected")
            } catch (e: RdpNegotiationFailure) {
                if (e.code == 2 && allowFallback) {
                    RdpLog.w("Server rejected TLS/NLA - retrying with Standard RDP Security", e)
                    cleanup()
                    val fellBack = connectWithoutNla()
                    if (fellBack) {
                        connected = true
                        RdpLog.d("STEP 10b: Connected via Standard RDP Security fallback")
                        _sessionState.emit(RdpSessionState.CONNECTED)
                        clientScope.launch { receiveLoop() }
                        return@withContext true
                    }
                    val fallbackMsg = "Server only supports legacy Standard RDP Security, and the fallback connection attempt also failed."
                    RdpLog.e(fallbackMsg)
                    throw RdpException(fallbackMsg)
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
                        val fallbackMsg = "NLA authentication failed (${e.message}), and fallback also failed."
                        RdpLog.e(fallbackMsg)
                        throw RdpAuthException(fallbackMsg)
                    }
                    val msg = "NLA authentication failed (${e.message})."
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
            inputStream = DataInputStream(BufferedInputStream(sock.getInputStream(), 65536))
            outputStream = DataOutputStream(BufferedOutputStream(sock.getOutputStream(), 65536))

            forceStandardRdpSecurity = true
            sendX224ConnectionRequest()
            RdpLog.d("FALLBACK STEP 1: X.224 CR sent (Standard RDP Security)")
            if (!readX224ConnectionConfirm()) { RdpLog.e("FALLBACK: X.224 connection rejected"); return false }
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

    // X.224 CONNECTION
    private fun sendX224ConnectionRequest() {
        val userHash = credentials.username.takeIf { it.isNotBlank() } ?: "user"
        val cookie = "Cookie: mstshash=$userHash\r\n"
        val cookieBytes = cookie.toByteArray(Charsets.US_ASCII)

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

        val x224CrFixed = 7
        val x224Length = x224CrFixed + cookieBytes.size + negReqBytes.size
        val tpktLength = 4 + 1 + x224Length

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
    }

    private fun readX224ConnectionConfirm(): Boolean {
        negotiatedNla = false
        negotiatedHybridEx = false
        serverSelectedProtocol = 0
        negotiationPresent = false

        val header = ByteArray(4)
        inputStream?.readFully(header) ?: return false
        if (header[0] != TPKT_VERSION.toByte()) return false

        val length = ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
        if (length < 4) return false
        val data = ByteArray(length - 4)
        inputStream?.readFully(data) ?: return false

        if (data.isEmpty() || (data[1].toInt() and 0xFF) != 0xD0) return false

        if (data.size >= 8) {
            val negType = data[7].toInt() and 0xFF
            when (negType) {
                0x02 -> {
                    negotiationPresent = true
                    val selected = ((data.getOrElse(14) { 0 }.toInt() and 0xFF) shl 24) or
                            ((data.getOrElse(13) { 0 }.toInt() and 0xFF) shl 16) or
                            ((data.getOrElse(12) { 0 }.toInt() and 0xFF) shl 8)  or
                            (data.getOrElse(11)  { 0 }.toInt() and 0xFF)
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
        1 -> "SSL_REQUIRED_BY_SERVER"
        2 -> "SSL_NOT_ALLOWED_BY_SERVER - disable Use NLA Authentication"
        3 -> "SSL_CERT_NOT_ON_SERVER"
        4 -> "INCONSISTENT_FLAGS"
        5 -> "HYBRID_REQUIRED_BY_SERVER - enable Use NLA Authentication"
        6 -> "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"
        else -> "Server rejected connection (RDP_NEG_FAILURE code $code)"
    }

    // TLS UPGRADE
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
        socket = sslSocket as Socket
        sslSocketRef = sslSocket
        inputStream  = DataInputStream(BufferedInputStream(sslSocket.getInputStream(), 65536))
        outputStream = DataOutputStream(BufferedOutputStream(sslSocket.getOutputStream(), 65536))
        RdpLog.d("TLS upgraded: ${sslSocket.session.protocol}")
    }

    // NLA / CredSSP
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
        pos++
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
            RdpLog.d("CredSSP v$serverVersion")
        }

        val serverPublicKey = serverPublicKeyDer()
        val authResult = NtlmHelper.buildAuthenticateMessage(
            username = credentials.username, password = credentials.password, domain = credentials.domain,
            challenge = challenge, negotiateMessage = negotiateMsg, challengeMessage = challengeMsg,
            serverSpn = "TERMSRV/${credentials.host}"
        )
        RdpLog.d("NLA: AUTHENTICATE built")

        val pubKeyAuthToken = CredSspHelper.computePubKeyAuth(serverPublicKey, authResult.encryptionState, 0)
        sendRaw(CredSspHelper.buildAuthenticateTsRequest(authResult.message, pubKeyAuthToken))
        RdpLog.d("NLA Step 3: AUTHENTICATE + pubKeyAuth sent")

        val pubKeyResponse = readRaw() ?: throw RdpAuthException("No pubKeyAuth response")
        CredSspHelper.extractErrorCode(pubKeyResponse)?.let { code ->
            throw RdpAuthException(CredSspHelper.describeErrorCode(code))
        }

        val encryptedServerConfirm = CredSspHelper.extractPubKeyAuth(pubKeyResponse)
            ?: throw RdpAuthException("Missing pubKeyAuth confirmation")

        val verified = CredSspHelper.verifyPubKeyAuthResponse(
            encryptedResponse = encryptedServerConfirm, serverPublicKey = serverPublicKey,
            encryptionState = authResult.encryptionState, sequenceNumber = 0
        )
        if (!verified) throw RdpAuthException("Server public key confirmation mismatch")
        RdpLog.d("Server pubKeyAuth verified")

        val tsCredentials = CredSspHelper.buildTsCredentials(credentials.domain, credentials.username, credentials.password)
        val encryptedCreds = NtlmHelper.encryptMessage(authResult.encryptionState, tsCredentials, 1)
        sendRaw(CredSspHelper.buildAuthInfoTsRequest(encryptedCreds))
        RdpLog.d("NLA Step 5: Encrypted credentials sent")
    }

    private fun handleEarlyUserAuthResult(): Boolean {
        return try {
            val buf = ByteArray(4)
            inputStream?.readFully(buf) ?: return true
            val result = ((buf[3].toInt() and 0xFF) shl 24) or
                         ((buf[2].toInt() and 0xFF) shl 16) or
                         ((buf[1].toInt() and 0xFF) shl 8)  or
                          (buf[0].toInt() and 0xFF)
            RdpLog.d("Early User Authorization Result: 0x${result.toString(16).padStart(8, '0')}")
            result == 0x00000000
        } catch (e: Exception) {
            RdpLog.w("Early User Auth Result handling failed: ${e.message}")
            true
        }
    }

    // MCS CONNECT INITIAL
    private fun sendMcsConnectInitial() = sendTpkt(buildMcsConnectInitialPayload())

    private fun buildMcsConnectInitialPayload(): ByteArray {
        val coreData    = buildClientCoreData()
        val secData     = buildClientSecurityData()
        val netData     = buildClientNetworkData()
        val clusterData = buildClientClusterData()
        val userData = coreData + secData + netData + clusterData
        return wrapInGccConferenceCreateRequest(userData)
    }

    private fun buildClientCoreData(): ByteArray {
        val buf = ByteBuffer.allocate(256).order(ByteOrder.LITTLE_ENDIAN)
        val rdpVersion = RDP_VERSION_5_0

        buf.putShort(0xC001.toShort())
        buf.putShort(216)

        buf.putInt(rdpVersion)
        buf.putShort(displayWidth.toShort())
        buf.putShort(displayHeight.toShort())
        buf.putShort(RNS_UD_COLOR_8BPP.toShort())
        buf.putShort(RNS_UD_SAS_DEL.toShort())
        buf.putInt(0x00000409)
        buf.putInt(2600)
        val clientName = "HEXRDP".padEnd(16, ' ')
        clientName.forEach { buf.putShort(it.code.toShort()) }
        buf.putInt(4)
        buf.putInt(0)
        buf.putInt(12)
        repeat(64) { buf.put(0) }
        buf.putShort(RNS_UD_COLOR_8BPP.toShort())
        buf.putShort(1)
        buf.putInt(0)
        buf.putShort(0x0018.toShort())
        buf.putShort(0x000F.toShort())
        buf.putShort(0x0001.toShort())
        repeat(64) { buf.put(0) }
        buf.put(0)
        buf.put(0)
        buf.putInt(serverSelectedProtocol)

        return buf.array().copyOf(216)
    }

    private fun buildClientSecurityData(): ByteArray {
        val buf = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0xC002.toShort())
        buf.putShort(12)
        val encryptionMethods = if (forceStandardRdpSecurity || serverSelectedProtocol == PROTOCOL_RDP) {
            ENCRYPTION_METHOD_40BIT or ENCRYPTION_METHOD_128BIT
        } else {
            0x00000000
        }
        buf.putInt(encryptionMethods)
        buf.putInt(0x00000000)
        return buf.array()
    }

    private fun buildClientNetworkData(): ByteArray {
        val channels = listOf(
            CHANNEL_CLIPRDR to 0xC0A00000,
            CHANNEL_RDPSND to 0xC0000000
        )
        val channelCount = channels.size
        val headerSize = 8
        val channelSize = 12
        val totalSize = headerSize + (channelCount * channelSize)

        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0xC003.toShort())
        buf.putShort(totalSize.toShort())
        buf.putInt(channelCount)

        for ((name, options) in channels) {
            val nameBytes = name.padEnd(8, ' ').toByteArray(Charsets.UTF_8)
            buf.put(nameBytes.copyOf(8))
            buf.putInt(options)
        }
        return buf.array()
    }

    private fun buildClientClusterData(): ByteArray {
        val buf = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0xC004.toShort())
        buf.putShort(12)
        buf.putInt(0x0000001C)
        buf.putInt(0)
        return buf.array()
    }

    // GCC CONFERENCE CREATE REQUEST (PER ENCODING)
    private fun wrapInGccConferenceCreateRequest(userData: ByteArray): ByteArray {
        val gccRequest = buildGccConferenceCreateRequest(userData)

        val targetParams  = buildDomainParameters(34, 2, 0, 1, 0, 1, 65535, 2)
        val minimumParams = buildDomainParameters(1, 1, 1, 1, 0, 1, 1056, 2)
        val maximumParams = buildDomainParameters(65535, 64535, 65535, 1, 0, 1, 65535, 2)

        val mcsBody = byteArrayOf(
            0x04, 0x01, 0x01,
            0x04, 0x01, 0x01,
            0x01, 0x01, 0xFF.toByte()
        ) + targetParams + minimumParams + maximumParams +
            byteArrayOf(0x04) + berLengthBytes(gccRequest.size) + gccRequest

        val out = ByteArrayOutputStream()
        out.write(0x7F)
        out.write(0x65)
        out.write(berLengthBytes(mcsBody.size))
        out.write(mcsBody)
        return out.toByteArray()
    }

    private fun buildGccConferenceCreateRequest(userData: ByteArray): ByteArray {
        val s = ByteArrayOutputStream()

        s.write(0x00)
        s.write(byteArrayOf(0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01))

        val conferenceLen = 14 + userData.size
        writePerLength(s, conferenceLen)

        s.write(0x00)
        s.write(0x08)

        s.write(0x01)
        s.write('1'.code)

        s.write(0x00)

        s.write(0x01)

        s.write(0xC0)

        s.write(byteArrayOf('D'.toByte(), 'u'.toByte(), 'c'.toByte(), 'a'.toByte()))

        writePerLength(s, userData.size)
        s.write(userData)

        return s.toByteArray()
    }

    private fun writePerLength(s: ByteArrayOutputStream, length: Int) {
        when {
            length < 128 -> s.write(length)
            length <= 255 -> {
                s.write(0x81)
                s.write(length)
            }
            else -> {
                s.write(0x82)
                s.write((length ushr 8) and 0xFF)
                s.write(length and 0xFF)
            }
        }
    }

    private fun buildDomainParameters(
        maxCh: Int, maxUs: Int, maxTok: Int,
        numPri: Int, minThr: Int, maxH: Int,
        maxPDU: Int, proto: Int
    ): ByteArray {
        val body = berIntegerMinimal(maxCh) +
                   berIntegerMinimal(maxUs) +
                   berIntegerMinimal(maxTok) +
                   berIntegerMinimal(numPri) +
                   berIntegerMinimal(minThr) +
                   berIntegerMinimal(maxH) +
                   berIntegerMinimal(maxPDU) +
                   berIntegerMinimal(proto)
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    private fun berIntegerMinimal(value: Int): ByteArray {
        return when {
            value == 0 -> byteArrayOf(0x02, 0x01, 0x00)
            value in 1..127 -> byteArrayOf(0x02, 0x01, value.toByte())
            value in 128..255 -> byteArrayOf(0x02, 0x02, 0x00, value.toByte())
            value in 256..65535 -> byteArrayOf(
                0x02, 0x02,
                (value ushr 8).toByte(),
                (value and 0xFF).toByte()
            )
            else -> byteArrayOf(
                0x02, 0x03,
                (value ushr 16).toByte(),
                ((value ushr 8) and 0xFF).toByte(),
                (value and 0xFF).toByte()
            )
        }
    }

    private fun berLengthBytes(length: Int): ByteArray = when {
        length < 0x80  -> byteArrayOf(length.toByte())
        length < 0x100 -> byteArrayOf(0x81.toByte(), length.toByte())
        else           -> byteArrayOf(0x82.toByte(), (length ushr 8).toByte(), (length and 0xFF).toByte())
    }

    // MCS CONNECT RESPONSE
    private fun readMcsConnectResponse(): Boolean {
        val packet = readX224Data()
        if (packet == null) {
            RdpLog.e("MCS Connect Response: no data received")
            return false
        }
        if (packet.isEmpty()) {
            RdpLog.e("MCS Connect Response: empty packet")
            return false
        }

        var pos = 0
        if (pos >= packet.size) return false

        val tag = packet[pos].toInt() and 0xFF
        when {
            tag == 0x7F -> {
                if (pos + 1 >= packet.size) return false
                val extTag = packet[pos + 1].toInt() and 0xFF
                if (extTag != 0x42) {
                    RdpLog.w("MCS CR: unexpected extTag=0x${extTag.toString(16)}")
                }
                pos += 2
            }
            tag == 0x30 || tag == 0x66 -> pos += 1
            else -> {
                val preview = packet.take(minOf(32, packet.size)).joinToString(" ") { "%02X".format(it) }
                RdpLog.e("MCS CR: unexpected tag=0x${tag.toString(16)} bytes=[$preview]")
            }
        }

        if (pos >= packet.size) return false
        val (mcsLen, lenBytes) = readBerLength(packet, pos)
        pos += lenBytes

        if (pos + 2 > packet.size) return false
        if (packet[pos].toInt() and 0xFF == 0x0A) {
            val resLen = packet[pos + 1].toInt() and 0xFF
            pos += 2 + resLen
        }

        if (pos + 2 <= packet.size && packet[pos].toInt() and 0xFF == 0x02) {
            val idLen = packet[pos + 1].toInt() and 0xFF
            pos += 2 + idLen
        }

        if (pos + 2 <= packet.size && packet[pos].toInt() and 0xFF == 0x30) {
            val dpLen = readBerLength(packet, pos).first
            val dpLenBytes = readBerLength(packet, pos).second
            pos += dpLenBytes + dpLen
        }

        if (pos + 2 <= packet.size && packet[pos].toInt() and 0xFF == 0x04) {
            pos++
            val (udLen, udLenBytes) = readBerLength(packet, pos)
            pos += udLenBytes
            RdpLog.d("MCS CR: GCC data at offset $pos, len=$udLen")
            if (pos + udLen <= packet.size) return true
        }

        RdpLog.d("MCS CR: parsed (lenient, pos=$pos)")
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
            first == 0x83 -> {
                if (offset + 3 >= data.size) return Pair(0, 0)
                val len = ((data[offset + 1].toInt() and 0xFF) shl 16) or
                          ((data[offset + 2].toInt() and 0xFF) shl 8) or
                          (data[offset + 3].toInt() and 0xFF)
                Pair(len, 4)
            }
            else -> Pair(0, 0)
        }
    }

    // MCS DOMAIN SETUP
    private fun performMcsDomainSetup() {
        sendTpkt(byteArrayOf(0x04, 0x01, 0x00, 0x01, 0x00))
        sendTpkt(byteArrayOf(0x28))

        val aucf = readX224Data() ?: throw RdpException("No Attach User Confirm")
        if (aucf.size < 4) throw RdpException("Malformed Attach User Confirm")
        val result = aucf[1].toInt() and 0xFF
        if (result != 0) throw RdpException("Attach User failed (result=$result)")
        mcsUserId = ((aucf[2].toInt() and 0xFF) shl 8) or (aucf[3].toInt() and 0xFF)
        RdpLog.d("MCS user ID: $mcsUserId")

        joinChannel(mcsUserId + MCS_USER_CHANNEL_BASE)
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

    // CLIENT INFO PDU
    private fun sendClientInfoPdu() {
        val domainBytes = (credentials.domain + " ").toByteArray(Charsets.UTF_16LE)
        val userBytes   = (credentials.username + " ").toByteArray(Charsets.UTF_16LE)
        val passBytes   = (credentials.password + " ").toByteArray(Charsets.UTF_16LE)
        val shellBytes  = " ".toByteArray(Charsets.UTF_16LE)
        val workBytes   = " ".toByteArray(Charsets.UTF_16LE)

        val infoPacketFlags = INFO_MOUSE or INFO_DISABLECTRLALTDEL or INFO_AUTOLOGON or
                INFO_MAXIMIZESHELL or INFO_UNICODE or INFO_ENABLEWINDOWSKEY or INFO_LOGON_NOTIFY

        val infoPacketSize = 4 + 4 + 2 + 2 + 2 + 2 + 2 +
                domainBytes.size + userBytes.size + passBytes.size + shellBytes.size + workBytes.size

        val secHeader = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
        secHeader.putShort(SEC_INFO_PKT.toShort()); secHeader.putShort(0)

        val infoBuf = ByteBuffer.allocate(infoPacketSize).order(ByteOrder.LITTLE_ENDIAN)
        infoBuf.putInt(0x00000000)
        infoBuf.putInt(infoPacketFlags)
        infoBuf.putShort((domainBytes.size - 2).toShort())
        infoBuf.putShort((userBytes.size - 2).toShort())
        infoBuf.putShort((passBytes.size - 2).toShort())
        infoBuf.putShort((shellBytes.size - 2).toShort())
        infoBuf.putShort((workBytes.size - 2).toShort())
        infoBuf.put(domainBytes); infoBuf.put(userBytes); infoBuf.put(passBytes)
        infoBuf.put(shellBytes); infoBuf.put(workBytes)

        val payload = secHeader.array() + infoBuf.array().copyOf(infoBuf.position())
        sendMcsSendDataRequest(payload)
    }

    // DEMAND ACTIVE + POST-CONNECTION
    private fun handleDemandActivePdu() {
        var foundDemandActive = false
        for (attempt in 0 until 10) {
            val raw = readX224Data() ?: break
            val payload = stripMcsSendDataIndication(raw)
            if (payload.size >= 6) {
                val pduType = payload[2].toInt() and 0xFF
                if (pduType == PDU_TYPE_DEMAND_ACTIVE) {
                    if (payload.size >= 10) {
                        serverShareId = ((payload[9].toInt() and 0xFF) shl 24) or
                                        ((payload[8].toInt() and 0xFF) shl 16) or
                                        ((payload[7].toInt() and 0xFF) shl 8) or
                                        (payload[6].toInt() and 0xFF)
                        RdpLog.d("Demand Active: shareId=0x${serverShareId.toString(16)}")
                    }
                    foundDemandActive = true; break
                }
            }
        }
        if (!foundDemandActive) {
            RdpLog.w("Demand Active PDU not found; using default shareId=0x${serverShareId.toString(16)}")
        }

        sendConfirmActivePdu(); RdpLog.d("PDU burst: Confirm Active sent")
        sendSynchronizePdu(); RdpLog.d("PDU burst: Synchronize sent")
        sendControlPdu(CTRLACTION_COOPERATE); RdpLog.d("PDU burst: Control COOPERATE sent")
        sendControlPdu(CTRLACTION_REQUEST_CONTROL); RdpLog.d("PDU burst: Control REQUEST_CONTROL sent")
        sendFontListPdu(); RdpLog.d("PDU burst: Font List sent")

        var drained = 0
        for (i in 0 until 8) {
            val raw = try { readX224Data() } catch (e: Exception) { null }
            if (raw == null) break
            val payload = stripMcsSendDataIndication(raw)
            if (payload.size >= 3) {
                val pduType = payload[2].toInt() and 0xFF
                RdpLog.d("Post-burst server PDU type=0x${pduType.toString(16)}")
                if (pduType == PDU_TYPE_DATA) { drained++; if (drained >= 4) break }
            }
        }
        RdpLog.d("Post-burst drain complete ($drained PDUs consumed)")
    }

    // CONFIRM ACTIVE PDU
    private fun sendConfirmActivePdu() {
        val caps = buildCapabilitySets()
        val srcDesc = byteArrayOf('R'.code.toByte(), 'D'.code.toByte(), 'P'.code.toByte(), 0x00)
        val srcDescLen = srcDesc.size.toShort()
        val numCaps = countCapabilitySets(caps).toShort()
        val combinedLen = (caps.size + 4).toShort()
        val totalLength = 6 + 4 + 2 + 2 + 2 + srcDesc.size + 2 + 2 + caps.size

        val buf = ByteBuffer.allocate(totalLength).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(totalLength.toShort())
        buf.putShort(PDU_TYPE_CONFIRM_ACTIVE.toShort())
        buf.putShort(0x03EA.toShort())
        buf.putInt(serverShareId)
        buf.putShort(0x03EA.toShort())
        buf.putShort(srcDescLen)
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
        buf.putInt(0); buf.putShort(1); buf.putShort(20); buf.putShort(0)
        buf.putShort(1); buf.putShort(0); buf.putShort(0x002F)
        repeat(32) { buf.put(0) }
        buf.putShort(0); buf.putShort(0x0040); buf.putInt(0)
        buf.putInt(230400); buf.putShort(0); buf.putShort(0); buf.putShort(0x0409); buf.putShort(0)

        // CAPSTYPE_BITMAPCACHE_REV2 (0x0013) — 40 bytes
        buf.putShort(0x0013); buf.putShort(40)
        buf.putShort(0x0003); buf.putShort(0); buf.put(3)
        buf.put(0); buf.put(0); buf.put(0)
        buf.putInt(600); buf.putInt(0x00000078); buf.putInt(0x00000078)
        repeat(16) { buf.put(0) }

        // CAPSTYPE_POINTER (0x0008) — 10 bytes
        buf.putShort(0x0008); buf.putShort(10)
        buf.putShort(1); buf.putShort(20); buf.putShort(20)

        // CAPSTYPE_INPUT (0x000D) — 88 bytes
        buf.putShort(0x000D); buf.putShort(88)
        buf.putShort(0x0008); buf.putShort(0)
        buf.putInt(0x00000409); buf.putInt(4); buf.putInt(0); buf.putInt(12)
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
        buf.putShort(0x000C); buf.putShort(8); buf.putShort(0); buf.putShort(0)

        // CAPSTYPE_SURFACE_COMMANDS (0x001D) — 8 bytes
        buf.putShort(0x001D); buf.putShort(8); buf.putInt(0x00000001)

        return buf.array().copyOf(buf.position())
    }

    // POST-CONNECTION PDUs
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

    // RECEIVE LOOP
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
                delay(100 * consecutiveErrors)
            }
        }
        cleanup()
    }

    private suspend fun processIncomingPdu(data: ByteArray) {
        if (data.isEmpty()) return
        val isMcsSdi = data.size >= 3 && (data[0].toInt() and 0xFF) == 0x02 && (data[1].toInt() and 0xFF) == 0xF0
        if (isMcsSdi) {
            val payload = stripMcsSendDataIndication(data.copyOfRange(3, data.size))
            if (payload.size >= 3) {
                val pduType = payload[2].toInt() and 0xFF
                when (pduType) {
                    PDU_TYPE_DEMAND_ACTIVE -> { RdpLog.d("Reactivation: new Demand Active"); handleDemandActivePdu() }
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
            bandwidthKbps < 100 -> RdpPerformance.LOW_BANDWIDTH
            bandwidthKbps < 500 -> RdpPerformance.MEDIUM
            bandwidthKbps < 2000 -> RdpPerformance.WIFI
            else -> RdpPerformance.LAN
        }
    }

    // INPUT HANDLING
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
            MouseButton.LEFT -> if (down) (0x1000 or 0x8000) else 0x1000
            MouseButton.RIGHT -> if (down) (0x2000 or 0x8000) else 0x2000
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
        sendKeyEvent(0x1D, true); sendKeyEvent(0x38, true)
        sendKeyEvent(0x53, true, extended = true)
        sendKeyEvent(0x53, false, extended = true)
        sendKeyEvent(0x38, false); sendKeyEvent(0x1D, false)
    }

    // I/O HELPERS
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
        val header = byteArrayOf(TPKT_VERSION.toByte(), 0x00, (length shr 8).toByte(), (length and 0xFF).toByte())
        synchronized(outputStream!!) { outputStream?.write(header + x224Data); outputStream?.flush() }
    }

    private fun sendMcsSendDataRequest(data: ByteArray) {
        val header = ByteBuffer.allocate(6).order(ByteOrder.BIG_ENDIAN)
        header.put(0x64); header.putShort(mcsUserId.toShort())
        header.putShort(ioChannelId.toShort()); header.put(0x70)
        val lengthBytes = if (data.size < 0x80) byteArrayOf(data.size.toByte())
            else byteArrayOf((0x80 or (data.size shr 8)).toByte(), (data.size and 0xFF).toByte())
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
            val content = ByteArray(contentLength); inputStream?.readFully(content)
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

    // FIX-18: readTpkt handles Fast Path packets (0x00-0x03)
    private fun readTpkt(): ByteArray? {
        return try {
            val firstByte = inputStream?.readUnsignedByte() ?: return null

            // Fast Path: first byte 0x00-0x03 (action code)
            if (firstByte in 0x00..0x03) {
                val secondByte = inputStream?.readUnsignedByte() ?: return null
                val fpLen = if ((secondByte and 0x80) != 0) {
                    val thirdByte = inputStream?.readUnsignedByte() ?: return null
                    ((secondByte and 0x7F) shl 8) or thirdByte
                } else {
                    secondByte
                }
                val remaining = fpLen - 2
                if (remaining <= 0) return byteArrayOf(firstByte.toByte())
                val data = ByteArray(remaining); inputStream?.readFully(data)
                return byteArrayOf(firstByte.toByte()) + data
            }

            // Standard TPKT
            if (firstByte != TPKT_VERSION) {
                RdpLog.w("readTpkt: unexpected first byte 0x${firstByte.toString(16)}")
                val rest = ByteArray(3); inputStream?.readFully(rest)
                val length = ((rest[1].toInt() and 0xFF) shl 8) or (rest[2].toInt() and 0xFF)
                val dataLength = length - 4
                if (dataLength <= 0) return ByteArray(0)
                val data = ByteArray(dataLength); inputStream?.readFully(data)
                return data
            }

            val headerRest = ByteArray(3); inputStream?.readFully(headerRest)
            val length = ((headerRest[1].toInt() and 0xFF) shl 8) or (headerRest[2].toInt() and 0xFF)
            val dataLength = length - 4
            if (dataLength <= 0) return ByteArray(0)
            val data = ByteArray(dataLength); inputStream?.readFully(data)
            data
        } catch (e: Exception) { RdpLog.w("readTpkt failed: ${e.message}"); null }
    }

    // FIX-18: readX224Data handles Fast Path and returns raw data on mismatch
    private fun readX224Data(): ByteArray? {
        val data = readTpkt() ?: return null
        if (data.size >= 3 && (data[1].toInt() and 0xFF) == 0xF0) {
            return data.copyOfRange(3, data.size)
        }
        // Not X.224 Data TPDU, return raw (might be Fast Path)
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

    // LIFECYCLE
    fun disconnect() {
        connected = false; clientScope.cancel(); cleanup()
    }

    private fun cleanup() {
        try { outputStream?.close(); inputStream?.close(); socket?.close() }
        catch (e: Exception) { RdpLog.w("Cleanup error: ${e.message}") }
        socket = null; inputStream = null; outputStream = null
    }
}

