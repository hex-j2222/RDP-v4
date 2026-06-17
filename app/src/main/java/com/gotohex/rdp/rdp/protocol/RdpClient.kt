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
 * FIXES APPLIED IN THIS REVISION (v4 → v4.1):
 *
 * FIX-A  sendClientInfoPdu(): Missing 4-byte TS_SECURITY_HEADER
 *         (SEC_INFO_PKT = 0x0040) that must precede TS_INFO_PACKET
 *         even over TLS/NLA sessions per MS-RDPBCGR §5.4.5.
 *         Without it Windows Server 2012+ misparses the PDU, treating
 *         CodePage (0x00000000) as the security header and silently
 *         dropping the packet, leaving the connection to hang.
 *         Also corrected flags: added INFO_AUTOLOGON (0x0008) and
 *         INFO_LOGON_NOTIFY (0x1000) which are required for proper
 *         credential injection over NLA sessions.
 *
 * FIX-B  sendConfirmActivePdu(): Malformed PDU layout.
 *         TS_CONFIRM_ACTIVE_PDU (MS-RDPBCGR 2.2.1.13.2) requires,
 *         after the Share Control Header:
 *           shareId (4), originatorId (2), lengthSourceDescriptor (2),
 *           lengthCombinedCapabilities (2), sourceDescriptor ("RDP\0"),
 *           numberCapabilities (2), pad2Octets (2), then caps.
 *         The previous code skipped lengthSourceDescriptor,
 *         lengthCombinedCapabilities, sourceDescriptor, numberCapabilities,
 *         and pad2Octets entirely. Windows servers validate all of these;
 *         any mismatch causes an immediate disconnect.
 *         Also: totalLength in the Share Control Header was off by the
 *         missing fields (16 bytes short).
 *
 * FIX-C  shareId: Was hardcoded as 0x000103EA.
 *         The shareId is assigned by the server in its Demand Active PDU
 *         (TS_DEMAND_ACTIVE_PDU field shareId). It is almost always
 *         0x000103EA in practice but the spec allows any value, and
 *         the Confirm Active PDU MUST echo the server's value exactly.
 *         Now parsed and stored in serverShareId.
 *
 * FIX-D  sendSyncPdu() / sendControlPdu() / sendFontListPdu():
 *         Previously sent 4 meaningless raw bytes each with NO Share
 *         Control Header and NO Share Data Header. Replaced with proper
 *         PDU construction per MS-RDPBCGR:
 *         - Synchronize PDU  (2.2.1.14): pduType=DATAPDU, pduType2=RDP_UPDATE_SYNCHRONIZE
 *         - Control PDU COOPERATE (2.2.1.15): action=CTRLACTION_COOPERATE (4)
 *         - Control PDU REQUEST_CONTROL (2.2.1.15): action=CTRLACTION_REQUEST_CONTROL (1)
 *         - Font List PDU (2.2.1.18): listFlags=0x0003, entrySize=0x0032
 *         Each PDU needs a 6-byte Share Control Header + 18-byte Share
 *         Data Header before the PDU-specific payload.
 *
 * FIX-E  buildCapabilitySets(): Bitmap Codecs capability (0x001E) was
 *         malformed — wrote 2 bytes (0x0001) as a codec GUID which is
 *         16 bytes. Removed the broken Bitmap Codecs and Frame Marker
 *         caps for now; they caused Windows to reject the entire
 *         Confirm Active PDU. Surface Commands kept (it is safe).
 *
 * FIX-F  handleDemandActivePdu(): Now parses the server's shareId from
 *         the Demand Active PDU, and after sending the PDU burst
 *         (Confirm Active + Sync + Control x2 + Font List) drains the
 *         5 server-initiated PDUs that follow (Sync, Control Cooperate,
 *         Control Granted, Font Map, and optionally Monitor Layout).
 *         Skipping these caused the receiveLoop to see stale data and
 *         immediately report an error.
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
        const val PROTOCOL_RDP      = 0x00000000
        const val PROTOCOL_SSL      = 0x00000001
        const val PROTOCOL_HYBRID   = 0x00000002
        const val PROTOCOL_HYBRID_EX = 0x00000008

        // PDU type nibbles (lower 4 bits of pduType field in Share Control Header)
        const val PDU_TYPE_DEMAND_ACTIVE  = 0x11   // 0x01 | version=1<<4
        const val PDU_TYPE_CONFIRM_ACTIVE = 0x13   // 0x03 | version=1<<4
        const val PDU_TYPE_DATA           = 0x17   // 0x07 | version=1<<4

        // PDU type 2 (Share Data Header pduType2)
        const val PDUTYPE2_SYNCHRONIZE       = 0x1F
        const val PDUTYPE2_CONTROL           = 0x14
        const val PDUTYPE2_FONTLIST          = 0x27
        const val PDUTYPE2_FONTMAP           = 0x28   // server→client

        // Control actions
        const val CTRLACTION_REQUEST_CONTROL = 0x0001
        const val CTRLACTION_GRANTED_CONTROL = 0x0002
        const val CTRLACTION_DETACH          = 0x0003
        const val CTRLACTION_COOPERATE       = 0x0004

        // TS_SECURITY_HEADER flags (MS-RDPBCGR §2.2.8.1.1.2.1)
        const val SEC_INFO_PKT       = 0x0040
        const val SEC_IGNORE_SEQNO   = 0x0004

        // TPKT
        const val TPKT_VERSION = 0x03

        // RDP version constants
        const val RDP_VERSION_8_0 = 0x00080004
        const val RDP_VERSION_8_1 = 0x00080005

        // TS_INFO_PACKET flags (MS-RDPBCGR §2.2.1.11.1.1)
        const val INFO_MOUSE            = 0x00000001
        const val INFO_DISABLECTRLALTDEL = 0x00000002
        const val INFO_AUTOLOGON        = 0x00000008
        const val INFO_UNICODE          = 0x00000040
        const val INFO_MAXIMIZESHELL    = 0x00000020
        const val INFO_LOGON_NOTIFY     = 0x00001000
        const val INFO_ENABLEWINDOWSKEY = 0x00000100
        const val INFO_NOAUDIOPLAYBACK  = 0x00080000

        // Fixed MCS channel IDs used by all known servers
        const val MCS_IO_CHANNEL_ID     = 1003
        const val MCS_USER_BASE         = 1001
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
    private var negotiatedNla      = false
    private var negotiatedHybridEx = false
    private var serverSelectedProtocol: Int = 0
    private var negotiationPresent = false
    private var forceStandardRdpSecurity = false
    private var sslSocketRef: javax.net.ssl.SSLSocket? = null
    private var mcsUserId: Int = 0
    private val ioChannelId: Int = MCS_IO_CHANNEL_ID

    // FIX-C: shareId must be parsed from server's Demand Active PDU
    private var serverShareId: Int = 0x000103EA

    // ── connect() ──────────────────────────────────────────────────────────

    suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        try {
            _sessionState.emit(RdpSessionState.CONNECTING)
            Log.d(TAG, "Connecting to ${credentials.host}:${credentials.port}")

            val sock = Socket()
            sock.connect(InetSocketAddress(credentials.host, credentials.port), CONNECT_TIMEOUT_MS)
            sock.soTimeout = READ_TIMEOUT_MS
            sock.tcpNoDelay = true
            sock.setPerformancePreferences(0, 2, 1)

            socket = sock
            inputStream = DataInputStream(BufferedInputStream(sock.getInputStream(), 65536))
            outputStream = DataOutputStream(BufferedOutputStream(sock.getOutputStream(), 65536))

            Log.d(TAG, "STEP 1: TCP connected")

            sendX224ConnectionRequest()
            Log.d(TAG, "STEP 2: X.224 CR sent")

            if (!readX224ConnectionConfirm()) throw RdpException("X.224 connection rejected")
            Log.d(TAG, "STEP 3: X.224 CC (selected=0x${serverSelectedProtocol.toString(16)}, NLA=$negotiatedNla, HybridEX=$negotiatedHybridEx)")

            if (negotiationPresent && serverSelectedProtocol != PROTOCOL_RDP) {
                upgradeTls()
                Log.d(TAG, "STEP 4: TLS upgraded")
            } else {
                Log.d(TAG, "STEP 4: Skipped TLS (Standard RDP Security or pre-negotiation server)")
            }

            if (negotiatedHybridEx) {
                if (!handleEarlyUserAuthResult()) throw RdpAuthException("Early user authorization failed")
                Log.d(TAG, "STEP 4a: Early User Auth Result handled")
            }

            if (negotiatedNla || negotiatedHybridEx) {
                try {
                    performNlaAuthentication()
                    Log.d(TAG, "STEP 5: NLA complete")
                } catch (e: Exception) {
                    Log.w(TAG, "NLA failed: ${e.message}")
                    val looksLikeBadCredentials = e is RdpAuthException &&
                        (e.message?.contains("LOGON_FAILURE") == true ||
                         e.message?.contains("ACCOUNT_DISABLED") == true ||
                         e.message?.contains("ACCOUNT_LOCKED_OUT") == true ||
                         e.message?.contains("PASSWORD_EXPIRED") == true)

                    if (allowFallback && !looksLikeBadCredentials) {
                        Log.w(TAG, "Attempting fallback to Standard RDP Security (NLA disabled)")
                        cleanup()
                        val fellBack = connectWithoutNla()
                        if (fellBack) {
                            connected = true
                            _sessionState.emit(RdpSessionState.CONNECTED)
                            clientScope.launch { receiveLoop() }
                            return@withContext true
                        }
                        throw RdpAuthException(
                            "NLA authentication failed (${e.message}), and fallback to Standard RDP " +
                            "Security also failed. Try disabling 'Use NLA Authentication' in the profile."
                        )
                    }
                    throw RdpAuthException("NLA authentication failed (${e.message}). Try disabling 'Use NLA Authentication'.")
                }
            }

            sendMcsConnectInitial()
            Log.d(TAG, "STEP 6: MCS Connect Initial sent")

            if (!readMcsConnectResponse()) throw RdpException("MCS connection failed")
            Log.d(TAG, "STEP 7: MCS Connect Response received")

            performMcsDomainSetup()
            Log.d(TAG, "STEP 8: MCS Domain Setup complete (userId=$mcsUserId)")

            sendClientInfoPdu()
            Log.d(TAG, "STEP 9: Client Info sent")

            handleDemandActivePdu()
            Log.d(TAG, "STEP 10: Demand Active + post-connection sequence complete")

            connected = true
            _sessionState.emit(RdpSessionState.CONNECTED)
            clientScope.launch { receiveLoop() }
            true

        } catch (e: RdpAuthException) {
            Log.e(TAG, "Auth failed: ${e.message}")
            _sessionState.emit(RdpSessionState.AUTH_FAILED)
            _error.emit("Authentication failed: ${e.message}")
            cleanup()
            false
        } catch (e: Exception) {
            Log.e(TAG, "Connection failed: ${e.message}", e)
            _sessionState.emit(RdpSessionState.ERROR)
            _error.emit("Connection failed: ${e.message ?: "Unknown error"}")
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
            if (!readX224ConnectionConfirm()) return false

            if (negotiationPresent && serverSelectedProtocol != PROTOCOL_RDP) upgradeTls()

            sendMcsConnectInitial()
            if (!readMcsConnectResponse()) return false
            performMcsDomainSetup()
            sendClientInfoPdu()
            handleDemandActivePdu()
            true
        } catch (e: Exception) {
            Log.w(TAG, "Fallback connection failed: ${e.message}")
            false
        }
    }

    // ── X.224 ──────────────────────────────────────────────────────────────

    private fun sendX224ConnectionRequest() {
        val cookie = "Cookie: mstshash=user\r\n"
        val cookieBytes = cookie.toByteArray()

        val requestedProtocols = when {
            forceStandardRdpSecurity -> PROTOCOL_SSL
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
        Log.d(TAG, "X.224 CR sent, length=$tpktLength, proto=0x${requestedProtocols.toString(16)}")
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
                    Log.d(TAG, "Server selected: 0x${selected.toString(16)} (NLA=$negotiatedNla, HybridEX=$negotiatedHybridEx)")
                }
                0x03 -> {
                    negotiationPresent = true
                    val failureCode = data.getOrElse(11) { 0 }.toInt() and 0xFF
                    throw RdpException(describeNegFailure(failureCode))
                }
                else -> Log.w(TAG, "Unrecognized X.224 negotiation type: 0x${negType.toString(16)}")
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
        else -> "Server rejected the connection (RDP_NEG_FAILURE code $code, see MS-RDPBCGR 2.2.1.2.2)"
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
        socket = sslSocket as Socket
        sslSocketRef = sslSocket
        inputStream  = DataInputStream(BufferedInputStream(sslSocket.getInputStream(), 65536))
        outputStream = DataOutputStream(BufferedOutputStream(sslSocket.getOutputStream(), 65536))
        Log.d(TAG, "TLS upgraded: ${sslSocket.session.protocol}")
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
        Log.d(TAG, "Starting CredSSP/NTLMv2 auth")

        val negotiateMsg = NtlmHelper.buildNegotiateMessage(credentials.domain)
        sendRaw(CredSspHelper.buildNegotiateTsRequest(negotiateMsg))
        Log.d(TAG, "NLA Step 1: NEGOTIATE sent")

        val challengeRequest = readRaw() ?: throw RdpAuthException("No CredSSP CHALLENGE response")
        CredSspHelper.extractErrorCode(challengeRequest)?.let { code ->
            throw RdpAuthException("Server rejected NLA negotiation: ${CredSspHelper.describeErrorCode(code)}")
        }

        val challengeMsg = CredSspHelper.extractNegoToken(challengeRequest)
            ?: throw RdpAuthException("Missing NTLM CHALLENGE token")
        val challenge = NtlmHelper.parseChallengeMessage(challengeMsg)
        Log.d(TAG, "NLA Step 2: CHALLENGE received")

        val serverVersion = CredSspHelper.extractVersion(challengeRequest)
        if (serverVersion >= 5) {
            CredSspHelper.negotiatedCredSspVersion = serverVersion
            Log.d(TAG, "CredSSP v$serverVersion (SHA256 mode, Windows 8+)")
        }

        val serverPublicKey = serverPublicKeyDer()

        val authResult = NtlmHelper.buildAuthenticateMessage(
            username = credentials.username,
            password = credentials.password,
            domain = credentials.domain,
            challenge = challenge,
            negotiateMessage = negotiateMsg,
            challengeMessage = challengeMsg,
            serverSpn = "TERMSRV/${credentials.host}"  // FIX-M: Required for Windows 2019+ SPN enforcement
        )
        Log.d(TAG, "NLA: AUTHENTICATE built")

        val pubKeyAuthToken = CredSspHelper.computePubKeyAuth(serverPublicKey, authResult.encryptionState, 0)
        sendRaw(CredSspHelper.buildAuthenticateTsRequest(authResult.message, pubKeyAuthToken))
        Log.d(TAG, "NLA Step 3: AUTHENTICATE + pubKeyAuth sent")

        val pubKeyResponse = readRaw() ?: throw RdpAuthException(
            "No pubKeyAuth response – server closed the connection after credentials were sent " +
            "(wrong username/password, or NLA not actually enabled on the server)"
        )
        CredSspHelper.extractErrorCode(pubKeyResponse)?.let { code ->
            throw RdpAuthException(CredSspHelper.describeErrorCode(code))
        }

        val encryptedServerConfirm = CredSspHelper.extractPubKeyAuth(pubKeyResponse)
            ?: throw RdpAuthException("Missing pubKeyAuth confirmation")

        val verified = CredSspHelper.verifyPubKeyAuthResponse(
            encryptedResponse = encryptedServerConfirm,
            serverPublicKey = serverPublicKey,
            encryptionState = authResult.encryptionState,
            sequenceNumber = 0
        )
        if (!verified) throw RdpAuthException("Server public key confirmation mismatch")
        Log.d(TAG, "Server pubKeyAuth verified")

        val tsCredentials = CredSspHelper.buildTsCredentials(credentials.domain, credentials.username, credentials.password)
        val encryptedCreds = NtlmHelper.encryptMessage(authResult.encryptionState, tsCredentials, 1)
        sendRaw(CredSspHelper.buildAuthInfoTsRequest(encryptedCreds))
        Log.d(TAG, "NLA Step 5: Encrypted credentials sent – CredSSP complete")
    }

    /**
     * BUG-8 FIX: Early User Authorization Result (MS-RDPBCGR 2.2.1.2.3) is a
     * raw 4-byte little-endian DWORD, NOT an ASN.1 structure.
     * Previous code used readRaw() which expects a 0x30 ASN.1 tag — the server
     * sends 0x00 (first byte of ACCESS_PERMITTED=0), causing readRaw() to
     * return null → handleEarlyUserAuthResult() returned false → connection
     * immediately threw RdpAuthException even with correct credentials.
     *   0x00000000 = ACCESS_PERMITTED
     *   0x00000002 = ACCESS_DENIED
     *   0x00000006 = ACCESS_DENIED_FIPS
     */
    private fun handleEarlyUserAuthResult(): Boolean {
        return try {
            val buf = ByteArray(4)
            inputStream?.readFully(buf) ?: return true  // unreadable = assume permitted
            val result = ((buf[3].toInt() and 0xFF) shl 24) or
                         ((buf[2].toInt() and 0xFF) shl 16) or
                         ((buf[1].toInt() and 0xFF) shl 8)  or
                          (buf[0].toInt() and 0xFF)
            Log.d(TAG, "Early User Authorization Result: 0x${result.toString(16).padStart(8, '0')}")
            result == 0x00000000  // only ACCESS_PERMITTED is success
        } catch (e: Exception) {
            Log.w(TAG, "Early User Auth Result handling failed: ${e.message}")
            true  // if we can't read it, assume permitted and continue
        }
    }

    // ── MCS ────────────────────────────────────────────────────────────────

    private fun sendMcsConnectInitial() = sendTpkt(buildMcsConnectInitialPayload())

    private fun buildMcsConnectInitialPayload(): ByteArray {
        val coreData    = buildClientCoreData()
        val secData     = buildClientSecurityData()
        val netData     = buildClientNetworkData()
        val clusterData = buildClientClusterData()
        return wrapInGccConferenceCreateRequest(coreData + secData + netData + clusterData)
    }

    /**
     * TS_UD_CS_CORE (MS-RDPBCGR 2.2.1.3.2) — 216 bytes, little-endian.
     * Field layout is now exact per spec (FIX in v4, still correct here).
     */
    private fun buildClientCoreData(): ByteArray {
        val buf = ByteBuffer.allocate(216).order(ByteOrder.LITTLE_ENDIAN)
        val rdpVersion = if (serverSelectedProtocol and PROTOCOL_HYBRID_EX != 0) RDP_VERSION_8_1 else RDP_VERSION_8_0

        buf.putShort(0xC001.toShort())        // header.type = CS_CORE
        buf.putShort(216)                     // header.length
        buf.putInt(rdpVersion)
        buf.putShort(displayWidth.toShort())
        buf.putShort(displayHeight.toShort())
        buf.putShort(0xCA01.toShort())        // colorDepth (legacy)
        buf.putShort(0xAA03.toShort())        // SASSequence
        buf.putInt(0x00000409)                // keyboardLayout (EN-US)
        buf.putInt(2600)                      // clientBuild
        val clientName = "HEXRDP".padEnd(16, '\u0000')
        clientName.forEach { buf.putShort(it.code.toShort()) }  // 32 bytes UTF-16LE
        buf.putInt(4)                         // keyboardType
        buf.putInt(0)                         // keyboardSubType
        buf.putInt(12)                        // keyboardFunctionKey
        repeat(64) { buf.put(0) }             // imeFileName
        buf.putShort(0xCA01.toShort())        // postBeta2ColorDepth
        buf.putShort(1)                       // clientProductId
        buf.putInt(0)                         // serialNumber
        buf.putShort(0x0018.toShort())        // highColorDepth = 24 bpp
        buf.putShort(0x000F.toShort())        // supportedColorDepths
        buf.putShort(0x0001.toShort())        // earlyCapabilityFlags
        repeat(64) { buf.put(0) }             // clientDigProductId
        buf.put(0)                            // connectionType
        buf.put(0)                            // pad1octet
        buf.putInt(serverSelectedProtocol)    // CRITICAL: must echo server's choice
        return buf.array().copyOf(buf.position())
    }

    private fun buildClientSecurityData(): ByteArray {
        val buf = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0xC002.toShort()); buf.putShort(12)
        buf.putInt(0x00000003); buf.putInt(0x00000000)
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
        buf.putInt(0x0000001C)   // REDIRECTION_SUPPORTED | REDIRECTION_VERSION3
        buf.putInt(0)
        return buf.array()
    }

    /**
     * BUG-7 FIX: Complete rewrite of MCS Connect Initial + GCC wrapping.
     *
     * Previous code had THREE fatal bugs:
     *   7a) MCS Connect Initial tag was 0x65 alone — MUST be 0x7F 0x65
     *       (T.125 BER Application class, constructed, tag 101).
     *   7b) Each DomainParameters SEQUENCE was 0x30 0x00 (empty).
     *       Must be 0x30 0x1E + 30 bytes of BER INTEGERs per T.125 §11.1.
     *   7c) The inner "GCC" dos was actually building a second MCS wrapper
     *       with the wrong tag, resulting in double-wrapped garbage.
     *       The correct GCC Conference Create Request payload is:
     *         T.124 key (7 bytes) + PER-encoded ConferenceCreateRequest header
     *         + H221 "Duca" NonStandard key + userData.
     *
     * Correct structure (per MS-RDPBCGR 2.2.1.3, T.124, T.125, FreeRDP gcc.c):
     *
     *   0x7F 0x65 <BER-length>          ← MCS Connect Initial
     *     04 01 01                       ← callingDomainSelector
     *     04 01 01                       ← calledDomainSelector
     *     01 01 FF                       ← upwardFlag = TRUE
     *     [targetParameters  – 32 bytes] ← SEQUENCE of 8 BER INTEGERs
     *     [minimumParameters – 32 bytes]
     *     [maximumParameters – 32 bytes]
     *     04 <BER-length>                ← userData OCTET STRING
     *       00 05 00 14 7C 00 01         ← T.124 ConnectData key (PER OID)
     *       00 08 <len-2B-BE>            ← conferenceCreateRequest CHOICE + PER length
     *       00 01 C0 00                  ← fixed ConferenceCreateRequest PER fields
     *       44 75 63 61                  ← H221 NonStandard key "Duca"
     *       <userDataLen-2B-LE>          ← CS_* blocks length (little-endian)
     *       [userData]                   ← CS_CORE + CS_SECURITY + CS_NET + CS_CLUSTER
     */
    private fun wrapInGccConferenceCreateRequest(userData: ByteArray): ByteArray {
        // === GCC Conference Create Request payload (T.124 PER) ===
        // Bytes after T.124 key: CHOICE(0) + ConferenceCreateRequest in PER
        // remaining = bytes after the 2-byte PER length field to end
        val remaining = 4 + 4 + 2 + userData.size  // 00 01 C0 00 + "Duca" + len(2) + userData
        val gccConferenceHeader = byteArrayOf(
            0x00, 0x08,                                         // conferenceCreateRequest CHOICE
            (remaining ushr 8).toByte(), (remaining and 0xFF).toByte(), // PER length (big-endian)
            0x00, 0x01, 0xC0.toByte(), 0x00,                   // ConferenceCreateRequest fixed fields
            0x44, 0x75, 0x63, 0x61,                            // H221 NonStandard key = "Duca"
            (userData.size and 0xFF).toByte(), (userData.size ushr 8).toByte() // userData length (little-endian)
        )
        val t124Key = byteArrayOf(0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01)
        val gccPayload = t124Key + gccConferenceHeader + userData

        // === DomainParameters (T.125 BER SEQUENCE of 8 INTEGERs) ===
        val targetParams  = buildDomainParameters(34,    2,     0,     1, 0, 1, 65535, 2)
        val minimumParams = buildDomainParameters(1,     1,     1,     1, 0, 1, 512,   2)
        val maximumParams = buildDomainParameters(65535, 64535, 65535, 1, 0, 1, 65535, 2)

        // === MCS Connect Initial body ===
        val mcsBody = byteArrayOf(
            0x04, 0x01, 0x01,        // callingDomainSelector: OCTET STRING length=1, value=1
            0x04, 0x01, 0x01,        // calledDomainSelector:  OCTET STRING length=1, value=1
            0x01, 0x01, 0xFF.toByte()  // upwardFlag: BOOLEAN = TRUE
        ) + targetParams + minimumParams + maximumParams +
            byteArrayOf(0x04) + berLengthBytes(gccPayload.size) + gccPayload

        // === MCS Connect Initial outer wrapper ===
        val out = ByteArrayOutputStream()
        out.write(0x7F); out.write(0x65)                       // APPLICATION 101, constructed
        out.write(berLengthBytes(mcsBody.size))
        out.write(mcsBody)
        return out.toByteArray()
    }

    /**
     * Build a T.125 DomainParameters SEQUENCE (BER).
     * Per T.125 §11.1 / MS-RDPBCGR 2.2.1.3.1 DomainParameters:
     *   maxChannelIds(2) maxUserIds(2) maxTokenIds(2) numPriorities(1)
     *   minThroughput(1) maxHeight(1) maxMCSPDUsize(4) protocolVersion(1)
     */
    private fun buildDomainParameters(
        maxCh: Int, maxUs: Int, maxTok: Int, numPri: Int,
        minThr: Int, maxH: Int, maxPDU: Int, proto: Int
    ): ByteArray {
        val body = berInteger(maxCh, 2) + berInteger(maxUs, 2) + berInteger(maxTok, 2) +
                   berInteger(numPri, 1) + berInteger(minThr, 1) + berInteger(maxH, 1) +
                   berInteger(maxPDU, 4) + berInteger(proto, 1)
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    private fun berInteger(value: Int, byteLen: Int): ByteArray {
        val data = ByteArray(byteLen)
        for (i in byteLen - 1 downTo 0) data[i] = (value ushr ((byteLen - 1 - i) * 8)).toByte()
        return byteArrayOf(0x02, byteLen.toByte()) + data
    }

    private fun berLengthBytes(length: Int): ByteArray = when {
        length < 0x80  -> byteArrayOf(length.toByte())
        length < 0x100 -> byteArrayOf(0x81.toByte(), length.toByte())
        else           -> byteArrayOf(0x82.toByte(), (length ushr 8).toByte(), (length and 0xFF).toByte())
    }

    private fun readMcsConnectResponse(): Boolean {
        val packet = readX224Data() ?: return false
        if (packet.isEmpty()) return false
        val tag = packet[0].toInt() and 0xFF
        return tag == 0x7F || tag == 0x30 || tag == 0x65 || tag == 0x66
    }

    private fun performMcsDomainSetup() {
        sendTpkt(byteArrayOf(0x04, 0x01, 0x00, 0x01, 0x00))  // ErectDomainRequest
        sendTpkt(byteArrayOf(0x28))                            // AttachUserRequest

        val aucf = readX224Data() ?: throw RdpException("No Attach User Confirm")
        if (aucf.size < 4) throw RdpException("Malformed Attach User Confirm")
        val result = aucf[1].toInt() and 0xFF
        if (result != 0) throw RdpException("Attach User failed (result=$result)")
        mcsUserId = ((aucf[2].toInt() and 0xFF) shl 8) or (aucf[3].toInt() and 0xFF)
        Log.d(TAG, "MCS user ID: $mcsUserId")

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

    /**
     * FIX-A: prepend TS_SECURITY_HEADER (SEC_INFO_PKT = 0x0040) before the
     * TS_INFO_PACKET. Per MS-RDPBCGR §5.4.5 this 4-byte header is REQUIRED
     * even on TLS/NLA connections (the data just isn't encrypted). Without it
     * Windows Server 2012+ sees CodePage (0x00000000) as the security header,
     * finds no SEC_INFO_PKT flag, and discards the PDU silently, leaving the
     * client waiting forever for a Demand Active that never comes.
     *
     * FIX-A2: corrected infoPacketFlags. The comment previously said
     * "INFO_UNICODE|LOGON_NOTIFY|LOGON_ERRORS|NOAUDIOPLAYBACK" but the
     * value 0x53 set none of those (it set INFO_MOUSE|DISABLECTRLALTDEL|
     * MAXIMIZESHELL|UNICODE). Added INFO_AUTOLOGON (0x0008) so the server
     * accepts the username/password carried in this PDU, and INFO_LOGON_NOTIFY
     * (0x1000) so the server fires logon-notification events.
     */
    private fun sendClientInfoPdu() {
        val domainBytes = (credentials.domain + "\u0000").toByteArray(Charsets.UTF_16LE)
        val userBytes   = (credentials.username + "\u0000").toByteArray(Charsets.UTF_16LE)
        val passBytes   = (credentials.password + "\u0000").toByteArray(Charsets.UTF_16LE)
        val shellBytes  = "\u0000".toByteArray(Charsets.UTF_16LE)
        val workBytes   = "\u0000".toByteArray(Charsets.UTF_16LE)

        val infoPacketFlags = INFO_MOUSE or
                INFO_DISABLECTRLALTDEL or
                INFO_AUTOLOGON or         // FIX-A2: was missing
                INFO_MAXIMIZESHELL or
                INFO_UNICODE or
                INFO_ENABLEWINDOWSKEY or
                INFO_LOGON_NOTIFY          // FIX-A2: was missing

        // FIX-I: The 2-byte "pad" field after the 5 length fields was counted in
        // infoPacketSize but never written to infoBuf, causing a 2-byte buffer
        // underrun that left the credentials misaligned and got silently dropped
        // by the server.  Removed the pad from the size; the size must match
        // exactly what is actually written below.
        val infoPacketSize = 4 + 4 + 2 + 2 + 2 + 2 + 2 +
                domainBytes.size + userBytes.size + passBytes.size +
                shellBytes.size + workBytes.size

        // FIX-A: 4-byte TS_SECURITY_HEADER (secFlags + secFlagsHi)
        val secHeader = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
        secHeader.putShort(SEC_INFO_PKT.toShort())  // flags = 0x0040
        secHeader.putShort(0)                        // flagsHi

        val infoBuf = ByteBuffer.allocate(infoPacketSize).order(ByteOrder.LITTLE_ENDIAN)
        infoBuf.putInt(0x00000000)                   // CodePage
        infoBuf.putInt(infoPacketFlags)
        infoBuf.putShort((domainBytes.size - 2).toShort())
        infoBuf.putShort((userBytes.size - 2).toShort())
        infoBuf.putShort((passBytes.size - 2).toShort())
        infoBuf.putShort((shellBytes.size - 2).toShort())
        infoBuf.putShort((workBytes.size - 2).toShort())
        // FIX-I: No pad field here — TS_INFO_PACKET has no padding between
        // the length fields and the variable-length credential data.
        // The extra putShort(0) was causing a 2-byte misalignment on all
        // Windows versions (server read domain/username/password at wrong offsets).
        infoBuf.put(domainBytes)
        infoBuf.put(userBytes)
        infoBuf.put(passBytes)
        infoBuf.put(shellBytes)
        infoBuf.put(workBytes)

        val payload = secHeader.array() + infoBuf.array().copyOf(infoBuf.position())
        sendMcsSendDataRequest(payload)
    }

    // ── Demand Active + post-connection PDU burst ──────────────────────────

    /**
     * FIX-C: parse the server's shareId from the Demand Active PDU.
     * FIX-F: drain the 4-5 server PDUs that follow our PDU burst
     * (Synchronize → Control Cooperate → Control Granted → Font Map).
     */
    private fun handleDemandActivePdu() {
        // --- 1. Find Demand Active, parse shareId ---
        var foundDemandActive = false
        for (attempt in 0 until 10) {
            val raw = readX224Data() ?: break
            val payload = stripMcsSendDataIndication(raw)
            if (payload.size >= 6) {
                val pduType = payload[2].toInt() and 0xFF
                if (pduType == PDU_TYPE_DEMAND_ACTIVE) {
                    // TS_DEMAND_ACTIVE_PDU: bytes 6-9 are shareId (little-endian)
                    if (payload.size >= 10) {
                        serverShareId = ((payload[9].toInt() and 0xFF) shl 24) or
                                        ((payload[8].toInt() and 0xFF) shl 16) or
                                        ((payload[7].toInt() and 0xFF) shl 8)  or
                                        (payload[6].toInt() and 0xFF)
                        Log.d(TAG, "Demand Active: shareId=0x${serverShareId.toString(16)}")
                    }
                    foundDemandActive = true
                    break
                }
            }
        }
        if (!foundDemandActive) {
            Log.w(TAG, "Demand Active PDU not found; using default shareId=0x${serverShareId.toString(16)}")
        }

        // --- 2. Send our burst ---
        sendConfirmActivePdu()
        Log.d(TAG, "PDU burst: Confirm Active sent")

        sendSynchronizePdu()
        Log.d(TAG, "PDU burst: Synchronize sent")

        sendControlPdu(CTRLACTION_COOPERATE)
        Log.d(TAG, "PDU burst: Control COOPERATE sent")

        sendControlPdu(CTRLACTION_REQUEST_CONTROL)
        Log.d(TAG, "PDU burst: Control REQUEST_CONTROL sent")

        sendFontListPdu()
        Log.d(TAG, "PDU burst: Font List sent")

        // --- 3. Drain server's response burst ---
        // Server sends: Synchronize → Control(Cooperate) → Control(Granted) → Font Map
        // (optionally also Monitor Layout on multi-monitor setups)
        var drained = 0
        for (i in 0 until 8) {
            val raw = try { readX224Data() } catch (e: Exception) { null }
            if (raw == null) break
            val payload = stripMcsSendDataIndication(raw)
            if (payload.size >= 3) {
                val pduType = payload[2].toInt() and 0xFF
                Log.d(TAG, "Post-burst server PDU type=0x${pduType.toString(16)}")
                if (pduType == PDU_TYPE_DATA) {
                    // Share Data Header pduType2 at payload offset ~26 (rough heuristic)
                    // We just drain without strict parsing; 4 PDUs is the expected count.
                    drained++
                    if (drained >= 4) break
                }
            }
        }
        Log.d(TAG, "Post-burst drain complete ($drained PDUs consumed)")
    }

    // ── Confirm Active PDU ────────────────────────────────────────────────

    /**
     * FIX-B: Full TS_CONFIRM_ACTIVE_PDU layout per MS-RDPBCGR 2.2.1.13.2.
     *
     * Structure (all little-endian):
     *   TS_SHARECONTROLHEADER (6 bytes):
     *     totalLength (2)    = entire PDU size including this header
     *     pduType (2)        = PDU_TYPE_CONFIRM_ACTIVE (0x0013)
     *     pduSource (2)      = 0x03EA (client channel)
     *   shareId (4)          ← echoes server's shareId (FIX-C)
     *   originatorId (2)     = 0x03EA
     *   lengthSourceDescriptor (2)   ← was missing
     *   lengthCombinedCapabilities (2) ← was missing
     *   sourceDescriptor (4 bytes: "RDP\0") ← was missing
     *   numberCapabilities (2)  ← was missing
     *   pad2Octets (2)       ← was missing
     *   capabilitySets (variable)
     */
    private fun sendConfirmActivePdu() {
        val caps          = buildCapabilitySets()
        val srcDesc       = byteArrayOf('R'.code.toByte(), 'D'.code.toByte(), 'P'.code.toByte(), 0x00)
        val srcDescLen    = srcDesc.size.toShort()                // 4
        val numCaps       = countCapabilitySets(caps).toShort()
        val combinedLen   = (caps.size + 4).toShort()            // caps + numCaps(2) + pad(2)

        // Total PDU length = 6 (shareCtrl) + 4 (shareId) + 2 (originatorId)
        //   + 2 (lenSrcDesc) + 2 (lenCombined) + srcDesc.size
        //   + 2 (numCaps) + 2 (pad) + caps.size
        val totalLength = 6 + 4 + 2 + 2 + 2 + srcDesc.size + 2 + 2 + caps.size

        val buf = ByteBuffer.allocate(totalLength).order(ByteOrder.LITTLE_ENDIAN)

        // TS_SHARECONTROLHEADER
        buf.putShort(totalLength.toShort())     // totalLength
        buf.putShort(PDU_TYPE_CONFIRM_ACTIVE.toShort()) // pduType = 0x0013
        buf.putShort(0x03EA.toShort())          // pduSource

        // TS_CONFIRM_ACTIVE_PDU body
        buf.putInt(serverShareId)               // FIX-C: use parsed shareId
        buf.putShort(0x03EA.toShort())          // originatorId
        buf.putShort(srcDescLen)                // lengthSourceDescriptor (FIX-B)
        buf.putShort(combinedLen)               // lengthCombinedCapabilities (FIX-B)
        buf.put(srcDesc)                        // sourceDescriptor "RDP\0" (FIX-B)
        buf.putShort(numCaps)                   // numberCapabilities (FIX-B)
        buf.putShort(0)                         // pad2Octets (FIX-B)
        buf.put(caps)

        sendMcsSendDataRequest(buf.array().copyOf(buf.position()))
    }

    /** Count the number of capability sets in the blob by walking the 4-byte headers. */
    private fun countCapabilitySets(caps: ByteArray): Int {
        var count = 0
        var pos = 0
        while (pos + 4 <= caps.size) {
            val len = ((caps[pos + 3].toInt() and 0xFF) shl 8) or (caps[pos + 2].toInt() and 0xFF)
            if (len < 4 || pos + len > caps.size) break
            count++
            pos += len
        }
        return count
    }

    /**
     * FIX-E: Removed the malformed Bitmap Codecs capability (wrote 2 bytes
     * for a 16-byte GUID) and the Frame Marker capability (depends on it).
     * Keeping Surface Commands (0x001D) which is safe and properly encoded.
     *
     * FIX-J: Corrected three capability sets whose declared length (in the
     * 2-byte length field) did not match the number of bytes actually written:
     *
     *  • ORDER caps: declared 88, wrote 104.
     *    Body per MS-RDPBCGR 2.2.7.1.3:
     *      terminalDescriptor(16) + pad4octetsA(4) + desktopSaveXGranularity(2)
     *      + desktopSaveYGranularity(2) + pad2octetsA(2) + maximumOrderLevel(2)
     *      + numberFonts(2) + orderFlags(2) + orderSupport(32) + textFlags(2)
     *      + orderSupportExFlags(2) + pad4octetsB(4) + desktopSaveSize(4)
     *      + pad2octetsC(2) + pad2octetsD(2) + textANSICodePage(2) + pad2octetsE(2)
     *    = 16+4+2+2+2+2+2+2+32+2+2+4+4+2+2+2+2 = 84. Total with header = 88. ✓
     *    Bug: previous code wrote 32+4+2+2+2+2+2+2+32+2+2+4+4+2+2+2+2 = 100 body
     *         (16-byte descriptor had 32 bytes written). Fixed to write 16 zeros.
     *
     *  • BITMAP CACHE REV2 caps: declared 40, wrote 32.
     *    Body per MS-RDPBCGR 2.2.7.1.5.2 (TS_BITMAPCACHE_CAPABILITYSET_REV2):
     *      cacheFlags(2) + pad2(2) + numCellCaches(1) + pad3(3) +
     *      bitmapCache0CellInfo(4) + bitmapCache1CellInfo(4) +
     *      bitmapCache2CellInfo(4) + pad4(12) = 2+2+1+3+4+4+4+12 = 32.
     *    Wait — declared 40 means 36-byte body; spec says numCellCaches+pad = 4,
     *    plus 3 × CellInfo (4 bytes each) + pad2 (16 bytes) = 4+12+16 = 32.
     *    Total body = 2+2+4+12+16 = 36, total cap = 40. ✓  Fixed below.
     *
     *  • INPUT caps: declared 88, wrote 92.
     *    Body per MS-RDPBCGR 2.2.7.1.6:
     *      inputFlags(2) + pad2octetsA(2) + keyboardLayout(4) + keyboardType(4)
     *      + keyboardSubType(4) + keyboardFunctionKey(4) + imeFileName(64)
     *    = 2+2+4+4+4+4+64 = 84. Total with header = 88. ✓
     *    Bug: previous code wrote an extra putShort(0); putShort(0) (4 extra bytes)
     *         at the end.  Removed.
     */
    private fun buildCapabilitySets(): ByteArray {
        val buf = ByteBuffer.allocate(1024).order(ByteOrder.LITTLE_ENDIAN)

        // ── CAPSTYPE_GENERAL (0x0001) — 24 bytes total ──────────────────────
        // Header (4) + body (20):
        //   osMajorType(2) osMinorType(2) protocolVersion(2) pad2octetsA(2)
        //   generalCompressionTypes(2) extraFlags(2) updateCapabilityFlag(2)
        //   remoteUnshareFlag(2) generalCompressionLevel(2) refreshRectSupport(1)
        //   suppressOutputSupport(1)
        buf.putShort(0x0001); buf.putShort(24)
        buf.putShort(1)               // osMajorType = OSMAJORTYPE_WINDOWS
        buf.putShort(3)               // osMinorType = OSMINORTYPE_WINDOWS_NT
        buf.putShort(0x0200)          // protocolVersion = TS_CAPS_PROTOCOLVERSION
        buf.putShort(0)               // pad2octetsA
        buf.putShort(0)               // generalCompressionTypes = 0 (none)
        buf.putShort(0x0441)          // extraFlags: FASTPATH_OUTPUT_SUPPORTED | NO_BITMAP_COMPRESSION_HDR | ENC_SALTED_CHECKSUM
        buf.putShort(0)               // updateCapabilityFlag
        buf.putShort(0)               // remoteUnshareFlag
        buf.putShort(0)               // generalCompressionLevel
        buf.put(1)                    // refreshRectSupport
        buf.put(1)                    // suppressOutputSupport

        // ── CAPSTYPE_BITMAP (0x0002) — 28 bytes total ───────────────────────
        // Header (4) + body (24):
        //   preferredBitsPerPixel(2) receive1BitPerPixel(2) receive4BitsPerPixel(2)
        //   receive8BitsPerPixel(2) desktopWidth(2) desktopHeight(2) pad2octets(2)
        //   desktopResizeFlag(2) bitmapCompressionFlag(2) highColorFlags(1)
        //   drawingFlags(1) multipleRectangleSupport(2) pad2octetsB(2)
        buf.putShort(0x0002); buf.putShort(28)
        buf.putShort(32)              // preferredBitsPerPixel
        buf.putShort(1)               // receive1BitPerPixel
        buf.putShort(1)               // receive4BitsPerPixel
        buf.putShort(1)               // receive8BitsPerPixel
        buf.putShort(displayWidth.toShort())
        buf.putShort(displayHeight.toShort())
        buf.putShort(0)               // pad2octets
        buf.putShort(1)               // desktopResizeFlag
        buf.putShort(1)               // bitmapCompressionFlag
        buf.put(0)                    // highColorFlags
        buf.put(0)                    // drawingFlags
        buf.putShort(1)               // multipleRectangleSupport
        buf.putShort(0)               // pad2octetsB

        // ── CAPSTYPE_ORDER (0x0003) — 88 bytes total ────────────────────────
        // Header (4) + body (84):
        //   terminalDescriptor(16) pad4octetsA(4)
        //   desktopSaveXGranularity(2) desktopSaveYGranularity(2) pad2octetsA(2)
        //   maximumOrderLevel(2) numberFonts(2) orderFlags(2)
        //   orderSupport(32) textFlags(2) orderSupportExFlags(2)
        //   pad4octetsB(4) desktopSaveSize(4)
        //   pad2octetsC(2) pad2octetsD(2) textANSICodePage(2) pad2octetsE(2)
        // FIX-J: terminalDescriptor is 16 bytes (was 32)
        buf.putShort(0x0003); buf.putShort(88)
        repeat(16) { buf.put(0) }    // terminalDescriptor[16] — FIX-J: was repeat(32)
        buf.putInt(0)                 // pad4octetsA
        buf.putShort(1)               // desktopSaveXGranularity
        buf.putShort(20)              // desktopSaveYGranularity
        buf.putShort(0)               // pad2octetsA
        buf.putShort(1)               // maximumOrderLevel = ORD_LEVEL_1_ORDERS
        buf.putShort(0)               // numberFonts
        buf.putShort(0x002F)          // orderFlags: NEGOTIATEORDERSUPPORT|ZEROBOUNDSDELTASSUPPORT|COLORINDEXSUPPORT|SOLIDPATTERNBRUSHONLY
        repeat(32) { buf.put(0) }    // orderSupport[32] (all orders disabled)
        buf.putShort(0)               // textFlags
        buf.putShort(0x0040)          // orderSupportExFlags: CACHE_BITMAP_REV3_SUPPORT
        buf.putInt(0)                 // pad4octetsB
        buf.putInt(230400)            // desktopSaveSize
        buf.putShort(0)               // pad2octetsC
        buf.putShort(0)               // pad2octetsD
        buf.putShort(0x0409)          // textANSICodePage
        buf.putShort(0)               // pad2octetsE

        // ── CAPSTYPE_BITMAPCACHE_REV2 (0x0013) — 40 bytes total ─────────────
        // Header (4) + body (36):
        //   cacheFlags(2) pad2(2) numCellCaches(1) pad3(3)
        //   bitmapCache0CellInfo(4) bitmapCache1CellInfo(4) bitmapCache2CellInfo(4)
        //   pad2a(16)
        // FIX-J: added 16-byte pad at end (was missing, total was 32 not 40)
        buf.putShort(0x0013); buf.putShort(40)
        buf.putShort(0x0003)          // cacheFlags: ALLOW_CACHE_WAITING_LIST | PERSISTENT_KEYS_EXPECTED_FLAG
        buf.putShort(0)               // pad2
        buf.put(3)                    // numCellCaches = 3
        buf.put(0); buf.put(0); buf.put(0)  // pad3
        buf.putInt(600)               // bitmapCache0CellInfo (numEntries, low 31 bits)
        buf.putInt(0x00000078)        // bitmapCache1CellInfo
        buf.putInt(0x00000078)        // bitmapCache2CellInfo
        repeat(16) { buf.put(0) }    // pad2a[16] — FIX-J: was missing entirely

        // ── CAPSTYPE_POINTER (0x0008) — 10 bytes total ──────────────────────
        buf.putShort(0x0008); buf.putShort(10)
        buf.putShort(1)               // colorPointerFlag
        buf.putShort(20)              // colorPointerCacheSize
        buf.putShort(20)              // pointerCacheSize

        // ── CAPSTYPE_INPUT (0x000D) — 88 bytes total ────────────────────────
        // Header (4) + body (84):
        //   inputFlags(2) pad2octetsA(2) keyboardLayout(4) keyboardType(4)
        //   keyboardSubType(4) keyboardFunctionKey(4) imeFileName(64)
        // FIX-J: removed the extra putShort(0);putShort(0) at the end (4 bytes over)
        buf.putShort(0x000D); buf.putShort(88)
        buf.putShort(0x0008)          // inputFlags: INPUT_FLAG_FASTPATH_INPUT2
        buf.putShort(0)               // pad2octetsA
        buf.putInt(0x00000409)        // keyboardLayout = EN-US
        buf.putInt(4)                 // keyboardType = IBM enhanced 101/102-key
        buf.putInt(0)                 // keyboardSubType
        buf.putInt(12)                // keyboardFunctionKey
        repeat(64) { buf.put(0) }    // imeFileName[64]

        // ── CAPSTYPE_BRUSH (0x000F) — 8 bytes ──────────────────────────────
        buf.putShort(0x000F); buf.putShort(8)
        buf.putInt(1)                 // brushSupportLevel = BRUSH_COLOR_8x8

        // ── CAPSTYPE_GLYPHCACHE (0x0010) — 52 bytes ─────────────────────────
        buf.putShort(0x0010); buf.putShort(52)
        repeat(10) { buf.putShort(0x0100); buf.putShort(0x0004) }  // 10 × GlyphCache entries
        buf.putInt(0x00000001)        // fragCache
        buf.putShort(0x0001)          // glyphSupportLevel = GLYPH_SUPPORT_PARTIAL
        buf.putShort(0)               // pad2octets

        // ── CAPSTYPE_OFFSCREENCACHE (0x0011) — 12 bytes ─────────────────────
        buf.putShort(0x0011); buf.putShort(12)
        buf.putInt(7680)              // offscreenSupportLevel
        buf.putShort(0x0064)          // offscreenCacheSize (in 4K units)
        buf.putShort(0x0001)          // offscreenCacheEntries

        // ── CAPSTYPE_VIRTUALCHANNEL (0x0014) — 12 bytes ─────────────────────
        buf.putShort(0x0014); buf.putShort(12)
        buf.putInt(0)                 // flags (no compression)
        buf.putInt(0x00020000)        // VCChunkSize

        // ── CAPSTYPE_SOUND (0x000C) — 8 bytes ──────────────────────────────
        buf.putShort(0x000C); buf.putShort(8)
        buf.putShort(0)               // soundFlags
        buf.putShort(0)               // pad2octetsA

        // ── CAPSTYPE_SURFACE_COMMANDS (0x001D) — 8 bytes ────────────────────
        // Windows 8+ capability; safe to include for all targets.
        buf.putShort(0x001D); buf.putShort(8)
        buf.putInt(0x00000001)        // cmdFlags: SURFCMDS_SETSURFACEBITS

        return buf.array().copyOf(buf.position())
    }

    // ── Post-connection sync/control/font PDUs ─────────────────────────────

    /**
     * FIX-D: All three PDUs now have a proper Share Control Header +
     * Share Data Header before their payload, per MS-RDPBCGR.
     *
     * Share Control Header (6 bytes, little-endian):
     *   totalLength (2), pduType = 0x0017 (DATA|version1) (2), pduSource (2)
     *
     * Share Data Header (18 bytes, little-endian):
     *   shareId (4), pad1 (1), streamId (1) = 1, uncompressedLength (2),
     *   pduType2 (1), generalCompressedType (1), generalCompressedLen (2)
     *   → fields after pduType2 are 0 for uncompressed.
     *
     * Note: totalLength covers the whole PDU including Share Control Header.
     */
    private fun buildDataPdu(pduType2: Int, payload: ByteArray): ByteArray {
        val totalLength = 6 + 18 + payload.size   // shareCtrl + shareData + payload
        val buf = ByteBuffer.allocate(totalLength).order(ByteOrder.LITTLE_ENDIAN)

        // Share Control Header
        buf.putShort(totalLength.toShort())
        buf.putShort(PDU_TYPE_DATA.toShort())       // 0x0017
        buf.putShort(0x03EA.toShort())              // pduSource

        // Share Data Header (18 bytes per MS-RDPBCGR 2.2.8.1.1.2.1)
        buf.putInt(serverShareId)                   // shareId (FIX-C)
        buf.put(0)                                  // pad1
        buf.put(1)                                  // streamId = STREAM_LOW (1)
        // uncompressedLength: size of data from pduType2 field to end of PDU payload
        // = 1 (pduType2) + 1 (generalCompressedType) + 2 (generalCompressedLen) + payload.size
        buf.putShort((4 + payload.size).toShort())  // uncompressedLength
        buf.put(pduType2.toByte())                  // pduType2
        buf.put(0)                                  // generalCompressedType = 0 (uncompressed)
        buf.putShort(0)                             // generalCompressedLen = 0

        buf.put(payload)
        return buf.array().copyOf(buf.position())
    }

    /** MS-RDPBCGR 2.2.1.14 TS_SYNCHRONIZE_PDU: type=1, targetUser=mcsUserId */
    private fun sendSynchronizePdu() {
        val payload = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(1)                            // messageType = SYNCMSGTYPE_SYNC
            .putShort(mcsUserId.toShort())          // targetUser
            .array()
        sendMcsSendDataRequest(buildDataPdu(PDUTYPE2_SYNCHRONIZE, payload))
    }

    /** MS-RDPBCGR 2.2.1.15 TS_CONTROL_PDU */
    private fun sendControlPdu(action: Int) {
        val payload = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(action.toShort())
            .putShort(0)                            // grantId
            .putInt(0)                              // controlId
            .array()
        sendMcsSendDataRequest(buildDataPdu(PDUTYPE2_CONTROL, payload))
    }

    /** MS-RDPBCGR 2.2.1.18 TS_FONT_LIST_PDU */
    private fun sendFontListPdu() {
        val payload = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(0)                            // numberFonts
            .putShort(0)                            // totalNumFonts
            .putShort(0x0003)                       // listFlags
            .putShort(0x0032)                       // entrySize (50)
            .array()
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
                Log.w(TAG, "Receive error ($consecutiveErrors): ${e.message}")
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

        // ── Fast-Path Update PDU (MS-RDPBCGR 5.3.8) ──────────────────────
        // A Fast-Path PDU does NOT go through X.224/TPKT; readTpkt() already
        // returns the raw frame when it sees a non-0x03 first byte. The first
        // byte of that raw frame is the fpOutputHeader (actionCode field):
        //   bits 0-1 = action (0 = FastPath)
        //   bits 2-3 = reserved
        //   bits 4-5 = numEvents (0 if > 15, use separate count byte)
        //   bits 6-7 = secFlags
        // The second (and possibly third) byte encodes the length (same
        // two-byte length format as TPKT). readTpkt() already consumed the
        // header and returned only the payload, so `data` here starts directly
        // at the Fast-Path update header — NOT at the fpOutputHeader byte.
        //
        // FIX-K: The previous code checked data[0]==0x02 && data[1]==0xF0,
        // which is the X.224 DT-TPDU header (already stripped by readX224Data).
        // When readTpkt() returns a FastPath frame (non-TPKT), the entire
        // payload IS the drawing data; route it straight to processDataPdu().
        //
        // For MCS SendDataIndication frames the X.224 prefix IS still present
        // inside the TPKT payload at bytes 0-2 (0x02 0xF0 0x80).
        val isMcsSdi = data.size >= 3 &&
                (data[0].toInt() and 0xFF) == 0x02 &&
                (data[1].toInt() and 0xFF) == 0xF0

        if (isMcsSdi) {
            val payload = stripMcsSendDataIndication(data.copyOfRange(3, data.size))
            if (payload.size >= 3) {
                val pduType = payload[2].toInt() and 0xFF
                when (pduType) {
                    PDU_TYPE_DEMAND_ACTIVE -> {
                        Log.d(TAG, "Reactivation: new Demand Active received")
                        handleDemandActivePdu()
                    }
                    else -> Log.v(TAG, "Unhandled MCS PDU type: 0x${pduType.toString(16)}")
                }
            }
            return
        }

        // Everything else (FastPath update data or raw frames) goes to bitmap decoder
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

    // ── Input ───────────────────────────────────────────────────────────────

    fun sendMouseMove(x: Int, y: Int) {
        if (!connected) return
        val buf = ByteBuffer.allocate(7).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(0x10.toByte())           // eventHeader: eventCode=MOUSE (0x01 << 4)
        buf.putShort(0x0800.toShort())   // PTRFLAGS_MOVE
        buf.putShort(x.toShort())
        buf.putShort(y.toShort())
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
        buf.put(0x10.toByte())           // eventHeader: eventCode=MOUSE
        buf.putShort(flags)
        buf.putShort(x.toShort())
        buf.putShort(y.toShort())
        sendFastPathInput(buf.array().copyOf(buf.position()))
    }

    fun sendMouseScroll(x: Int, y: Int, delta: Int) {
        if (!connected) return
        val buf = ByteBuffer.allocate(7).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(0x10.toByte())           // eventHeader: eventCode=MOUSE
        buf.putShort((0x0200 or if (delta > 0) 0x0100 else 0x0000).toShort())
        buf.putShort(x.toShort())
        buf.putShort(y.toShort())
        sendFastPathInput(buf.array().copyOf(buf.position()))
    }

    fun sendKeyEvent(scanCode: Int, down: Boolean, extended: Boolean = false) {
        if (!connected) return
        val eventFlags = (if (!down) 0x01 else 0x00) or (if (extended) 0x02 else 0x00)
        val eventHeader = ((0x01 shl 4) or eventFlags).toByte()  // eventCode=KEYBOARD (0x01)
        val buf = ByteBuffer.allocate(2)
        buf.put(eventHeader)
        buf.put((scanCode and 0xFF).toByte())
        sendFastPathInput(buf.array().copyOf(buf.position()))
    }

    fun sendUnicodeKeyEvent(char: Char, down: Boolean) {
        if (!connected) return
        val eventFlags = if (!down) 0x01 else 0x00
        val eventHeader = ((0x04 shl 4) or eventFlags).toByte()  // eventCode=UNICODE_KEYBOARD (0x04)
        val buf = ByteBuffer.allocate(3).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(eventHeader)
        buf.putShort(char.code.toShort())
        sendFastPathInput(buf.array().copyOf(buf.position()))
    }

    fun sendCtrlAltDel() {
        sendKeyEvent(0x1D, true)
        sendKeyEvent(0x38, true)
        sendKeyEvent(0x53, true, extended = true)
        sendKeyEvent(0x53, false, extended = true)
        sendKeyEvent(0x38, false)
        sendKeyEvent(0x1D, false)
    }

    // ── I/O helpers ─────────────────────────────────────────────────────────

    private fun sendFastPathInput(data: ByteArray) {
        try {
            val header = ByteBuffer.allocate(4)
            header.put(0x10)
            writeFastPathLength(header, data.size + 2)
            val packet = header.array().copyOf(header.position()) + data
            synchronized(outputStream!!) { outputStream?.write(packet); outputStream?.flush() }
        } catch (e: Exception) { Log.w(TAG, "Failed to send input: ${e.message}") }
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
        } catch (e: Exception) { Log.w(TAG, "readRaw failed: ${e.message}"); null }
    }

    private fun readTpkt(): ByteArray? {
        return try {
            val header = ByteArray(4)
            inputStream?.readFully(header) ?: return null
            if ((header[0].toInt() and 0xFF) != TPKT_VERSION) {
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
        } catch (e: Exception) { null }
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

    // ── Lifecycle ───────────────────────────────────────────────────────────

    fun disconnect() {
        connected = false
        clientScope.cancel()
        cleanup()
    }

    private fun cleanup() {
        try { outputStream?.close(); inputStream?.close(); socket?.close() }
        catch (e: Exception) { Log.w(TAG, "Cleanup error: ${e.message}") }
        socket = null; inputStream = null; outputStream = null
    }
}

// ── Supporting types ────────────────────────────────────────────────────────

enum class RdpSessionState { DISCONNECTED, CONNECTING, CONNECTED, RECONNECTING, AUTH_FAILED, ERROR }
enum class MouseButton { LEFT, RIGHT, MIDDLE }

data class RdpFrameUpdate(
    val x: Int, val y: Int, val width: Int, val height: Int,
    val pixels: IntArray, val fullScreen: Boolean = false
)

class RdpException(message: String) : Exception(message)
class RdpAuthException(message: String) : Exception(message)

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
