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
import java.util.concurrent.TimeUnit

/**
 * Universal RDP Protocol Client - Auto-Detection Multi-Protocol Support
 * Supports: Windows XP/7/2008/2012/2016/2019/2022/2025, Windows 10/11, xrdp/Linux
 *
 * Protocol Detection Strategy (2026):
 * 1. Attempt negotiation-based approach (modern servers)
 * 2. Auto-detect server capabilities from response
 * 3. Fallback to legacy protocols for older systems
 * 4. Support both NLA (CredSSP) and Standard RDP Security
 * 5. Handle Windows Server 2025 Early User Authorization
 * 6. Support TLS 1.0-1.3 with automatic downgrade
 */
class RdpClient(
    private val credentials: RdpCredentials,
    private val displayWidth: Int,
    private val displayHeight: Int,
    private val performanceMode: Int = RdpPerformance.AUTO
) {
    companion object {
        private const val TAG = "RdpClient"
        const val RDP_DEFAULT_PORT = 3389
        const val CONNECT_TIMEOUT_MS = 15_000
        const val READ_TIMEOUT_MS = 30_000

        // Protocol flags
        const val PROTOCOL_RDP = 0x00000000
        const val PROTOCOL_SSL = 0x00000001
        const val PROTOCOL_HYBRID = 0x00000002
        const val PROTOCOL_HYBRID_EX = 0x00000008

        // RDP PDU types
        const val PDU_TYPE_DEMAND_ACTIVE = 0x11
        const val PDU_TYPE_CONFIRM_ACTIVE = 0x13
        const val PDU_TYPE_DATA = 0x17

        // TPKT constants
        const val TPKT_VERSION = 0x03

        // Server type detection
        const val SERVER_TYPE_UNKNOWN = 0
        const val SERVER_TYPE_XP_2003 = 1
        const val SERVER_TYPE_2008 = 2
        const val SERVER_TYPE_2012 = 3
        const val SERVER_TYPE_2016_2019 = 4
        const val SERVER_TYPE_2022_2025 = 5
        const val SERVER_TYPE_XRDP = 6
        const val SERVER_TYPE_WIN10_11 = 7
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
    private var frameBuffer: Array<IntArray> = Array(displayHeight) { IntArray(displayWidth) }

    var latencyMs: Long = 0L
        private set
    var bandwidthKbps: Int = 0
        private set

    // Auto-detection state
    var detectedServerType: Int = SERVER_TYPE_UNKNOWN
        private set
    var detectedServerVersion: String = "Unknown"
        private set
    var detectedProtocol: String = "Unknown"
        private set

    /**
     * Universal Connect with Auto-Detection
     * Detects server type and uses appropriate protocol automatically
     */
    suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        try {
            _sessionState.emit(RdpSessionState.CONNECTING)
            Log.d(TAG, "Universal connect to ${credentials.host}:${credentials.port}")

            // Phase 1: TCP Connection
            val sock = Socket()
            sock.connect(InetSocketAddress(credentials.host, credentials.port), CONNECT_TIMEOUT_MS)
            sock.soTimeout = READ_TIMEOUT_MS
            sock.tcpNoDelay = true
            sock.setPerformancePreferences(0, 2, 1)

            socket = sock
            inputStream = DataInputStream(BufferedInputStream(sock.getInputStream(), 65536))
            outputStream = DataOutputStream(BufferedOutputStream(sock.getOutputStream(), 65536))

            Log.d(TAG, "Phase 1: TCP connected")

            // Phase 2: Protocol Detection & Negotiation
            val detectionResult = detectAndNegotiateProtocol()
            if (!detectionResult.success) {
                throw RdpException("Protocol negotiation failed: ${detectionResult.error}")
            }

            Log.d(TAG, "Phase 2: Protocol detected - ${detectedProtocol}, Server: ${detectedServerVersion}")

            // Phase 3: Security Layer Setup
            if (detectionResult.requiresTls) {
                upgradeTls(detectionResult.tlsVersion)
                Log.d(TAG, "Phase 3: TLS ${detectionResult.tlsVersion} established")
            }

            // Phase 4: Authentication (NLA or Standard)
            if (detectionResult.requiresNla) {
                try {
                    performNlaAuthentication(detectionResult.credSspVersion)
                    Log.d(TAG, "Phase 4: NLA/CredSSP auth complete")
                } catch (e: Exception) {
                    Log.w(TAG, "NLA failed: ${e.message}, attempting fallback...")
                    // Fallback: Try Standard RDP Security if NLA fails
                    if (credentials.allowFallback) {
                        reconnectStandardSecurity()
                        return@withContext true
                    }
                    throw RdpAuthException("NLA authentication failed (${e.message})")
                }
            }

            // Phase 5: MCS Connection
            sendMcsConnectInitial()
            Log.d(TAG, "Phase 5: MCS Connect Initial sent")

            if (!readMcsConnectResponse()) {
                throw RdpException("MCS connection failed")
            }
            Log.d(TAG, "Phase 6: MCS Connect Response received")

            // Phase 6: MCS Domain Setup
            performMcsDomainSetup()
            Log.d(TAG, "Phase 7: MCS Domain Setup complete (userId=$mcsUserId)")

            // Phase 7: Client Info & Activation
            sendClientInfoPdu()
            Log.d(TAG, "Phase 8: Client Info sent")

            handleDemandActivePdu()
            Log.d(TAG, "Phase 9: Demand Active handled")

            connected = true
            _sessionState.emit(RdpSessionState.CONNECTED)

            launch { receiveLoop() }
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

    // ═══════════════════════════════════════════════════════════════════════════
    // PROTOCOL DETECTION & NEGOTIATION (Auto-Detection)
    // ═══════════════════════════════════════════════════════════════════════════

    data class DetectionResult(
        val success: Boolean,
        val error: String = "",
        val requiresTls: Boolean = false,
        val requiresNla: Boolean = false,
        val tlsVersion: String = "TLS",
        val credSspVersion: Int = 2
    )

    /**
     * Auto-detects server type and negotiates best protocol
     * Supports: Legacy (XP/2003), Standard (2008/2012), Modern (2016/2019/2022/2025), xrdp
     */
    private fun detectAndNegotiateProtocol(): DetectionResult {
        // Strategy: Try modern protocols first, fallback to legacy
        val protocols = if (credentials.useNla) {
            listOf(
                PROTOCOL_SSL or PROTOCOL_HYBRID or PROTOCOL_HYBRID_EX,  // Modern: TLS + NLA + Hybrid EX
                PROTOCOL_SSL or PROTOCOL_HYBRID,                         // Standard: TLS + NLA
                PROTOCOL_SSL,                                            // TLS only
                PROTOCOL_RDP                                             // Legacy: Standard RDP
            )
        } else {
            listOf(PROTOCOL_SSL, PROTOCOL_RDP)
        }

        for (requestedProtocol in protocols) {
            try {
                val result = attemptProtocolNegotiation(requestedProtocol)
                if (result.success) {
                    return result
                }
            } catch (e: Exception) {
                Log.w(TAG, "Protocol 0x${requestedProtocol.toString(16)} failed: ${e.message}")
                // Continue to next protocol
            }
        }

        return DetectionResult(success = false, error = "All protocols failed")
    }

    private fun attemptProtocolNegotiation(requestedProtocol: Int): DetectionResult {
        val userHash = credentials.username.replace(" ", "_").take(9)
        val cookie = "Cookie: mstshash=$userHash\r\n"
        val cookieBytes = cookie.toByteArray()

        val negReq = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        negReq.put(0x01) // Type: RDP_NEG_REQ
        negReq.put(0x00) // Flags
        negReq.putShort(8) // Length
        negReq.putInt(requestedProtocol)
        val negReqBytes = negReq.array()

        val x224Length = 1 + 1 + 2 + cookieBytes.size + negReqBytes.size + 2
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

        // Read response
        val header = ByteArray(4)
        inputStream?.readFully(header) ?: return DetectionResult(false, "No response")
        if (header[0] != TPKT_VERSION.toByte()) {
            // Legacy server without negotiation support
            return handleLegacyServer()
        }

        val length = ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
        val data = ByteArray(length - 4)
        inputStream?.readFully(data)

        if (data.isEmpty() || (data[1].toInt() and 0xFF) != 0xD0) {
            return DetectionResult(false, "Invalid X.224 response")
        }

        // Check for RDP Negotiation Response
        if (data.size >= 8) {
            val negType = data[6].toInt() and 0xFF
            when (negType) {
                0x02 -> { // RDP_NEG_RSP
                    val selected = ((data.getOrElse(11) { 0 }.toInt() and 0xFF) shl 24) or
                            ((data.getOrElse(10) { 0 }.toInt() and 0xFF) shl 16) or
                            ((data.getOrElse(9) { 0 }.toInt() and 0xFF) shl 8) or
                            (data.getOrElse(8) { 0 }.toInt() and 0xFF)
                    serverSelectedProtocol = selected
                    negotiatedNla = (selected and PROTOCOL_HYBRID) != 0
                    negotiatedHybridEx = (selected and PROTOCOL_HYBRID_EX) != 0

                    // Detect server type based on selected protocol
                    detectServerType(selected)

                    Log.d(TAG, "Server selected: 0x${selected.toString(16)} (NLA=$negotiatedNla, HybridEX=$negotiatedHybridEx)")

                    return DetectionResult(
                        success = true,
                        requiresTls = (selected and PROTOCOL_SSL) != 0 || (selected and PROTOCOL_HYBRID) != 0,
                        requiresNla = negotiatedNla || negotiatedHybridEx,
                        tlsVersion = selectTlsVersion(),
                        credSspVersion = if (detectedServerType >= SERVER_TYPE_2022_2025) 6 else 2
                    )
                }
                0x03 -> { // RDP_NEG_FAILURE
                    val failureCode = ((data.getOrElse(11) { 0 }.toInt() and 0xFF) shl 24) or
                            ((data.getOrElse(10) { 0 }.toInt() and 0xFF) shl 16) or
                            ((data.getOrElse(9) { 0 }.toInt() and 0xFF) shl 8) or
                            (data.getOrElse(8) { 0 }.toInt() and 0xFF)
                    Log.w(TAG, "RDP_NEG_FAILURE: 0x${failureCode.toString(16)}")
                    return DetectionResult(false, "Negotiation failure: 0x${failureCode.toString(16)}")
                }
            }
        }

        return DetectionResult(false, "No negotiation response")
    }

    /**
     * Handle legacy servers (Windows XP/2003, some Linux xrdp) without RDP Negotiation
     */
    private fun handleLegacyServer(): DetectionResult {
        Log.d(TAG, "Legacy server detected (no RDP Negotiation support)")
        detectedServerType = SERVER_TYPE_XP_2003
        detectedServerVersion = "Windows XP/2003 or Legacy"
        detectedProtocol = "Standard RDP Security"

        return DetectionResult(
            success = true,
            requiresTls = false,
            requiresNla = false,
            tlsVersion = "TLS",
            credSspVersion = 2
        )
    }

    /**
     * Detect server type based on selected protocol and behavior
     */
    private fun detectServerType(selectedProtocol: Int) {
        when {
            (selectedProtocol and PROTOCOL_HYBRID_EX) != 0 -> {
                detectedServerType = SERVER_TYPE_2022_2025
                detectedServerVersion = "Windows Server 2022/2025 or Windows 11"
                detectedProtocol = "TLS + NLA (Hybrid EX)"
            }
            (selectedProtocol and PROTOCOL_HYBRID) != 0 -> {
                detectedServerType = SERVER_TYPE_2016_2019
                detectedServerVersion = "Windows Server 2016/2019 or Windows 10"
                detectedProtocol = "TLS + NLA (Hybrid)"
            }
            (selectedProtocol and PROTOCOL_SSL) != 0 -> {
                detectedServerType = SERVER_TYPE_2012
                detectedServerVersion = "Windows Server 2012 or Windows 8.1"
                detectedProtocol = "TLS Only"
            }
            else -> {
                detectedServerType = SERVER_TYPE_2008
                detectedServerVersion = "Windows Server 2008 or Windows 7"
                detectedProtocol = "Standard RDP Security"
            }
        }
    }

    /**
     * Select appropriate TLS version based on detected server type
     */
    private fun selectTlsVersion(): String {
        return when (detectedServerType) {
            SERVER_TYPE_2022_2025 -> "TLSv1.3"  // Windows Server 2025 supports TLS 1.3
            SERVER_TYPE_2016_2019 -> "TLSv1.2"  // Windows Server 2016/2019
            SERVER_TYPE_2012 -> "TLSv1.2"       // Windows Server 2012
            SERVER_TYPE_2008 -> "TLSv1.0"       // Windows Server 2008 (legacy)
            else -> "TLSv1.2"                     // Default
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // TLS UPGRADE (Multi-Version Support)
    // ═══════════════════════════════════════════════════════════════════════════

    private var sslSocketRef: javax.net.ssl.SSLSocket? = null

    /**
     * Upgrades to TLS with automatic version selection
     * Supports TLSv1.0 through TLSv1.3 based on server capability
     */
    private fun upgradeTls(tlsVersion: String) {
        val trustAllManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

        val sslContext = SSLContext.getInstance(tlsVersion)
        sslContext.init(null, arrayOf<TrustManager>(trustAllManager), SecureRandom())

        val sslSocket = sslContext.socketFactory.createSocket(
            socket, credentials.host, credentials.port, true
        ) as javax.net.ssl.SSLSocket

        // Enable appropriate protocols based on server type
        sslSocket.enabledProtocols = when (tlsVersion) {
            "TLSv1.3" -> arrayOf("TLSv1.3", "TLSv1.2")
            "TLSv1.2" -> arrayOf("TLSv1.2", "TLSv1.1")
            "TLSv1.0" -> arrayOf("TLSv1.0", "SSLv3")
            else -> arrayOf("TLSv1.2")
        }

        sslSocket.startHandshake()

        socket = sslSocket as Socket
        sslSocketRef = sslSocket
        inputStream = DataInputStream(BufferedInputStream(sslSocket.getInputStream(), 65536))
        outputStream = DataOutputStream(BufferedOutputStream(sslSocket.getOutputStream(), 65536))
        Log.d(TAG, "TLS upgraded: ${sslSocket.session.protocol} / ${sslSocket.session.cipherSuite}")
    }

    /**
     * Reconnect with Standard RDP Security (fallback when NLA fails)
     */
    private suspend fun reconnectStandardSecurity(): Boolean {
        Log.w(TAG, "Falling back to Standard RDP Security")
        cleanup()

        // Reconnect without NLA
        val sock = Socket()
        sock.connect(InetSocketAddress(credentials.host, credentials.port), CONNECT_TIMEOUT_MS)
        sock.soTimeout = READ_TIMEOUT_MS
        socket = sock
        inputStream = DataInputStream(BufferedInputStream(sock.getInputStream(), 65536))
        outputStream = DataOutputStream(BufferedOutputStream(sock.getOutputStream(), 65536))

        // Send connection request without NLA
        sendX224ConnectionRequestLegacy()
        readX224ConnectionConfirmLegacy()

        // Continue with MCS without NLA
        sendMcsConnectInitial()
        readMcsConnectResponse()
        performMcsDomainSetup()
        sendClientInfoPdu()
        handleDemandActivePdu()

        connected = true
        _sessionState.emit(RdpSessionState.CONNECTED)
        launch { receiveLoop() }
        return true
    }

    private fun sendX224ConnectionRequestLegacy() {
        val cookie = "Cookie: mstshash=${credentials.username}\r\n".toByteArray()
        val x224Length = 1 + 1 + 2 + cookie.size + 2
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
        buf.put(cookie)

        outputStream?.write(buf.array())
        outputStream?.flush()
    }

    private fun readX224ConnectionConfirmLegacy(): Boolean {
        val header = ByteArray(4)
        inputStream?.readFully(header) ?: return false
        val length = ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
        val data = ByteArray(length - 4)
        inputStream?.readFully(data)
        return data.isNotEmpty() && (data[1].toInt() and 0xFF) == 0xD0
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // NLA AUTHENTICATION (CredSSP/NTLMv2)
    // ═══════════════════════════════════════════════════════════════════════════

    private var negotiatedNla = false
    private var negotiatedHybridEx = false
    private var serverSelectedProtocol: Int = 0

    private suspend fun performNlaAuthentication(credSspVersion: Int) {
        Log.d(TAG, "Starting CredSSP/NTLMv2 auth (version $credSspVersion)")

        val negotiateMsg = NtlmHelper.buildNegotiateMessage(credentials.domain)
        sendRaw(CredSspHelper.buildNegotiateTsRequest(negotiateMsg))
        Log.d(TAG, "NLA Step 1: NEGOTIATE sent")

        val challengeRequest = readRaw() ?: throw RdpAuthException("No CredSSP CHALLENGE response")

        val errorCode = CredSspHelper.extractErrorCode(challengeRequest)
        if (errorCode != null) {
            throw RdpAuthException("Server error: 0x${errorCode.toString(16)}")
        }

        val challengeMsg = CredSspHelper.extractNegoToken(challengeRequest)
            ?: throw RdpAuthException("Missing NTLM CHALLENGE token")
        val challenge = NtlmHelper.parseChallengeMessage(challengeMsg)
        Log.d(TAG, "NLA Step 2: CHALLENGE received")

        // Detect server's CredSSP version
        val serverVersion = CredSspHelper.extractVersion(challengeRequest)
        if (serverVersion >= 5) {
            CredSspHelper.negotiatedCredSspVersion = serverVersion
            Log.d(TAG, "Server supports CredSSP version $serverVersion")
        }

        val serverPublicKey = serverPublicKeyDer()
        Log.d(TAG, "Server public key: ${serverPublicKey.size} bytes")

        val authResult = NtlmHelper.buildAuthenticateMessage(
            username = credentials.username,
            password = credentials.password,
            domain = credentials.domain,
            challenge = challenge,
            negotiateMessage = negotiateMsg,
            challengeMessage = challengeMsg
        )
        Log.d(TAG, "NLA: AUTHENTICATE built")

        val pubKeyAuthToken = CredSspHelper.computePubKeyAuth(
            serverPublicKey = serverPublicKey,
            encryptionState = authResult.encryptionState,
            sequenceNumber = 0
        )
        sendRaw(CredSspHelper.buildAuthenticateTsRequest(authResult.message, pubKeyAuthToken))
        Log.d(TAG, "NLA Step 3: AUTHENTICATE + pubKeyAuth sent")

        val pubKeyResponse = readRaw() ?: throw RdpAuthException("No pubKeyAuth response")

        val pubKeyError = CredSspHelper.extractErrorCode(pubKeyResponse)
        if (pubKeyError != null) {
            throw RdpAuthException("Server rejected: 0x${pubKeyError.toString(16)}")
        }

        val encryptedServerConfirm = CredSspHelper.extractPubKeyAuth(pubKeyResponse)
            ?: throw RdpAuthException("Missing pubKeyAuth confirmation")
        Log.d(TAG, "NLA Step 4: Server pubKeyAuth received")

        val verified = CredSspHelper.verifyPubKeyAuthResponse(
            encryptedResponse = encryptedServerConfirm,
            serverPublicKey = serverPublicKey,
            encryptionState = authResult.encryptionState,
            sequenceNumber = 0
        )
        if (!verified) {
            throw RdpAuthException("Server public key confirmation mismatch")
        }
        Log.d(TAG, "Server pubKeyAuth verified")

        val tsCredentials = CredSspHelper.buildTsCredentials(
            domain = credentials.domain,
            username = credentials.username,
            password = credentials.password
        )
        val encryptedCreds = NtlmHelper.encryptMessage(authResult.encryptionState, tsCredentials, 1)
        sendRaw(CredSspHelper.buildAuthInfoTsRequest(encryptedCreds))
        Log.d(TAG, "NLA Step 5: Encrypted credentials sent")

        // Handle Early User Authorization for Hybrid EX
        if (negotiatedHybridEx) {
            Log.d(TAG, "NLA Step 6: Early User Authorization")
            val earlyAuthResult = readEarlyUserAuthorizationResult()
            if (earlyAuthResult != 0x00000000) {
                throw RdpAuthException("Early Authorization failed: 0x${earlyAuthResult.toString(16)}")
            }
            Log.d(TAG, "Early User Authorization: SUCCESS")
        }

        Log.d(TAG, "CredSSP/NTLMv2 authentication COMPLETE")
    }

    private fun readEarlyUserAuthorizationResult(): Int {
        return try {
            val packet = readTpkt() ?: return 0xFFFFFFFF.toInt()
            if (packet.size < 4) return 0xFFFFFFFF.toInt()
            ByteBuffer.wrap(packet).order(ByteOrder.LITTLE_ENDIAN).getInt(0)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to read Early User Authorization: ${e.message}")
            0xFFFFFFFF.toInt()
        }
    }

    private fun serverPublicKeyDer(): ByteArray {
        val session = sslSocketRef?.session ?: throw RdpException("No TLS session")
        val cert = session.peerCertificates.firstOrNull() ?: throw RdpException("No server certificate")
        val encoded = cert.publicKey.encoded
        return extractSubjectPublicKey(encoded)
    }

    private fun extractSubjectPublicKey(subjectPublicKeyInfo: ByteArray): ByteArray {
        var pos = 0
        if (subjectPublicKeyInfo[pos].toInt() and 0xFF != 0x30) return subjectPublicKeyInfo
        pos++
        val outerLen = readAsn1Length(subjectPublicKeyInfo, pos)
        pos += outerLen.second

        if (subjectPublicKeyInfo[pos].toInt() and 0xFF != 0x30) return subjectPublicKeyInfo
        pos++
        val algoLen = readAsn1Length(subjectPublicKeyInfo, pos)
        pos += algoLen.second + algoLen.first

        if (subjectPublicKeyInfo[pos].toInt() and 0xFF != 0x03) return subjectPublicKeyInfo
        pos++
        val bitStrLen = readAsn1Length(subjectPublicKeyInfo, pos)
        pos += bitStrLen.second
        pos++
        return subjectPublicKeyInfo.copyOfRange(pos, pos + bitStrLen.first - 1)
    }

    private fun readAsn1Length(data: ByteArray, offset: Int): Pair<Int, Int> {
        val first = data[offset].toInt() and 0xFF
        return if (first < 0x80) {
            Pair(first, 1)
        } else {
            val numBytes = first and 0x7F
            var len = 0
            for (i in 0 until numBytes) {
                len = (len shl 8) or (data[offset + 1 + i].toInt() and 0xFF)
            }
            Pair(len, 1 + numBytes)
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MCS CONNECTION
    // ═══════════════════════════════════════════════════════════════════════════

    private fun sendMcsConnectInitial() {
        val payload = buildMcsConnectInitialPayload()
        sendTpkt(payload)
    }

    private fun buildMcsConnectInitialPayload(): ByteArray {
        val coreData = buildClientCoreData()
        val secData = buildClientSecurityData()
        val netData = buildClientNetworkData()
        val userData = coreData + secData + netData
        return wrapInMcsConnectInitial(userData)
    }

    /**
     * Client Core Data with auto-detection support
     */
    private fun buildClientCoreData(): ByteArray {
        val buf = ByteBuffer.allocate(218).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0xC001.toShort())
        buf.putShort(218)
        buf.putInt(0x00080004)
        buf.putShort(displayWidth.toShort())
        buf.putShort(displayHeight.toShort())
        buf.putShort(0xCA01.toShort())
        buf.putShort(0xAA03.toShort())
        buf.putInt(0x409)
        buf.putInt(2600)
        val name = "HEXRDP".padEnd(15, '\u0000')
        name.forEach { buf.putShort(it.code.toShort()) }
        buf.putShort(0)
        buf.putInt(0x04)
        buf.putInt(0x00)
        buf.putInt(0x0C)
        repeat(32) { buf.put(0) }
        buf.putShort(0xCA01.toShort())
        buf.putShort(1)
        buf.putInt(0)
        buf.putShort(32)
        buf.putShort(0x0007)
        buf.putShort(0x0001)
        repeat(64) { buf.put(0) }
        buf.put(0)
        buf.put(0)
        // connectionType based on detected server
        val connectionType = when (detectedServerType) {
            SERVER_TYPE_2022_2025 -> 0x07  // CONNECTION_TYPE_AUTODETECT
            SERVER_TYPE_2016_2019 -> 0x06  // LAN
            SERVER_TYPE_2012 -> 0x06       // LAN
            else -> 0x03                    // BROADBAND
        }
        buf.put(connectionType.toByte())
        buf.put(0)  // pad1octet
        buf.putInt(serverSelectedProtocol)
        return buf.array().copyOf(buf.position())
    }

    private fun buildClientSecurityData(): ByteArray {
        val buf = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0xC002.toShort())
        buf.putShort(12)
        buf.putInt(0x00000003)
        buf.putInt(0x00000000)
        return buf.array()
    }

    private fun buildClientNetworkData(): ByteArray {
        val buf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0xC003.toShort())
        buf.putShort(8)
        buf.putInt(0)
        return buf.array()
    }

    /**
     * MCS Connect Initial (BER encoded)
     */
    private fun wrapInMcsConnectInitial(userData: ByteArray): ByteArray {
        val output = ByteArrayOutputStream()
        val dos = DataOutputStream(output)

        dos.write(0x65)  // Application-Tag 101 = Connect-Initial
        val mcsContentLength = 5 + 5 + 5 + 5 + userData.size + 10
        writeBerLength(dos, mcsContentLength)

        dos.write(0x04)
        dos.write(0x01)
        dos.write(0x01)

        dos.write(0x04)
        dos.write(0x01)
        dos.write(0x01)

        dos.write(0x01)
        dos.write(0x01)
        dos.write(0xFF.toByte())

        dos.write(0x30)
        dos.write(0x00)

        dos.write(0x30)
        dos.write(0x00)

        dos.write(0x30)
        dos.write(0x00)

        dos.write(0x04)
        writeBerLength(dos, userData.size)
        dos.write(userData)

        return output.toByteArray()
    }

    private fun writeBerLength(dos: DataOutputStream, length: Int) {
        when {
            length < 0x80 -> dos.write(length)
            length < 0x100 -> { dos.write(0x81); dos.write(length) }
            else -> { dos.write(0x82); dos.write((length shr 8) and 0xFF); dos.write(length and 0xFF) }
        }
    }

    private fun readMcsConnectResponse(): Boolean {
        val packet = readX224Data() ?: return false
        if (packet.isEmpty()) return false
        val tag = packet[0].toInt() and 0xFF
        return tag == 0x7F || tag == 0x30 || tag == 0x65 || tag == 0x66
    }

    private fun readX224Data(): ByteArray? {
        val data = readTpkt() ?: return null
        if (data.size >= 3 && (data[1].toInt() and 0xFF) == 0xF0) {
            return data.copyOfRange(3, data.size)
        }
        return data
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MCS DOMAIN SETUP
    // ═══════════════════════════════════════════════════════════════════════════

    private var mcsUserId: Int = 0
    private val ioChannelId: Int = 1003

    private fun performMcsDomainSetup() {
        sendTpkt(byteArrayOf(0x04, 0x01, 0x00, 0x01, 0x00))
        sendTpkt(byteArrayOf(0x28))

        val aucf = readX224Data() ?: throw RdpException("No Attach User Confirm")
        if (aucf.size < 4) throw RdpException("Malformed Attach User Confirm")
        val result = aucf[1].toInt() and 0xFF
        if (result != 0) throw RdpException("Attach User failed (result=$result)")
        mcsUserId = ((aucf[2].toInt() and 0xFF) shl 8) or (aucf[3].toInt() and 0xFF)
        Log.d(TAG, "MCS user ID: $mcsUserId")

        joinChannel(mcsUserId + 1001)
        joinChannel(ioChannelId)
    }

    private fun joinChannel(channelId: Int) {
        val req = ByteBuffer.allocate(5).order(ByteOrder.BIG_ENDIAN)
        req.put(0x38)
        req.putShort(mcsUserId.toShort())
        req.putShort(channelId.toShort())
        sendTpkt(req.array())

        val cjcf = readX224Data() ?: throw RdpException("No Channel Join Confirm")
        if (cjcf.size < 2 || (cjcf[1].toInt() and 0xFF) != 0) {
            throw RdpException("Channel Join failed for $channelId")
        }
    }

    private fun sendMcsSendDataRequest(data: ByteArray) {
        val header = ByteBuffer.allocate(6).order(ByteOrder.BIG_ENDIAN)
        header.put(0x64)
        header.putShort(mcsUserId.toShort())
        header.putShort(ioChannelId.toShort())
        header.put(0x70)

        val lengthBytes = if (data.size < 0x80) {
            byteArrayOf(data.size.toByte())
        } else {
            byteArrayOf((0x80 or (data.size shr 8)).toByte(), (data.size and 0xFF).toByte())
        }
        sendTpkt(header.array() + lengthBytes + data)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CLIENT INFO & ACTIVATION
    // ═══════════════════════════════════════════════════════════════════════════

    private fun sendClientInfoPdu() {
        val domainBytes = (credentials.domain + "\u0000").toByteArray(Charsets.UTF_16LE)
        val userBytes = (credentials.username + "\u0000").toByteArray(Charsets.UTF_16LE)
        val passBytes = (credentials.password + "\u0000").toByteArray(Charsets.UTF_16LE)
        val shellBytes = "\u0000".toByteArray(Charsets.UTF_16LE)
        val workdirBytes = "\u0000".toByteArray(Charsets.UTF_16LE)

        val pduSize = 18 + 10 + domainBytes.size + userBytes.size + passBytes.size + shellBytes.size + workdirBytes.size
        val buf = ByteBuffer.allocate(pduSize).order(ByteOrder.LITTLE_ENDIAN)

        buf.putInt(0x00000000)
        buf.putInt(0x00000053)

        buf.putShort((domainBytes.size - 2).toShort())
        buf.putShort((userBytes.size - 2).toShort())
        buf.putShort((passBytes.size - 2).toShort())
        buf.putShort((shellBytes.size - 2).toShort())
        buf.putShort((workdirBytes.size - 2).toShort())
        buf.putShort(0)

        buf.put(domainBytes)
        buf.put(userBytes)
        buf.put(passBytes)
        buf.put(shellBytes)
        buf.put(workdirBytes)

        sendMcsSendDataRequest(buf.array().copyOf(buf.position()))
    }

    private var serverShareId: Int = 0x03EA

    private fun handleDemandActivePdu() {
        var foundDemandActive = false
        for (attempt in 0 until 5) {
            val raw = readX224Data() ?: return
            val payload = stripMcsSendDataIndication(raw)
            if (payload.size >= 3 && (payload[2].toInt() and 0x0F) == 0x01) {
                if (payload.size >= 6) {
                    serverShareId = ((payload[4].toInt() and 0xFF) shl 8) or (payload[5].toInt() and 0xFF)
                    Log.d(TAG, "Server Share ID: 0x${serverShareId.toString(16)}")
                }
                foundDemandActive = true
                break
            }
        }
        if (!foundDemandActive) {
            Log.w(TAG, "Demand Active not found after 5 attempts")
            return
        }

        sendConfirmActivePdu()
        sendSyncPdu()
        sendControlPdu()
        sendFontListPdu()
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

    private fun sendConfirmActivePdu() {
        val caps = buildCapabilitySets()

        val shareControlHeader = ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN)
        shareControlHeader.putShort((caps.size + 14).toShort())
        shareControlHeader.putShort(0x0013)
        shareControlHeader.putShort(serverShareId.toShort())

        val shareDataHeader = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        shareDataHeader.putInt(0x00010000 or serverShareId)
        shareDataHeader.putShort(0x03EA.toShort())
        shareDataHeader.putShort(0x02)

        val fullPdu = shareControlHeader.array() + shareDataHeader.array() + caps
        sendMcsSendDataRequest(fullPdu)
    }

    private fun buildCapabilitySets(): ByteArray {
        val buf = ByteBuffer.allocate(512).order(ByteOrder.LITTLE_ENDIAN)

        // General (24 bytes)
        buf.putShort(0x0001); buf.putShort(24)
        buf.putShort(1); buf.putShort(3)
        buf.putShort(0x0200); buf.putShort(0)
        buf.putShort(0); buf.putShort(0x0041)
        buf.putShort(0); buf.putShort(0)
        buf.putShort(0); buf.putShort(0); buf.putShort(0)

        // Bitmap (28 bytes)
        buf.putShort(0x0002); buf.putShort(28)
        buf.putShort(32); buf.putShort(1); buf.putShort(1); buf.putShort(1)
        buf.putShort(displayWidth.toShort()); buf.putShort(displayHeight.toShort())
        buf.putShort(0); buf.putShort(1); buf.putShort(1)
        buf.put(0); buf.put(0)
        buf.putShort(1); buf.putShort(0)

        // Order (88 bytes)
        buf.putShort(0x0003); buf.putShort(88)
        repeat(32) { buf.put(0) }
        buf.putInt(0); buf.putShort(1); buf.putShort(20)
        buf.putShort(0); buf.putShort(1); buf.putShort(0); buf.putShort(0x2F)
        repeat(32) { buf.put(0) }
        buf.putShort(0x0040); buf.putShort(0)
        buf.putInt(0); buf.putInt(230400)
        buf.putShort(0); buf.putShort(0); buf.putShort(0x01); buf.putShort(0)

        // Bitmap Cache Rev2 (40 bytes)
        buf.putShort(0x0013); buf.putShort(40)
        buf.putShort(0x0003); buf.putShort(0)
        buf.putInt(600)
        buf.putInt(0x00000078); buf.putInt(0x00000078); buf.putInt(0x00000078)
        buf.putInt(0); buf.putInt(0)

        // Pointer (10 bytes)
        buf.putShort(0x0008); buf.putShort(10)
        buf.putShort(1); buf.putShort(20); buf.putShort(20)

        // Input (88 bytes)
        buf.putShort(0x000D); buf.putShort(88)
        buf.putShort(0); buf.putShort(0)
        buf.putInt(0x00000409); buf.putInt(2600)
        buf.putInt(0); buf.putInt(12)
        repeat(64) { buf.put(0) }
        buf.putShort(0x0000); buf.putShort(0)

        // Brush (8 bytes)
        buf.putShort(0x000F); buf.putShort(8)
        buf.putInt(1)

        // Glyph Cache (52 bytes)
        buf.putShort(0x0010); buf.putShort(52)
        repeat(10) { buf.putShort(0x0100); buf.putShort(0x0004) }
        buf.putInt(0x00000001); buf.putShort(0x0001); buf.putShort(0)

        // Offscreen (12 bytes)
        buf.putShort(0x0011); buf.putShort(12)
        buf.putInt(7680); buf.putShort(0x0064); buf.putShort(0x0001)

        // Virtual Channel (12 bytes)
        buf.putShort(0x0014); buf.putShort(12)
        buf.putInt(0); buf.putInt(0x00020000)

        // Sound (8 bytes)
        buf.putShort(0x000C); buf.putShort(8)
        buf.putShort(0); buf.putShort(0)

        return buf.array().copyOf(buf.position())
    }

    private fun sendSyncPdu() = sendMcsSendDataRequest(byteArrayOf(0x16, 0x00, 0x00, 0x00))
    private fun sendControlPdu() = sendMcsSendDataRequest(byteArrayOf(0x17, 0x00, 0x00, 0x00))
    private fun sendFontListPdu() = sendMcsSendDataRequest(byteArrayOf(0x28, 0x00, 0x00, 0x00))

    // ═══════════════════════════════════════════════════════════════════════════
    // RECEIVE LOOP & INPUT
    // ═══════════════════════════════════════════════════════════════════════════

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
        if (data.size >= 3 && (data[0].toInt() and 0xFF) == 0x02 && (data[1].toInt() and 0xFF) == 0xF0) {
            val payload = stripMcsSendDataIndication(data.copyOfRange(3, data.size))
            if (payload.size >= 3) {
                val pduType = payload[2].toInt() and 0x0F
                when (pduType) {
                    0x01 -> handleDemandActivePdu()
                    else -> Log.v(TAG, "Unhandled PDU type: 0x${pduType.toString(16)}")
                }
            }
            return
        }
        processDataPdu(data)
    }

    private suspend fun processDataPdu(data: ByteArray) {
        val decoder = RdpBitmapDecoder()
        val frames = decoder.decode(data, displayWidth, displayHeight, currentPerformance)
        for (frame in frames) { _frameUpdates.emit(frame) }
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

    // ---- INPUT METHODS ----

    fun sendMouseMove(x: Int, y: Int) {
        if (!connected) return
        val buf = ByteBuffer.allocate(14).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0001)
        buf.putShort(0x0800)
        buf.putShort(x.toShort())
        buf.putShort(y.toShort())
        sendFastPathInput(buf.array().copyOf(buf.position()))
    }

    fun sendMouseClick(x: Int, y: Int, button: MouseButton, down: Boolean) {
        if (!connected) return
        val flags: Short = when (button) {
            MouseButton.LEFT -> if (down) 0x1000 else 0x0000
            MouseButton.RIGHT -> if (down) 0x2000 else 0x0000
            MouseButton.MIDDLE -> if (down) 0x4000 else 0x0000
        }.toShort()
        val buf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0001); buf.putShort(flags)
        buf.putShort(x.toShort()); buf.putShort(y.toShort())
        sendFastPathInput(buf.array().copyOf(buf.position()))
    }

    fun sendMouseScroll(x: Int, y: Int, delta: Int) {
        if (!connected) return
        val buf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0001)
        buf.putShort((0x0200 or if (delta > 0) 0x0100 else 0x0000).toShort())
        buf.putShort(x.toShort()); buf.putShort(y.toShort())
        sendFastPathInput(buf.array().copyOf(buf.position()))
    }

    fun sendKeyEvent(scanCode: Int, down: Boolean, extended: Boolean = false) {
        if (!connected) return
        val flags = (if (down) 0 else 0x8000) or (if (extended) 0x0100 else 0)
        val buf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(flags.toShort()); buf.putShort(scanCode.toShort())
        sendFastPathInput(buf.array().copyOf(buf.position()))
    }

    fun sendUnicodeKeyEvent(char: Char, down: Boolean) {
        if (!connected) return
        val buf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(if (down) 0 else 0x8000.toShort())
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

    // ---- HELPERS ----

    private fun sendFastPathInput(data: ByteArray) {
        try {
            val header = ByteBuffer.allocate(4)
            header.put(0x10)
            writeFastPathLength(header, data.size + 1)
            val packet = header.array().copyOf(header.position()) + data
            synchronized(outputStream!!) {
                outputStream?.write(packet)
                outputStream?.flush()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to send input: ${e.message}")
        }
    }

    private fun writeFastPathLength(buf: ByteBuffer, length: Int) {
        if (length > 0x7F) {
            buf.put((0x80 or (length shr 8)).toByte())
        }
        buf.put((length and 0xFF).toByte())
    }

    private fun sendTpkt(data: ByteArray) {
        val x224Data = byteArrayOf(0x02, 0xF0.toByte(), 0x80.toByte()) + data
        val length = x224Data.size + 4
        val header = byteArrayOf(
            TPKT_VERSION.toByte(), 0x00,
            (length shr 8).toByte(), (length and 0xFF).toByte()
        )
        synchronized(outputStream!!) {
            outputStream?.write(header + x224Data)
            outputStream?.flush()
        }
    }

    private fun sendRaw(data: ByteArray) {
        synchronized(outputStream!!) {
            outputStream?.write(data)
            outputStream?.flush()
        }
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
                    repeat(numBytes) {
                        len = (len shl 8) or (inputStream?.readUnsignedByte() ?: return null)
                    }
                    len to numBytes
                }
            }
            if (contentLength <= 0 || contentLength > 1_048_576) return null

            val content = ByteArray(contentLength)
            inputStream?.readFully(content)

            val header = if (lengthHeaderExtra == 0) {
                byteArrayOf(0x30, firstLenByte.toByte())
            } else {
                val lenBytes = ByteArray(lengthHeaderExtra)
                var rem = contentLength
                for (i in lengthHeaderExtra - 1 downTo 0) {
                    lenBytes[i] = (rem and 0xFF).toByte()
                    rem = rem ushr 8
                }
                byteArrayOf(0x30, firstLenByte.toByte()) + lenBytes
            }
            header + content
        } catch (e: Exception) {
            Log.w(TAG, "readRaw failed: ${e.message}")
            null
        }
    }

    private fun readTpkt(): ByteArray? {
        return try {
            val header = ByteArray(4)
            inputStream?.readFully(header) ?: return null
            if ((header[0].toInt() and 0xFF) != TPKT_VERSION) {
                val fpLen = if ((header[1].toInt() and 0x80) != 0) {
                    ((header[1].toInt() and 0x7F) shl 8) or (header[2].toInt() and 0xFF)
                } else {
                    header[1].toInt() and 0xFF
                }
                val remaining = fpLen - 2
                if (remaining <= 0) return byteArrayOf(header[0])
                val data = ByteArray(remaining)
                inputStream?.readFully(data)
                return data
            }
            val length = ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
            val dataLength = length - 4
            if (dataLength <= 0) return ByteArray(0)
            val data = ByteArray(dataLength)
            inputStream?.readFully(data)
            data
        } catch (e: Exception) { null }
    }

    fun disconnect() {
        connected = false
        cleanup()
    }

    private fun cleanup() {
        try {
            outputStream?.close()
            inputStream?.close()
            socket?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Cleanup error: ${e.message}")
        }
        socket = null
        inputStream = null
        outputStream = null
    }
}

enum class RdpSessionState {
    DISCONNECTED, CONNECTING, CONNECTED, RECONNECTING, AUTH_FAILED, ERROR
}

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
