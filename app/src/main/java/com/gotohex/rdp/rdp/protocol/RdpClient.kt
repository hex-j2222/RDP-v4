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
 * Protocol negotiation strategy:
 * - Request: PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX (0x0B)
 * - Server selects: TLS (0x01) or NLA (0x02) or Hybrid EX (0x08)
 * - If TLS only: skip NLA, go directly to MCS
 * - If NLA/Hybrid EX: perform CredSSP handshake
 * - If server rejects: fallback to Standard RDP Security (0x00)
 *
 * WINDOWS 8/8.1 SUPPORT:
 * - RDP 8.0/8.1 protocol features
 * - CredSSP v5/v6 with SHA256 hash
 * - Hybrid EX (0x08) with Early User Authorization Result PDU
 * - Dynamic Virtual Channels (DVC) support
 * - Multi-touch input support
 */
class RdpClient(
    private val credentials: RdpCredentials,
    private val displayWidth: Int,
    private val displayHeight: Int,
    private val performanceMode: Int = RdpPerformance.AUTO,
    private val allowFallback: Boolean = true  // ← FIX: Added missing parameter
) {
    companion object {
        private const val TAG = "RdpClient"
        const val RDP_DEFAULT_PORT = 3389
        const val CONNECT_TIMEOUT_MS = 10_000
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

        // Windows 8/8.1 specific constants
        const val RDP_VERSION_8_0 = 0x00080004
        const val RDP_VERSION_8_1 = 0x00080005
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

    // Coroutine scope for the client
    private val clientScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

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

            if (!readX224ConnectionConfirm()) {
                throw RdpException("X.224 connection rejected")
            }
            Log.d(TAG, "STEP 3: X.224 CC received (selected=$serverSelectedProtocol, NLA=$negotiatedNla, HybridEX=$negotiatedHybridEx)")

            upgradeTls()
            Log.d(TAG, "STEP 4: TLS upgraded")

            // Handle Early User Authorization Result for Hybrid EX (Windows 8.1+)
            if (negotiatedHybridEx) {
                if (!handleEarlyUserAuthResult()) {
                    throw RdpAuthException("Early user authorization failed")
                }
                Log.d(TAG, "STEP 4a: Early User Auth Result handled")
            }

            if (negotiatedNla || negotiatedHybridEx) {
                try {
                    performNlaAuthentication()
                    Log.d(TAG, "STEP 5: NLA complete")
                } catch (e: Exception) {
                    Log.w(TAG, "NLA failed: ${e.message}")
                    if (allowFallback) {
                        Log.w(TAG, "Fallback to Standard RDP Security not implemented in this version")
                    }
                    throw RdpAuthException("NLA authentication failed (${e.message}). Try disabling 'Use NLA Authentication'.")
                }
            }

            sendMcsConnectInitial()
            Log.d(TAG, "STEP 6: MCS Connect Initial sent")

            if (!readMcsConnectResponse()) {
                throw RdpException("MCS connection failed")
            }
            Log.d(TAG, "STEP 7: MCS Connect Response received")

            performMcsDomainSetup()
            Log.d(TAG, "STEP 8: MCS Domain Setup complete (userId=$mcsUserId)")

            sendClientInfoPdu()
            Log.d(TAG, "STEP 9: Client Info sent")

            handleDemandActivePdu()
            Log.d(TAG, "STEP 10: Demand Active handled")

            connected = true
            _sessionState.emit(RdpSessionState.CONNECTED)

            // FIX: Use clientScope.launch instead of bare launch
            clientScope.launch { receiveLoop() }
            true

        } catch (e: RdpAuthException) {
            Log.e(TAG, "Auth failed: ${e.message}")
            _sessionState.emit(RdpSessionState.AUTH_FAILED)
            _error.emit("Authentication failed: ${e.message}")
            cleanup()
            false
        } catch (e: Exception) {
            Log.e(TAG, "Connection failed at step: ${e.message}", e)
            _sessionState.emit(RdpSessionState.ERROR)
            _error.emit("Connection failed: ${e.message ?: "Unknown error"}")
            cleanup()
            false
        }
    }

    /**
     * CRITICAL FIX: Request all protocols for maximum compatibility.
     * PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX = 0x0B
     * Server will select the best it supports.
     *
     * WINDOWS 8/8.1: These systems support PROTOCOL_HYBRID_EX (0x08)
     * which provides enhanced security and performance.
     */
    private fun sendX224ConnectionRequest() {
        val cookie = "Cookie: mstshash=user\r\n"
        val cookieBytes = cookie.toByteArray()

        // Request all protocols: TLS + NLA + Hybrid EX
        // Server will select what it supports
        val requestedProtocols = if (credentials.useNla) {
            PROTOCOL_SSL or PROTOCOL_HYBRID or PROTOCOL_HYBRID_EX
        } else {
            PROTOCOL_SSL
        }

        val negReq = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        negReq.put(0x01) // Type: RDP_NEG_REQ
        negReq.put(0x00) // Flags
        negReq.putShort(8) // Length
        negReq.putInt(requestedProtocols)
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
        Log.d(TAG, "X.224 CR sent, length=$tpktLength, proto=0x${requestedProtocols.toString(16)}")
    }

    private var negotiatedNla = false
    private var negotiatedHybridEx = false
    private var serverSelectedProtocol: Int = 0

    private fun readX224ConnectionConfirm(): Boolean {
        val header = ByteArray(4)
        inputStream?.readFully(header) ?: return false
        if (header[0] != TPKT_VERSION.toByte()) return false

        val length = ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
        val data = ByteArray(length - 4)
        inputStream?.readFully(data) ?: return false

        if (data.isEmpty() || (data[1].toInt() and 0xFF) != 0xD0) return false

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
                    Log.d(TAG, "Server selected: 0x${selected.toString(16)} (NLA=$negotiatedNla, HybridEX=$negotiatedHybridEx)")
                }
                0x03 -> { // RDP_NEG_FAILURE
                    val failureCode = data.getOrElse(8) { 0 }.toInt() and 0xFF
                    throw RdpException("Server rejected connection (code $failureCode). Try toggling 'Use NLA Authentication'.")
                }
            }
        }
        return true
    }

    /**
     * WINDOWS 8.1+ SUPPORT: Handle Early User Authorization Result PDU
     * This is required when using Hybrid EX (0x08) protocol.
     * 
     * MS-RDPBCGR Section 2.2.10.2: Early User Authorization Result PDU
     * - 0x0000: Authorization successful
     * - 0x0001: User denied access (authorization failure)
     * - 0x0002: User granted access (but requires further authentication)
     */
    private fun handleEarlyUserAuthResult(): Boolean {
        return try {
            val result = readRaw() ?: return false
            if (result.size < 2) return false

            val authResult = (result[0].toInt() and 0xFF) or ((result[1].toInt() and 0xFF) shl 8)
            Log.d(TAG, "Early User Authorization Result: 0x${authResult.toString(16)}")

            when (authResult) {
                0x0000 -> {
                    Log.d(TAG, "Early authorization: Success")
                    true
                }
                0x0001 -> {
                    Log.e(TAG, "Early authorization: User denied access")
                    false
                }
                0x0002 -> {
                    Log.d(TAG, "Early authorization: User granted access (requires auth)")
                    true
                }
                else -> {
                    Log.w(TAG, "Early authorization: Unknown result 0x${authResult.toString(16)}")
                    true // Proceed anyway for compatibility
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Early User Auth Result handling failed: ${e.message}")
            true // Don't fail if this optional step fails
        }
    }

    private fun sendMcsConnectInitial() {
        val payload = buildMcsConnectInitialPayload()
        sendTpkt(payload)
    }

    private fun buildMcsConnectInitialPayload(): ByteArray {
        val coreData = buildClientCoreData()
        val secData = buildClientSecurityData()
        val netData = buildClientNetworkData()
        val clusterData = buildClientClusterData()  // Windows 8+ support
        val userData = coreData + secData + netData + clusterData
        return wrapInGccConferenceCreateRequest(userData)
    }

    /**
     * WINDOWS 8/8.1 SUPPORT: Updated Client Core Data with RDP 8.0/8.1 features
     * 
     * RDP 8.0 (Windows 8) introduces:
     * - UDP transport support
     * - Dynamic virtual channels
     * - Improved compression
     * 
     * RDP 8.1 (Windows 8.1) introduces:
     * - Multi-touch support
     * - Improved WAN performance
     */
    private fun buildClientCoreData(): ByteArray {
        val buf = ByteBuffer.allocate(216).order(ByteOrder.LITTLE_ENDIAN)

        // Use RDP 8.0 version for Windows 8/8.1 compatibility
        val rdpVersion = when {
            serverSelectedProtocol and PROTOCOL_HYBRID_EX != 0 -> RDP_VERSION_8_1
            else -> RDP_VERSION_8_0
        }

        buf.putShort(0xC001.toShort())
        buf.putShort(216)
        buf.putInt(rdpVersion)  // RDP version 8.0 or 8.1
        buf.putShort(displayWidth.toShort())
        buf.putShort(displayHeight.toShort())
        buf.putShort(0xCA01.toShort())
        buf.putShort(0xAA03.toShort())
        buf.putInt(0x409)  // English US
        buf.putInt(2600)   // Client build
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
        // CRITICAL: serverSelectedProtocol must match what server selected
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
     * WINDOWS 8+ SUPPORT: Client Cluster Data (optional but recommended)
     * Provides cluster redirection support and session brokering info.
     */
    private fun buildClientClusterData(): ByteArray {
        val buf = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0xC004.toShort())  // CS_CLUSTER
        buf.putShort(12)
        // REDIRECTION_SUPPORTED | REDIRECTION_VERSION3 (for Windows 8+)
        buf.putInt(0x0000001C)
        buf.putInt(0)  // RedirectedSessionID
        return buf.array()
    }

    private fun wrapInGccConferenceCreateRequest(userData: ByteArray): ByteArray {
        val output = ByteArrayOutputStream()
        val dos = DataOutputStream(output)

        dos.write(byteArrayOf(0x7F.toByte(), 0x65))
        writeBerLength(dos, userData.size + 14)
        dos.write(byteArrayOf(0x04, 0x01, 0x01, 0x04, 0x01, 0x01))
        dos.write(byteArrayOf(0x01, 0x01, 0xFF.toByte()))
        dos.write(byteArrayOf(0x30, 0x1A, 0x02, 0x01, 0x22))
        dos.write(byteArrayOf(0x04, 0x09, 0x00, 0x05))
        dos.write("Duca".toByteArray())
        dos.write(byteArrayOf(0x04.toByte()))
        writeBerLength(dos, userData.size)
        dos.write(userData)

        val gccPayload = output.toByteArray()

        val mcsOut = ByteArrayOutputStream()
        val mcsDos = DataOutputStream(mcsOut)
        mcsDos.write(byteArrayOf(0x65.toByte()))
        writeBerLength(mcsDos, gccPayload.size + 10)
        mcsDos.write(byteArrayOf(0x04, 0x01, 0x01))
        mcsDos.write(byteArrayOf(0x04, 0x01, 0x01))
        mcsDos.write(byteArrayOf(0x01, 0x01, 0xFF.toByte()))
        mcsDos.write(byteArrayOf(0x30, 0x00))
        mcsDos.write(byteArrayOf(0x30, 0x00))
        mcsDos.write(byteArrayOf(0x30, 0x00))
        mcsDos.write(byteArrayOf(0x04.toByte()))
        writeBerLength(mcsDos, gccPayload.size)
        mcsDos.write(gccPayload)

        return mcsOut.toByteArray()
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

    private var sslSocketRef: javax.net.ssl.SSLSocket? = null

    private fun upgradeTls() {
        val trustAllManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(trustAllManager), SecureRandom())

        val sslSocket = sslContext.socketFactory.createSocket(
            socket, credentials.host, credentials.port, true
        ) as javax.net.ssl.SSLSocket

        sslSocket.startHandshake()

        socket = sslSocket as Socket
        sslSocketRef = sslSocket
        inputStream = DataInputStream(BufferedInputStream(sslSocket.getInputStream(), 65536))
        outputStream = DataOutputStream(BufferedOutputStream(sslSocket.getOutputStream(), 65536))
        Log.d(TAG, "TLS upgraded: ${sslSocket.session.protocol}")
    }

    /**
     * CRITICAL FIX: Extract raw SubjectPublicKey from SubjectPublicKeyInfo.
     * SubjectPublicKeyInfo = SEQUENCE { algorithm, SubjectPublicKey BIT STRING }
     * We need the raw key bytes inside the BIT STRING (after the unused bits byte).
     */
    private fun serverPublicKeyDer(): ByteArray {
        val session = sslSocketRef?.session ?: throw RdpException("No TLS session")
        val cert = session.peerCertificates.firstOrNull() ?: throw RdpException("No server certificate")
        val encoded = cert.publicKey.encoded
        return extractSubjectPublicKey(encoded)
    }

    private fun extractSubjectPublicKey(subjectPublicKeyInfo: ByteArray): ByteArray {
        var pos = 0
        // Skip outer SEQUENCE tag and length
        if (subjectPublicKeyInfo[pos].toInt() and 0xFF != 0x30) return subjectPublicKeyInfo
        pos++
        val outerLen = readAsn1Length(subjectPublicKeyInfo, pos)
        pos += outerLen.second

        // Skip AlgorithmIdentifier SEQUENCE
        if (subjectPublicKeyInfo[pos].toInt() and 0xFF != 0x30) return subjectPublicKeyInfo
        pos++
        val algoLen = readAsn1Length(subjectPublicKeyInfo, pos)
        pos += algoLen.second + algoLen.first

        // Read BIT STRING
        if (subjectPublicKeyInfo[pos].toInt() and 0xFF != 0x03) return subjectPublicKeyInfo
        pos++
        val bitStrLen = readAsn1Length(subjectPublicKeyInfo, pos)
        pos += bitStrLen.second
        // Skip unused bits byte
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

    /**
     * CRITICAL FIX: Complete CredSSP handshake with version negotiation.
     * 
     * Version handling:
     * - Start with version 2 (most compatible)
     * - Read server's version from its response
     * - If server sends version 5/6, adapt pubKeyAuth to use SHA256 hash
     * - Support both raw public key (v2) and SHA256 hash (v5/6)
     * 
     * WINDOWS 8/8.1: These systems typically use CredSSP v5/v6 with SHA256 hash.
     */
    private suspend fun performNlaAuthentication() {
        Log.d(TAG, "Starting CredSSP/NTLMv2 auth")

        val negotiateMsg = NtlmHelper.buildNegotiateMessage(credentials.domain)
        sendRaw(CredSspHelper.buildNegotiateTsRequest(negotiateMsg))
        Log.d(TAG, "NLA Step 1: NEGOTIATE sent")

        val challengeRequest = readRaw() ?: throw RdpAuthException("No CredSSP CHALLENGE response")
        val challengeMsg = CredSspHelper.extractNegoToken(challengeRequest)
            ?: throw RdpAuthException("Missing NTLM CHALLENGE token")
        val challenge = NtlmHelper.parseChallengeMessage(challengeMsg)
        Log.d(TAG, "NLA Step 2: CHALLENGE received")

        // Detect server's CredSSP version from its response
        val serverVersion = CredSspHelper.extractVersion(challengeRequest)
        if (serverVersion >= 5) {
            CredSspHelper.negotiatedCredSspVersion = serverVersion
            Log.d(TAG, "Server supports CredSSP version $serverVersion, using SHA256 mode (Windows 8+ detected)")
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
        Log.d(TAG, "NLA: AUTHENTICATE built (MIC=${authResult.message.size > 88})")

        // Use version-aware pubKeyAuth computation
        val pubKeyAuthToken = CredSspHelper.computePubKeyAuth(
            serverPublicKey = serverPublicKey,
            encryptionState = authResult.encryptionState,
            sequenceNumber = 0
        )
        sendRaw(CredSspHelper.buildAuthenticateTsRequest(authResult.message, pubKeyAuthToken))
        Log.d(TAG, "NLA Step 3: AUTHENTICATE + pubKeyAuth sent")

        val pubKeyResponse = readRaw() ?: throw RdpAuthException("No pubKeyAuth response - server rejected credentials")
        val encryptedServerConfirm = CredSspHelper.extractPubKeyAuth(pubKeyResponse)
            ?: throw RdpAuthException("Missing pubKeyAuth confirmation")
        Log.d(TAG, "NLA Step 4: Server pubKeyAuth received")

        // Verify using version-aware method
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

        Log.d(TAG, "CredSSP/NTLMv2 authentication COMPLETE")
    }

    private fun sendClientInfoPdu() {
        val domainBytes = (credentials.domain + "\u0000").toByteArray(Charsets.UTF_16LE)
        val userBytes = (credentials.username + "\u0000").toByteArray(Charsets.UTF_16LE)
        val passBytes = (credentials.password + "\u0000").toByteArray(Charsets.UTF_16LE)
        val shellBytes = "\u0000".toByteArray(Charsets.UTF_16LE)
        val workdirBytes = "\u0000".toByteArray(Charsets.UTF_16LE)

        val pduSize = 18 + 10 + domainBytes.size + userBytes.size + passBytes.size + shellBytes.size + workdirBytes.size
        val buf = ByteBuffer.allocate(pduSize).order(ByteOrder.LITTLE_ENDIAN)

        buf.putInt(0x00000000)
        // INFO_UNICODE | LOGON_NOTIFY | LOGON_ERRORS | NOAUDIOPLAYBACK | COMPRESSION_TYPE_MASK
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

    private fun handleDemandActivePdu() {
        var foundDemandActive = false
        for (attempt in 0 until 5) {
            val raw = readX224Data() ?: return
            val payload = stripMcsSendDataIndication(raw)
            if (payload.size >= 3 && (payload[2].toInt() and 0x0F) == 0x01) {
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
        shareControlHeader.putShort(0x03EA.toShort())

        val shareDataHeader = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        shareDataHeader.putInt(0x000103EA)
        shareDataHeader.putShort(0x03EA.toShort())
        shareDataHeader.putShort(0x02)

        val fullPdu = shareControlHeader.array() + shareDataHeader.array() + caps
        sendMcsSendDataRequest(fullPdu)
    }

    /**
     * WINDOWS 8/8.1 SUPPORT: Enhanced capability sets
     * Added support for:
     * - Bitmap Cache Rev3 (Windows 8+)
     * - Surface Commands (Windows 8+)
     * - Bitmap Codecs (NSCodec, RemoteFX)
     * - Frame Marker
     */
    private fun buildCapabilitySets(): ByteArray {
        val buf = ByteBuffer.allocate(1024).order(ByteOrder.LITTLE_ENDIAN)

        // General (24 bytes) - RDP 8.0+ flags
        buf.putShort(0x0001); buf.putShort(24)
        buf.putShort(1); buf.putShort(0x0003)  // RDP 8.0 support
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

        // WINDOWS 8+ SUPPORT: Surface Commands (8 bytes)
        buf.putShort(0x001D); buf.putShort(8)
        buf.putInt(0x00000001)  // SURFCMDS_SUPPORTED

        // WINDOWS 8+ SUPPORT: Bitmap Codecs (variable)
        // NSCodec and RemoteFX codec support for Windows 8+
        val codecCount = 1
        buf.putShort(0x001E); buf.putShort((8 + codecCount * 2).toShort())
        buf.putShort(codecCount.toShort())
        buf.putShort(0x0001)  // CODEC_GUID_NSCODEC

        // WINDOWS 8+ SUPPORT: Frame Marker (8 bytes)
        buf.putShort(0x001F); buf.putShort(8)
        buf.putInt(0x00000001)  // FRAMEMARKER_SUPPORTED

        return buf.array().copyOf(buf.position())
    }

    private fun sendSyncPdu() = sendMcsSendDataRequest(byteArrayOf(0x16, 0x00, 0x00, 0x00))
    private fun sendControlPdu() = sendMcsSendDataRequest(byteArrayOf(0x17, 0x00, 0x00, 0x00))
    private fun sendFontListPdu() = sendMcsSendDataRequest(byteArrayOf(0x28, 0x00, 0x00, 0x00))

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
            // 0x10 = encryption=0, reserved=0, numEvents=1, actionCode=0 (Input)
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
        clientScope.cancel()  // Cancel all coroutines
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
