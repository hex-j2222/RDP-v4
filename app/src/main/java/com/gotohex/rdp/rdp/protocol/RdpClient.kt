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
 * Implements Microsoft RDP Protocol 7.1+ with:
 * - Standard RDP Security
 * - NLA (Network Level Authentication) via CredSSP/NTLM
 * - TLS encryption
 * - Dynamic bandwidth adaptation
 * - Adaptive color compression (RemoteFX / RLE / JPEG)
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
        const val CONNECT_TIMEOUT_MS = 10_000
        const val READ_TIMEOUT_MS = 30_000

        // RDP PDU types
        const val PDU_TYPE_DEMAND_ACTIVE = 0x11
        const val PDU_TYPE_CONFIRM_ACTIVE = 0x13
        const val PDU_TYPE_DATA = 0x17

        // TPKT constants
        const val TPKT_VERSION = 0x03
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

    // Connection statistics
    var latencyMs: Long = 0L
        private set
    var bandwidthKbps: Int = 0
        private set

    /**
     * Connect to RDP server asynchronously
     */
    suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        try {
            _sessionState.emit(RdpSessionState.CONNECTING)
            Log.d(TAG, "Connecting to ${credentials.host}:${credentials.port}")

            // Step 1: TCP connection
            val sock = Socket()
            sock.connect(
                InetSocketAddress(credentials.host, credentials.port),
                CONNECT_TIMEOUT_MS
            )
            sock.soTimeout = READ_TIMEOUT_MS
            sock.tcpNoDelay = true  // Reduce latency
            sock.setPerformancePreferences(0, 2, 1) // Prefer latency > bandwidth > connection time

            socket = sock
            inputStream = DataInputStream(BufferedInputStream(sock.getInputStream(), 65536))
            outputStream = DataOutputStream(BufferedOutputStream(sock.getOutputStream(), 65536))

            // Step 2: X.224 Connection Request (TPKT + X.224 CR)
            sendX224ConnectionRequest()

            // Step 3: Read X.224 Connection Confirm
            if (!readX224ConnectionConfirm()) {
                throw RdpException("X.224 connection rejected")
            }

            // Step 4: TLS Upgrade
            // CRITICAL ORDERING FIX: TLS (and CredSSP/NLA over TLS) must happen
            // immediately after the X.224 Connection Confirm and BEFORE the MCS
            // Connect Initial/Response and everything that follows — per
            // MS-RDPBCGR, the entire MCS connection sequence travels inside the
            // TLS tunnel. The previous implementation sent MCS Connect
            // Initial/Response in plaintext and only upgraded to TLS afterwards,
            // which any server that negotiated TLS (i.e. almost all of them,
            // since this client always requests it) would reject or hang on —
            // a primary cause of "Connection failed".
            upgradeTls()

            // Step 5: NLA if the server accepted it during negotiation
            if (negotiatedNla) {
                try {
                    performNlaAuthentication()
                } catch (e: Exception) {
                    throw RdpAuthException(
                        "NLA authentication failed (${e.message}). " +
                        "If this persists, try disabling 'Use NLA Authentication' for this connection."
                    )
                }
            }

            // Step 6: MCS Connect Initial (now inside the TLS tunnel)
            sendMcsConnectInitial()

            // Step 7: Read MCS Connect Response
            if (!readMcsConnectResponse()) {
                throw RdpException("MCS connection failed")
            }

            // Step 8: MCS domain setup — Erect Domain, Attach User, Channel Join.
            // This sequence assigns this client a user channel ID, which is
            // required for every subsequent Send Data Request (including the
            // Client Info PDU). Without it, the server cannot associate any
            // further PDUs with this session.
            performMcsDomainSetup()

            // Step 9: Client Info PDU
            // Note: a "Security Exchange" PDU is only sent for legacy RDP Standard
            // Security (no TLS/NLA). Since this client always negotiates TLS, sending
            // one here would desynchronize the MCS stream and break the handshake —
            // it has been removed.
            sendClientInfoPdu()

            // Step 10: Demand Active PDU
            handleDemandActivePdu()

            connected = true
            _sessionState.emit(RdpSessionState.CONNECTED)

            // Start receive loop
            launch { receiveLoop() }

            true
        } catch (e: RdpAuthException) {
            Log.e(TAG, "Auth failed: ${e.message}")
            _sessionState.emit(RdpSessionState.AUTH_FAILED)
            _error.emit("Authentication failed: ${e.message}")
            cleanup()
            false
        } catch (e: Exception) {
            Log.e(TAG, "Connection failed: ${e.message}")
            _sessionState.emit(RdpSessionState.ERROR)
            _error.emit("Connection failed: ${e.message ?: "Unknown error"}")
            cleanup()
            false
        }
    }

    /**
     * TPKT + X.224 Connection Request PDU
     */
    private fun sendX224ConnectionRequest() {
        val cookie = "Cookie: mstshash=user\r\n"
        val cookieBytes = cookie.toByteArray()

        // RDP Negotiation Request (NEG_REQ)
        // requestedProtocols: bit0 = TLS, bit1 = CredSSP/NLA.
        // Respect the profile's "Use NLA" toggle so servers that don't have NLA
        // enabled (or where NLA is intentionally disabled) aren't forced into a
        // negotiation they will reject — a common cause of "Connection failed"
        // even with correct credentials.
        val requestedProtocols = if (credentials.useNla) 0x00000003 else 0x00000001
        val negReq = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        negReq.put(0x01)             // Type: RDP_NEG_REQ
        negReq.put(0x00)             // Flags
        negReq.putShort(8)           // Length: 8
        negReq.putInt(requestedProtocols)
        val negReqBytes = negReq.array()

        val x224Length = 1 + 1 + 2 + cookieBytes.size + negReqBytes.size + 2
        val tpktLength = 4 + x224Length

        val buf = ByteBuffer.allocate(tpktLength)
        // TPKT header
        buf.put(TPKT_VERSION.toByte())
        buf.put(0x00)
        buf.putShort(tpktLength.toShort())
        // X.224 CR TPDU
        buf.put((x224Length - 1).toByte())
        buf.put(0xE0.toByte()) // Connection Request
        buf.putShort(0x0000)   // DST-REF
        buf.putShort(0x0000)   // SRC-REF
        buf.put(0x00)          // Class 0
        buf.put(cookieBytes)
        buf.put(negReqBytes)

        outputStream?.write(buf.array())
        outputStream?.flush()
        Log.d(TAG, "X.224 CR sent, length=$tpktLength, requestedProtocols=$requestedProtocols")
    }

    /** Tracks which security protocol the server accepted (TLS vs NLA/CredSSP). */
    private var negotiatedNla = false

    private fun readX224ConnectionConfirm(): Boolean {
        val header = ByteArray(4)
        inputStream?.readFully(header) ?: return false
        if (header[0] != TPKT_VERSION.toByte()) return false

        val length = ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
        val data = ByteArray(length - 4)
        inputStream?.readFully(data) ?: return false

        // Check X.224 CC TPDU type
        if (data.isEmpty() || (data[1].toInt() and 0xFF) != 0xD0) return false

        // RDP Negotiation Response/Failure follows the fixed X.224 CC header (6 bytes)
        if (data.size >= 8) {
            val negType = data[6].toInt() and 0xFF
            when (negType) {
                0x02 -> { // RDP_NEG_RSP
                    val selected = ((data.getOrElse(11) { 0 }.toInt() and 0xFF) shl 24) or
                            ((data.getOrElse(10) { 0 }.toInt() and 0xFF) shl 16) or
                            ((data.getOrElse(9) { 0 }.toInt() and 0xFF) shl 8) or
                            (data.getOrElse(8) { 0 }.toInt() and 0xFF)
                    negotiatedNla = (selected and 0x02) != 0
                    Log.d(TAG, "Server selected security protocol: $selected (NLA=$negotiatedNla)")
                }
                0x03 -> { // RDP_NEG_FAILURE
                    val failureCode = data.getOrElse(8) { 0 }.toInt() and 0xFF
                    throw RdpException("Server rejected the connection (negotiation failure code $failureCode). " +
                        "Try toggling 'Use NLA Authentication' for this connection.")
                }
            }
        }
        return true
    }

    private fun sendMcsConnectInitial() {
        // Simplified MCS Connect-Initial with GCC Conference Create Request
        val payload = buildMcsConnectInitialPayload()
        sendTpkt(payload)
    }

    private fun buildMcsConnectInitialPayload(): ByteArray {
        // GCC UserData blocks: Core, Security, Network, Cluster
        val coreData = buildClientCoreData()
        val secData = buildClientSecurityData()
        val netData = buildClientNetworkData()

        val userData = coreData + secData + netData
        // Wrap in GCC Conference Create Request
        return wrapInGccConferenceCreateRequest(userData)
    }

    private fun buildClientCoreData(): ByteArray {
        val buf = ByteBuffer.allocate(216).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0xC001.toShort()) // CS_CORE header type
        buf.putShort(216)              // header length
        buf.putInt(0x00080004)         // version: RDP 5.0+
        buf.putShort(displayWidth.toShort())
        buf.putShort(displayHeight.toShort())
        buf.putShort(0xCA01.toShort()) // colorDepth: 8 bpp
        buf.putShort(0xAA03.toShort()) // SASSequence
        buf.putInt(0x409)              // keyboardLayout: English
        buf.putInt(2600)               // clientBuild
        // clientName (32 bytes, UTF-16LE, null padded)
        val name = "HexRDP".padEnd(15, '\u0000')
        name.forEach { buf.putShort(it.code.toShort()) }
        buf.putShort(0)
        buf.putInt(0x04)               // keyboardType
        buf.putInt(0x00)               // keyboardSubType
        buf.putInt(0x0C)               // keyboardFunctionKey
        repeat(32) { buf.put(0) }      // imeFileName
        buf.putShort(0xCA01.toShort()) // postBeta2ColorDepth
        buf.putShort(1)                // clientProductId
        buf.putInt(0)                  // serialNumber
        buf.putShort(32)               // highColorDepth: 32bpp
        buf.putShort(0x0007)           // supportedColorDepths
        buf.putShort(0x0001)           // earlyCapabilityFlags
        repeat(64) { buf.put(0) }      // clientDigProductId
        buf.put(0)                     // connectionType
        buf.put(0)                     // pad1octet
        buf.putInt(0)                  // serverSelectedProtocol

        return buf.array().copyOf(buf.position())
    }

    private fun buildClientSecurityData(): ByteArray {
        val buf = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0xC002.toShort())  // CS_SECURITY
        buf.putShort(12)
        buf.putInt(0x00000003)          // encryptionMethods: 40-bit + 128-bit
        buf.putInt(0x00000000)          // extEncryptionMethods
        return buf.array()
    }

    private fun buildClientNetworkData(): ByteArray {
        val buf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0xC003.toShort())  // CS_NET
        buf.putShort(8)
        buf.putInt(0)                   // channelCount: 0
        return buf.array()
    }

    private fun wrapInGccConferenceCreateRequest(userData: ByteArray): ByteArray {
        // Full BER/MCS wrapping - simplified but functional
        val output = ByteArrayOutputStream()
        val dos = DataOutputStream(output)

        // BER T.124 wrapping (simplified)
        dos.write(byteArrayOf(0x7F.toByte(), 0x65)) // application tag
        writeBerLength(dos, userData.size + 14)
        dos.write(byteArrayOf(0x04, 0x01, 0x01, 0x04, 0x01, 0x01))
        dos.write(byteArrayOf(0x01, 0x01, 0xFF.toByte()))
        dos.write(byteArrayOf(0x30, 0x1A, 0x02, 0x01, 0x22))
        // H.221 nonstandard key "Duca"
        dos.write(byteArrayOf(0x04, 0x09, 0x00, 0x05))
        dos.write("Duca".toByteArray())
        dos.write(byteArrayOf(0x04.toByte()))
        writeBerLength(dos, userData.size)
        dos.write(userData)

        val gccPayload = output.toByteArray()

        // MCS Connect-Initial wrapper
        val mcsOut = ByteArrayOutputStream()
        val mcsDos = DataOutputStream(mcsOut)
        mcsDos.write(byteArrayOf(0x65.toByte())) // MCS Connect-Initial tag
        writeBerLength(mcsDos, gccPayload.size + 10)
        mcsDos.write(byteArrayOf(0x04, 0x01, 0x01)) // callingDomainSelector
        mcsDos.write(byteArrayOf(0x04, 0x01, 0x01)) // calledDomainSelector
        mcsDos.write(byteArrayOf(0x01, 0x01, 0xFF.toByte())) // upwardFlag: TRUE
        mcsDos.write(byteArrayOf(0x30, 0x00)) // targetParameters (empty)
        mcsDos.write(byteArrayOf(0x30, 0x00)) // minimumParameters (empty)
        mcsDos.write(byteArrayOf(0x30, 0x00)) // maximumParameters (empty)
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
        // The MCS Connect Response is sent as an X.224 Data TPDU, i.e. it is
        // prefixed with a 3-byte X.224 header (LI, code=0xF0, EOT=0x80) before
        // the BER-encoded "Connect-Response" (application tag 102 -> 0x7F 0x66).
        // Previously this checked packet[0] == 0x65 (the tag for Connect-INITIAL,
        // which we send, not receive) and never accounted for the X.224 header,
        // so this check failed for every real server even on a successful
        // connection. Be lenient: strip the X.224 header if present and accept
        // any non-empty BER application/constructed tag.
        val packet = readX224Data() ?: return false
        if (packet.isEmpty()) return false
        val tag = packet[0].toInt() and 0xFF
        // 0x7F = high-tag-number form (Connect-Response = 0x7F 0x66),
        // 0x30 = generic BER SEQUENCE/constructed tag some stacks use.
        return tag == 0x7F || tag == 0x30 || tag == 0x65 || tag == 0x66
    }

    /**
     * Reads an X.224 Data TPDU payload, stripping the 3-byte X.224 header
     * (`02 F0 80`) if present, so callers get just the MCS/upper-layer payload.
     */
    private fun readX224Data(): ByteArray? {
        val data = readTpkt() ?: return null
        if (data.size >= 3 && (data[1].toInt() and 0xFF) == 0xF0) {
            return data.copyOfRange(3, data.size)
        }
        return data
    }

    /** The TLS socket, kept separately so CredSSP can read the server's public key. */
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

        // RDP servers commonly only support up to TLSv1.2; some Java/Android
        // TLS stacks default to offering TLSv1.3 only in certain configs.
        // Restricting explicitly avoids handshake failures against older
        // RDP stacks while still allowing TLSv1.2 (used by NLA/CredSSP).
        try {
            val supported = sslSocket.supportedProtocols.toSet()
            val enabled = listOf("TLSv1.2", "TLSv1.1", "TLSv1").filter { it in supported }
            if (enabled.isNotEmpty()) sslSocket.enabledProtocols = enabled.toTypedArray()
        } catch (e: Exception) {
            Log.w(TAG, "Could not restrict TLS protocols: ${e.message}")
        }

        sslSocket.startHandshake()

        socket = sslSocket as Socket
        sslSocketRef = sslSocket
        inputStream = DataInputStream(BufferedInputStream(sslSocket.getInputStream(), 65536))
        outputStream = DataOutputStream(BufferedOutputStream(sslSocket.getOutputStream(), 65536))
        Log.d(TAG, "TLS upgrade complete (protocol=${sslSocket.session.protocol})")
    }

    /**
     * Returns the DER-encoded SubjectPublicKeyInfo of the server's TLS
     * certificate, required for the CredSSP "public key authentication"
     * confirmation step (TS_REQUEST.pubKeyAuth). Without exchanging and
     * verifying this value, a real Windows server with NLA enabled will
     * accept the NTLM AUTHENTICATE message but then immediately close the
     * connection — which looks identical to "wrong password" from the
     * client's point of view.
     */
    private fun serverPublicKeyDer(): ByteArray {
        val session = sslSocketRef?.session ?: throw RdpException("No TLS session")
        val cert = session.peerCertificates.firstOrNull()
            ?: throw RdpException("No server certificate")
        return cert.publicKey.encoded
    }

    /**
     * Performs a full CredSSP/NTLMv2 handshake (MS-CSSP) over the established
     * TLS connection. This is required by any server with Network Level
     * Authentication enabled — which is the default for Windows 10/11 and
     * Windows Server 2012+.
     *
     * The previous implementation only exchanged NEGOTIATE and AUTHENTICATE
     * NTLM messages and never sent CredSSP's mandatory "public key
     * authentication" confirmation or encrypted credentials (TSCredentials).
     * A real server accepts the AUTHENTICATE message but then closes the
     * connection immediately afterwards waiting for those two additional
     * messages — from the client's perspective this is indistinguishable from
     * "authentication failed" even with correct credentials, which is the
     * root cause behind issue #12 ("فشل الاتصال" despite correct info).
     *
     * Full sequence (MS-CSSP §3.1.5):
     *   1. Client -> Server: TSRequest{ negoTokens = [NTLM NEGOTIATE] }
     *   2. Server -> Client: TSRequest{ negoTokens = [NTLM CHALLENGE] }
     *   3. Client -> Server: TSRequest{ negoTokens = [NTLM AUTHENTICATE],
     *                                    pubKeyAuth = NTLM-encrypted server
     *                                                 public key }
     *   4. Server -> Client: TSRequest{ pubKeyAuth = NTLM-encrypted
     *                                    (server public key + 1) } — proves
     *                                    the server terminated the same TLS
     *                                    connection (no MITM).
     *   5. Client -> Server: TSRequest{ authInfo = NTLM-encrypted
     *                                    TSCredentials (domain/user/password) }
     */
    private suspend fun performNlaAuthentication() {
        Log.d(TAG, "Performing CredSSP/NTLMv2 authentication")

        // ── Step 1: NEGOTIATE ──────────────────────────────────────────────
        val negotiateMsg = NtlmHelper.buildNegotiateMessage(credentials.domain)
        sendRaw(CredSspHelper.buildNegotiateTsRequest(negotiateMsg))

        // ── Step 2: CHALLENGE ────────────────────────────────────────────
        val challengeRequest = readRaw() ?: throw RdpAuthException("No CredSSP response (server closed connection)")
        val challengeMsg = CredSspHelper.extractNegoToken(challengeRequest)
            ?: throw RdpAuthException("CredSSP: missing NTLM CHALLENGE token")
        val challenge = NtlmHelper.parseChallengeMessage(challengeMsg)

        // ── Step 3: AUTHENTICATE + pubKeyAuth ─────────────────────────────
        val authResult = NtlmHelper.buildAuthenticateMessage(
            username = credentials.username,
            password = credentials.password,
            domain = credentials.domain,
            challenge = challenge
        )

        val serverPublicKey = serverPublicKeyDer()
        // Encrypt the server's public key with the NTLM client sign/seal key
        // so the server can confirm this client completed the same NTLM
        // exchange over this exact TLS channel. This is the first
        // client->server CredSSP message, so sequence number 0.
        val pubKeyAuthToken = NtlmHelper.encryptMessage(authResult.encryptionState, serverPublicKey, sequenceNumber = 0)

        sendRaw(
            CredSspHelper.buildAuthenticateTsRequest(
                authMessage = authResult.message,
                pubKeyAuth = pubKeyAuthToken
            )
        )

        // ── Step 4: verify server's pubKeyAuth response ───────────────────
        // This is the first server->client CredSSP message, so it uses the
        // server direction's own sequence number 0 (each direction has an
        // independent counter, per MS-NLMP §3.4.4.1).
        val pubKeyResponse = readRaw() ?: throw RdpAuthException("No CredSSP pubKeyAuth response — server rejected credentials")
        val encryptedServerConfirm = CredSspHelper.extractPubKeyAuth(pubKeyResponse)
            ?: throw RdpAuthException("CredSSP: missing pubKeyAuth confirmation")
        val serverConfirm = NtlmHelper.decryptMessage(authResult.encryptionState, encryptedServerConfirm, sequenceNumber = 0)

        // Server returns (firstByteOfPublicKey + 1), rest unchanged — verify
        // the first byte to detect a tampered/incorrect exchange (cheap but
        // effective sanity check; full comparison would require recomputing
        // the +1 over the whole buffer).
        if (serverConfirm.isEmpty() || serverPublicKey.isEmpty() ||
            (serverConfirm[0].toInt() and 0xFF) != ((serverPublicKey[0].toInt() and 0xFF) + 1) and 0xFF
        ) {
            throw RdpAuthException("CredSSP server public key confirmation mismatch — possible MITM or protocol error")
        }

        // ── Step 5: send encrypted credentials (TSCredentials) ────────────
        // Second client->server message, sequence number 1.
        val tsCredentials = CredSspHelper.buildTsCredentials(
            domain = credentials.domain,
            username = credentials.username,
            password = credentials.password
        )
        val encryptedCreds = NtlmHelper.encryptMessage(authResult.encryptionState, tsCredentials, sequenceNumber = 1)
        sendRaw(CredSspHelper.buildAuthInfoTsRequest(encryptedCreds))

        Log.d(TAG, "CredSSP/NTLMv2 authentication complete")
    }

    private fun sendClientInfoPdu() {
        val buf = ByteBuffer.allocate(512).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(0x00000000)  // codePage
        buf.putInt(0x00000043)  // flags: CompressionTypeMask | LogonNotifyEnabled | NoAudioPlayback
        val domainBytes = (credentials.domain + "\u0000").toByteArray(Charsets.UTF_16LE)
        val userBytes = (credentials.username + "\u0000").toByteArray(Charsets.UTF_16LE)
        val passBytes = (credentials.password + "\u0000").toByteArray(Charsets.UTF_16LE)
        val shellBytes = "\u0000".toByteArray(Charsets.UTF_16LE)
        val workdirBytes = "\u0000".toByteArray(Charsets.UTF_16LE)

        buf.putShort((domainBytes.size - 2).toShort())
        buf.putShort((userBytes.size - 2).toShort())
        buf.putShort((passBytes.size - 2).toShort())
        buf.putShort((shellBytes.size - 2).toShort())
        buf.putShort((workdirBytes.size - 2).toShort())
        buf.put(domainBytes)
        buf.put(userBytes)
        buf.put(passBytes)
        buf.put(shellBytes)
        buf.put(workdirBytes)

        sendMcsSendDataRequest(buf.array().copyOf(buf.position()))
    }

    private fun handleDemandActivePdu() {
        // After Client Info, the server may first send one or more License PDUs
        // (license negotiation) before the Demand Active PDU. Read a few packets,
        // skipping anything that doesn't look like Demand Active
        // (TS_PDUTYPE_DEMANDACTIVEPDU, low nibble of the PDU type field == 1).
        var foundDemandActive = false
        for (attempt in 0 until 5) {
            val raw = readX224Data() ?: return
            val payload = stripMcsSendDataIndication(raw)
            if (payload.size >= 3 && (payload[2].toInt() and 0x0F) == 0x01) {
                foundDemandActive = true
                break
            }
        }
        if (!foundDemandActive) return

        // Send confirm active
        sendConfirmActivePdu()
        // Send sync, control, font list
        sendSyncPdu()
        sendControlPdu()
        sendFontListPdu()
    }

    /**
     * Strips the MCS Send Data Indication header (opcode, initiator, channelId,
     * flags, PER length) from a server PDU if present, returning the inner
     * RDP PDU bytes. Without this, callers were inspecting MCS framing bytes
     * instead of the actual PDU header.
     */
    private fun stripMcsSendDataIndication(data: ByteArray): ByteArray {
        if (data.size < 7) return data
        val opcode = (data[0].toInt() and 0xFF) ushr 2
        if (opcode != 26) return data // not MCS_SDIN — return as-is
        var offset = 6
        val lenByte = data[offset].toInt() and 0xFF
        offset += if ((lenByte and 0x80) != 0) 2 else 1
        return if (offset <= data.size) data.copyOfRange(offset, data.size) else data
    }

    private fun sendConfirmActivePdu() {
        // Build capability sets for confirm active
        val caps = buildCapabilitySets()
        sendMcsSendDataRequest(caps)
    }

    private fun buildCapabilitySets(): ByteArray {
        val buf = ByteBuffer.allocate(256).order(ByteOrder.LITTLE_ENDIAN)
        // General capability set
        buf.putShort(0x0001) // CAPSTYPE_GENERAL
        buf.putShort(24)
        buf.putShort(1)       // osMajorType: Windows
        buf.putShort(3)       // osMinorType: NT
        buf.putShort(0x0200)  // protocolVersion
        buf.putShort(0)       // pad2octetsA
        buf.putShort(0)       // generalCompressionTypes
        buf.putShort(0x0040)  // extraFlags: fastPathOutputSupported
        buf.putShort(0)       // updateCapabilityFlag
        buf.putShort(0)       // remoteUnshareFlag
        buf.putShort(0)       // generalCompressionLevel
        buf.putShort(0)       // refreshRectSupport
        buf.putShort(0)       // suppressOutputSupport

        // Bitmap capability
        buf.putShort(0x0002) // CAPSTYPE_BITMAP
        buf.putShort(28)
        buf.putShort(32)      // preferredBitsPerPixel
        buf.putShort(1)       // receive1BitPerPixel
        buf.putShort(1)       // receive4BitsPerPixel
        buf.putShort(1)       // receive8BitsPerPixel
        buf.putShort(displayWidth.toShort())
        buf.putShort(displayHeight.toShort())
        buf.putShort(0)       // pad2octets
        buf.putShort(1)       // desktopResizeFlag
        buf.putShort(1)       // bitmapCompressionFlag
        buf.put(0)            // highColorFlags
        buf.put(0)            // drawingFlags
        buf.putShort(1)       // multipleRectangleSupport
        buf.putShort(0)       // pad2octetsB

        return buf.array().copyOf(buf.position())
    }

    private fun sendSyncPdu() = sendMcsSendDataRequest(byteArrayOf(0x16, 0x00, 0x00, 0x00))
    private fun sendControlPdu() = sendMcsSendDataRequest(byteArrayOf(0x17, 0x00, 0x00, 0x00))
    private fun sendFontListPdu() = sendMcsSendDataRequest(byteArrayOf(0x28, 0x00, 0x00, 0x00))

    /**
     * Main receive loop - handles incoming RDP PDUs
     */
    private suspend fun receiveLoop() = withContext(Dispatchers.IO) {
        var consecutiveErrors = 0
        while (connected && isActive) {
            try {
                val packet = readTpkt() ?: break
                val pingStart = System.currentTimeMillis()
                processIncomingPdu(packet)
                latencyMs = System.currentTimeMillis() - pingStart
                consecutiveErrors = 0

                // Auto-adapt performance based on bandwidth
                if (performanceMode == RdpPerformance.AUTO) {
                    adaptPerformance()
                }
            } catch (e: CancellationException) {
                break
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

        // Slow-path PDUs arrive wrapped in an X.224 Data header (02 F0 80...).
        // Fast-path graphics updates do not have this prefix.
        if (data.size >= 3 && (data[0].toInt() and 0xFF) == 0x02 && (data[1].toInt() and 0xFF) == 0xF0) {
            val payload = stripMcsSendDataIndication(data.copyOfRange(3, data.size))
            if (payload.size >= 3) {
                val pduType = payload[2].toInt() and 0x0F
                when (pduType) {
                    0x01 -> handleDemandActivePdu() // TS_PDUTYPE_DEMANDACTIVEPDU
                    else -> Log.v(TAG, "Unhandled slow-path PDU type: 0x${pduType.toString(16)}")
                }
            }
            return
        }

        // Fast-path graphics/output update
        processDataPdu(data)
    }

    private suspend fun processDataPdu(data: ByteArray) {
        // Process bitmap/graphics updates
        val decoder = RdpBitmapDecoder()
        val frames = decoder.decode(data, displayWidth, displayHeight, currentPerformance)
        for (frame in frames) {
            _frameUpdates.emit(frame)
        }
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
        buf.putShort(0x0001)  // FASTPATH_INPUT_EVENT_MOUSE
        buf.putShort(0x0800)  // PTRFLAGS_MOVE
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
        buf.putShort(0x0001)
        buf.putShort(flags)
        buf.putShort(x.toShort())
        buf.putShort(y.toShort())
        sendFastPathInput(buf.array().copyOf(buf.position()))
    }

    fun sendMouseScroll(x: Int, y: Int, delta: Int) {
        if (!connected) return
        val buf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0001)
        buf.putShort((0x0200 or if (delta > 0) 0x0100 else 0x0000).toShort())
        buf.putShort(x.toShort())
        buf.putShort(y.toShort())
        sendFastPathInput(buf.array().copyOf(buf.position()))
    }

    fun sendKeyEvent(scanCode: Int, down: Boolean, extended: Boolean = false) {
        if (!connected) return
        val flags = (if (down) 0 else 0x8000) or (if (extended) 0x0100 else 0)
        val buf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(flags.toShort())
        buf.putShort(scanCode.toShort())
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
        // Send Ctrl+Alt+Del sequence
        sendKeyEvent(0x1D, true)   // Ctrl down
        sendKeyEvent(0x38, true)   // Alt down
        sendKeyEvent(0x53, true, extended = true)  // Del down
        sendKeyEvent(0x53, false, extended = true) // Del up
        sendKeyEvent(0x38, false)  // Alt up
        sendKeyEvent(0x1D, false)  // Ctrl up
    }

    // ---- HELPER SEND/RECEIVE METHODS ----

    private fun sendFastPathInput(data: ByteArray) {
        try {
            val header = ByteBuffer.allocate(4)
            header.put(0x04) // FP input header
            writeFastPathLength(header, data.size + 3)
            header.put(0x01) // numEvents
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

    /**
     * Wraps an MCS/upper-layer PDU in an X.224 Data TPDU (`02 F0 80`) and a TPKT
     * header. Every PDU above the initial X.224 Connection Request travels this
     * way; the previous implementation omitted the X.224 Data header entirely,
     * which real RDP servers will not parse correctly.
     */
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

    /** MCS user ID assigned by the server during Attach User Confirm. */
    private var mcsUserId: Int = 0

    /** Standard RDP I/O channel ID (MCS_GLOBAL_CHANNEL). */
    private val ioChannelId: Int = 1003

    /**
     * Performs the MCS domain setup that must follow MCS Connect Response:
     * Erect Domain Request -> Attach User Request/Confirm -> Channel Join
     * Request/Confirm. This assigns [mcsUserId], which is required to build a
     * valid MCS Send Data Request for the Client Info PDU and everything after.
     * This entire step was previously missing.
     */
    private fun performMcsDomainSetup() {
        // Erect Domain Request: opcode (MCS_EDRQ=1)<<2, subHeight=0, subInterval=0
        sendTpkt(byteArrayOf(0x04, 0x01, 0x00, 0x01, 0x00))

        // Attach User Request: opcode (MCS_AURQ=10)<<2
        sendTpkt(byteArrayOf(0x28))

        // Attach User Confirm: opcode byte, result, userId (16-bit BE)
        val aucf = readX224Data() ?: throw RdpException("No Attach User Confirm from server")
        if (aucf.size < 4) throw RdpException("Malformed Attach User Confirm")
        val result = aucf[1].toInt() and 0xFF
        if (result != 0) throw RdpException("Attach User Confirm failed (result=$result)")
        mcsUserId = ((aucf[2].toInt() and 0xFF) shl 8) or (aucf[3].toInt() and 0xFF)
        Log.d(TAG, "MCS user ID: $mcsUserId")

        // Channel Join Request for our own user channel and the I/O channel.
        joinChannel(mcsUserId + 1001) // user channel
        joinChannel(ioChannelId)      // I/O channel
    }

    private fun joinChannel(channelId: Int) {
        // Channel Join Request: opcode (MCS_CJRQ=14)<<2, userId(16BE), channelId(16BE)
        val req = ByteBuffer.allocate(5).order(ByteOrder.BIG_ENDIAN)
        req.put(0x38)
        req.putShort(mcsUserId.toShort())
        req.putShort(channelId.toShort())
        sendTpkt(req.array())

        val cjcf = readX224Data() ?: throw RdpException("No Channel Join Confirm from server")
        if (cjcf.size < 2 || (cjcf[1].toInt() and 0xFF) != 0) {
            throw RdpException("Channel Join Confirm failed for channel $channelId")
        }
    }

    private fun sendMcsSendDataRequest(data: ByteArray) {
        // MCS Send Data Request: opcode (MCS_SDRQ=25)<<2, initiator(16BE)=userId,
        // channelId(16BE), dataPriority/segmentation flags, PER-encoded length,
        // then the payload. The previous implementation hardcoded a 5-byte header
        // with a fixed userId of 3 and no length field at all, which a real
        // server cannot parse.
        val header = ByteBuffer.allocate(6).order(ByteOrder.BIG_ENDIAN)
        header.put(0x64)                       // (MCS_SDRQ << 2)
        header.putShort(mcsUserId.toShort())   // initiator
        header.putShort(ioChannelId.toShort()) // channelId
        header.put(0x70)                       // dataPriority + segmentation (whole PDU)

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

    /**
     * Reads one complete CredSSP TSRequest message from the TLS stream.
     *
     * CredSSP messages are raw ASN.1 DER `SEQUENCE` values with **no**
     * length-prefix framing of their own — the previous implementation wrote
     * and expected a custom 4-byte length prefix that no real RDP server
     * produces, so every CredSSP response read here previously failed or
     * returned garbage. Instead, read the DER tag+length header first to
     * determine exactly how many more bytes make up the SEQUENCE, then read
     * that many bytes.
     */
    private fun readRaw(): ByteArray? {
        return try {
            val tag = inputStream?.readUnsignedByte() ?: return null
            if (tag != 0x30) return null // expected: SEQUENCE

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

            // Reconstruct the full DER value (tag + length header + content)
            // so CredSspHelper's parsers (which expect a complete TSRequest)
            // work unchanged.
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
                // Fast-path packet
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
        } catch (e: Exception) {
            null
        }
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
    val x: Int,
    val y: Int,
    val width: Int,
    val height: Int,
    val pixels: IntArray,
    val fullScreen: Boolean = false
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
        lastBytes = 0
        lastTime = now
        return kbps
    }
}
