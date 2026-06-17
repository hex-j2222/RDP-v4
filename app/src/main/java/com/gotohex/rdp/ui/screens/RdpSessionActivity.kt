package com.gotohex.rdp.ui.screens

import android.graphics.Bitmap
import android.graphics.Rect
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.input.pointer.*
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.*
import androidx.core.view.WindowCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.gotohex.rdp.data.model.RdpProfile
import com.gotohex.rdp.data.repository.RdpProfileRepository
import com.gotohex.rdp.rdp.protocol.*
import com.gotohex.rdp.ui.components.ButtonVariant
import com.gotohex.rdp.ui.components.SpaceButton
import com.gotohex.rdp.ui.theme.*
import dagger.hilt.android.AndroidEntryPoint
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import javax.inject.Inject

// ─────────────────────────────────────────────────────────────────────────────
// Activity
// ─────────────────────────────────────────────────────────────────────────────

@AndroidEntryPoint
class RdpSessionActivity : ComponentActivity() {

    private val viewModel: RdpSessionViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        val profileId = intent.getStringExtra("profile_id") ?: run { finish(); return }

        // Device display size, used as the "auto" resolution fallback (issue #5)
        val metrics = resources.displayMetrics
        val deviceWidth = metrics.widthPixels
        val deviceHeight = metrics.heightPixels

        setContent {
            val settings by viewModel.settings.collectAsState()
            val state by viewModel.state.collectAsState()

            // Keep the RDP session alive in the background via a foreground
            // service + persistent notification (issue #9 — "run in background").
            LaunchedEffect(state, settings.runInBackground) {
                val profileName = (state as? SessionUiState.Connected)?.profile?.name
                if (state is SessionUiState.Connected && settings.runInBackground) {
                    RdpSessionService.start(this@RdpSessionActivity, profileName ?: "RDP")
                } else if (state is SessionUiState.Disconnected || state is SessionUiState.Error) {
                    RdpSessionService.stop(this@RdpSessionActivity)
                }
            }

            HexRDPTheme(darkTheme = true, themeVariant = settings.themeVariant) {
                RdpSessionScreen(
                    viewModel = viewModel,
                    onClose = {
                        RdpSessionService.stop(this@RdpSessionActivity)
                        finish()
                    }
                )
            }
        }
        viewModel.loadAndConnect(profileId, deviceWidth, deviceHeight)
    }

    override fun onDestroy() {
        super.onDestroy()
        if (isFinishing) {
            RdpSessionService.stop(this)
        }
    }

    @Suppress("DEPRECATION")
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) {
            window.decorView.systemUiVisibility = (
                android.view.View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                    or android.view.View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                    or android.view.View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                    or android.view.View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                    or android.view.View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                    or android.view.View.SYSTEM_UI_FLAG_FULLSCREEN
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ViewModel
// ─────────────────────────────────────────────────────────────────────────────

@HiltViewModel
class RdpSessionViewModel @Inject constructor(
    @dagger.hilt.android.qualifiers.ApplicationContext private val appContext: android.content.Context,
    private val repository: RdpProfileRepository,
    private val settingsRepository: com.gotohex.rdp.data.repository.AppSettingsRepository,
) : ViewModel() {

    private val _state       = MutableStateFlow<SessionUiState>(SessionUiState.Idle)
    val state: StateFlow<SessionUiState> = _state.asStateFlow()

    private val _frameBitmap = MutableStateFlow<Bitmap?>(null)
    val frameBitmap: StateFlow<Bitmap?> = _frameBitmap.asStateFlow()

    private val _latency = MutableStateFlow(0L)
    val latency: StateFlow<Long> = _latency.asStateFlow()

    private val _resolution = MutableStateFlow(1280 to 720)
    val resolution: StateFlow<Pair<Int, Int>> = _resolution.asStateFlow()

    val settings: StateFlow<com.gotohex.rdp.data.repository.AppSettings> =
        settingsRepository.settingsFlow.stateIn(
            viewModelScope, SharingStarted.Eagerly, com.gotohex.rdp.data.repository.AppSettings()
        )

    private var rdpClient: RdpClient? = null
    private var screenBitmap: Bitmap? = null
    private var screenWidth  = 1280
    private var screenHeight = 720
    private var currentProfileId: String? = null

    /**
     * Dedicated scope for everything related to the active RDP session
     * (connection, receive loop collectors, frame decoding). Any exception
     * that escapes here is caught and surfaced as a normal "Error" state
     * instead of crashing the process — this is the final safety net behind
     * the per-frame try/catch in [loadAndConnect] (issue #3 — the app used to
     * close immediately after a connection attempt because an uncaught
     * exception from a `viewModelScope.launch` child propagates and kills
     * the app by design).
     */
    private val sessionScope = viewModelScope + CoroutineExceptionHandler { _, throwable ->
        android.util.Log.e("RdpSession", "Unhandled session error", throwable)
        _state.value = SessionUiState.Error(throwable.message ?: "Unexpected error")
    }

    /**
     * @param deviceWidth/deviceHeight the device's current display size, used when
     *        the profile and the global default resolution are both "auto" (issue #5).
     */
    fun loadAndConnect(profileId: String, deviceWidth: Int, deviceHeight: Int) {
        sessionScope.launch {
            _state.emit(SessionUiState.Connecting(""))
            val profile = repository.getProfileById(profileId)
            if (profile == null) {
                _state.emit(SessionUiState.Error("Profile not found"))
                return@launch
            }
            _state.emit(SessionUiState.Connecting(profile.name))
            currentProfileId = profile.id

            val defaultRes = settings.value.defaultResolution
            val (resW, resH) = when {
                profile.width > 0 && profile.height > 0 -> profile.width to profile.height
                defaultRes != "auto" && defaultRes.contains("x") -> {
                    val parts = defaultRes.split("x")
                    (parts.getOrNull(0)?.toIntOrNull() ?: deviceWidth) to (parts.getOrNull(1)?.toIntOrNull() ?: deviceHeight)
                }
                deviceWidth > 0 && deviceHeight > 0 -> deviceWidth to deviceHeight
                else -> 1280 to 720
            }
            screenWidth  = resW
            screenHeight = resH
            _resolution.value = screenWidth to screenHeight

            // android.graphics.Bitmap — fully qualified to avoid any ambiguity
            screenBitmap = android.graphics.Bitmap.createBitmap(
                screenWidth, screenHeight, android.graphics.Bitmap.Config.ARGB_8888
            )

            val client = RdpClient(
                credentials = com.gotohex.rdp.data.model.RdpCredentials(
                    host     = profile.host,
                    port     = profile.port,
                    username = profile.username,
                    password = profile.password,
                    domain   = profile.domain,
                    useNla   = profile.useNla
                ),
                displayWidth    = screenWidth,
                displayHeight   = screenHeight,
                performanceMode = profile.performanceFlags
            )
            rdpClient = client

            // FIX: previously `client.error` and `client.sessionState` were
            // collected in two independent `launch {}` coroutines. Both can
            // be scheduled in either order, so the ERROR/AUTH_FAILED branch
            // below could run before the matching error string had been
            // written to `lastError`, silently falling back to a useless
            // generic message ("Connection error"). combine() guarantees we
            // always see the latest error value paired with the state that
            // triggered it, since both flows are read from a single
            // downstream collector instead of two racing ones.
            launch {
                kotlinx.coroutines.flow.combine(client.sessionState, client.error.onStart { emit("") }) { rdpState, msg ->
                    rdpState to msg.ifBlank { null }
                }.collect { (rdpState, lastError) ->
                    when (rdpState) {
                        RdpSessionState.CONNECTED    -> _state.emit(SessionUiState.Connected(profile))
                        RdpSessionState.AUTH_FAILED  -> _state.emit(SessionUiState.Error(lastError ?: "Authentication failed. Check credentials."))
                        RdpSessionState.ERROR        -> _state.emit(SessionUiState.Error(lastError ?: "Connection error"))
                        RdpSessionState.DISCONNECTED -> _state.emit(SessionUiState.Disconnected)
                        else -> {}
                    }
                    if (rdpState != RdpSessionState.CONNECTED) {
                        saveLastFrameThumbnail()
                    }
                }
            }
            var lastError: String? = null
            launch {
                client.error.collect { msg -> lastError = msg }
            }

            // Periodically persist a thumbnail of the current screen (issue #11
            // — "show the last point the system was at" in the profile list,
            // blended into the card). Throttled to once every 15s so it never
            // becomes a performance concern, and also saved once more whenever
            // the session ends (above).
            launch {
                while (isActive) {
                    delay(15_000)
                    if (_state.value is SessionUiState.Connected) {
                        saveLastFrameThumbnail()
                    }
                }
            }

            launch {
                client.frameUpdates.collect { frame ->
                    try {
                        applyFrameUpdate(frame)
                    } catch (e: Exception) {
                        // A single malformed/oversized frame must never crash the
                        // whole app (issue #3 — app closes suddenly right after
                        // connecting). Log and skip this frame only.
                        android.util.Log.w("RdpSession", "Dropping malformed frame: ${e.message}")
                    }
                    _latency.value = client.latencyMs
                }
            }

            val success = client.connect()
            if (!success && _state.value !is SessionUiState.Error) {
                _state.emit(SessionUiState.Error(lastError ?: "Failed to connect to ${profile.host}:${profile.port}"))
            }
        }
    }

    /**
     * Saves a small thumbnail of the current [screenBitmap] for the active
     * profile (issue #11), used by [com.gotohex.rdp.ui.components.RdpProfileCard]
     * to show "what the system looked like last time" blended into the card.
     * Runs on a background thread and never throws.
     */
    private fun saveLastFrameThumbnail() {
        val bitmap = screenBitmap ?: return
        val profileId = currentProfileId ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val snapshot = synchronized(bitmap) {
                bitmap.copy(android.graphics.Bitmap.Config.ARGB_8888, false)
            }
            com.gotohex.rdp.util.LastFrameStore.save(appContext, profileId, snapshot)
            snapshot.recycle()
        }
    }

    private fun applyFrameUpdate(frame: RdpFrameUpdate) {
        val bitmap = screenBitmap ?: return
        if (frame.width <= 0 || frame.height <= 0) return

        // Defensive validation — never trust pixel array size or rectangle
        // bounds blindly. A mismatch here previously threw an uncaught
        // ArrayIndexOutOfBoundsException (or a native Canvas crash from
        // Bitmap.createBitmap/drawBitmap with out-of-range rects) on the very
        // first frame after the session reports CONNECTED, which is exactly
        // the "app closes suddenly when the connection starts" symptom
        // (issue #3).
        val expectedPixelCount = frame.width.toLong() * frame.height.toLong()
        if (frame.pixels.size.toLong() < expectedPixelCount) return

        // Clamp the destination rectangle to the screen bitmap's bounds.
        val dstX = frame.x.coerceIn(0, bitmap.width)
        val dstY = frame.y.coerceIn(0, bitmap.height)
        val drawW = frame.width.coerceAtMost(bitmap.width - dstX)
        val drawH = frame.height.coerceAtMost(bitmap.height - dstY)
        if (drawW <= 0 || drawH <= 0) return

        synchronized(bitmap) {
            if (frame.fullScreen && dstX == 0 && dstY == 0 &&
                drawW == bitmap.width && drawH == bitmap.height &&
                drawW == frame.width && drawH == frame.height
            ) {
                bitmap.setPixels(frame.pixels, 0, frame.width, 0, 0, frame.width, frame.height)
            } else {
                val srcRect = Rect(0, 0, drawW, drawH)
                val dstRect = Rect(dstX, dstY, dstX + drawW, dstY + drawH)
                // Use fully-qualified android.graphics.Canvas to avoid clash with Compose Canvas
                val androidCanvas = android.graphics.Canvas(bitmap)
                val tmp = android.graphics.Bitmap.createBitmap(
                    frame.pixels, frame.width, frame.height, android.graphics.Bitmap.Config.ARGB_8888
                )
                androidCanvas.drawBitmap(tmp, srcRect, dstRect, null)
                tmp.recycle()
            }
        }
        _frameBitmap.tryEmit(bitmap.copy(android.graphics.Bitmap.Config.ARGB_8888, false))
    }

    fun sendMouseMove(x: Int, y: Int)                                         = rdpClient?.sendMouseMove(x, y)
    fun sendMouseClick(x: Int, y: Int, button: MouseButton, down: Boolean)    = rdpClient?.sendMouseClick(x, y, button, down)
    fun sendMouseScroll(x: Int, y: Int, delta: Int)                           = rdpClient?.sendMouseScroll(x, y, delta)
    fun sendKeyEvent(scanCode: Int, down: Boolean, extended: Boolean = false) = rdpClient?.sendKeyEvent(scanCode, down, extended)
    fun sendCtrlAltDel()                                                      = rdpClient?.sendCtrlAltDel()

    fun setSessionToolbarVisible(visible: Boolean) = viewModelScope.launch {
        settingsRepository.updateSessionToolbarVisible(visible)
    }

    fun setSessionExtraKeysVisible(visible: Boolean) = viewModelScope.launch {
        settingsRepository.updateSessionExtraKeysVisible(visible)
    }

    fun disconnect() {
        saveLastFrameThumbnail()
        rdpClient?.disconnect()
        viewModelScope.launch { _state.emit(SessionUiState.Disconnected) }
    }

    override fun onCleared() {
        super.onCleared()
        // viewModelScope is already cancelled by this point, so save directly
        // on a plain thread rather than relying on saveLastFrameThumbnail's
        // viewModelScope.launch (issue #11).
        val bitmap = screenBitmap
        val profileId = currentProfileId
        rdpClient?.disconnect()
        if (bitmap != null && profileId != null) {
            Thread {
                val snapshot = synchronized(bitmap) {
                    bitmap.copy(android.graphics.Bitmap.Config.ARGB_8888, false)
                }
                com.gotohex.rdp.util.LastFrameStore.save(appContext, profileId, snapshot)
                snapshot.recycle()
                bitmap.recycle()
            }.start()
        } else {
            screenBitmap?.recycle()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UI State
// ─────────────────────────────────────────────────────────────────────────────

sealed class SessionUiState {
    object Idle                                   : SessionUiState()
    data class Connecting(val name: String)       : SessionUiState()
    data class Connected(val profile: RdpProfile) : SessionUiState()
    data class Error(val message: String)         : SessionUiState()
    object Disconnected                           : SessionUiState()
}

// ─────────────────────────────────────────────────────────────────────────────
// Session Screen Root
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun RdpSessionScreen(
    viewModel: RdpSessionViewModel,
    onClose: () -> Unit
) {
    val state       by viewModel.state.collectAsState()
    val frameBitmap by viewModel.frameBitmap.collectAsState()
    val latency     by viewModel.latency.collectAsState()
    val settings    by viewModel.settings.collectAsState()
    val (screenWidth, screenHeight) = viewModel.resolution.collectAsState().value

    // Toolbar / extra-keys visibility default from Settings, but can be toggled
    // freely by the user during the session (issue #8 — full show/hide control).
    // The default is persisted back to Settings so it's remembered next time
    // (issue #9).
    var showToolbar   by remember { mutableStateOf(settings.sessionToolbarVisible) }
    var showExtraKeys by remember { mutableStateOf(settings.sessionExtraKeysVisible) }

    val backgroundColor = DeepSpace

    Box(Modifier.fillMaxSize().background(backgroundColor)) {
        // Smooth crossfade between connecting / connected / error / disconnected
        // states instead of an abrupt switch (issue #6 — professional animation).
        AnimatedContent(
            targetState = state,
            transitionSpec = {
                (fadeIn(animationSpec = tween(350)) + scaleIn(initialScale = 0.97f, animationSpec = tween(350))) togetherWith
                    fadeOut(animationSpec = tween(200))
            },
            label = "session_state"
        ) { s ->
            when (s) {
                is SessionUiState.Connecting   -> ConnectingOverlay(s.name)
                is SessionUiState.Error        -> ErrorOverlay(s.message, onClose)
                is SessionUiState.Disconnected -> DisconnectedOverlay(onClose)
                is SessionUiState.Connected    -> {
                    Box(Modifier.fillMaxSize()) {
                        RdpCanvas(
                            bitmap       = frameBitmap,
                            screenWidth  = screenWidth,
                            screenHeight = screenHeight,
                            cursorStyle  = settings.cursorStyle,
                            cursorSize   = settings.cursorSize,
                            showCursor   = settings.showCursorOnTouch,
                            onMouseMove  = { x, y       -> viewModel.sendMouseMove(x, y) },
                            onMouseClick = { x, y, b, d -> viewModel.sendMouseClick(x, y, b, d) },
                            onScroll     = { x, y, d    -> viewModel.sendMouseScroll(x, y, d) },
                            modifier     = Modifier.fillMaxSize()
                        )

                        // Toolbar pinned to the top, safe-area aware.
                        AnimatedVisibility(
                            visible  = showToolbar,
                            enter    = slideInVertically(animationSpec = tween(250)) { -it } + fadeIn(tween(250)),
                            exit     = slideOutVertically(animationSpec = tween(200)) { -it } + fadeOut(tween(200)),
                            modifier = Modifier
                                .align(Alignment.TopCenter)
                                .windowInsetsPadding(WindowInsets.statusBars)
                        ) {
                            SessionToolbar(
                                latency      = latency,
                                profileName  = s.profile.name,
                                onCtrlAltDel = { viewModel.sendCtrlAltDel() },
                                onDisconnect = { viewModel.disconnect(); onClose() },
                                onHide       = {
                                    showToolbar = false
                                    viewModel.setSessionToolbarVisible(false)
                                }
                            )
                        }

                        // Extra-keys bar pinned to the bottom, but always pushed
                        // above the on-screen keyboard via imePadding (issue #8 —
                        // "important buttons must appear directly above the
                        // keyboard").
                        AnimatedVisibility(
                            visible  = showExtraKeys,
                            enter    = slideInVertically(animationSpec = tween(250)) { it } + fadeIn(tween(250)),
                            exit     = slideOutVertically(animationSpec = tween(200)) { it } + fadeOut(tween(200)),
                            modifier = Modifier
                                .align(Alignment.BottomCenter)
                                .imePadding()
                                .navigationBarsPadding()
                        ) {
                            ExtraKeysBar(
                                onHide = {
                                    showExtraKeys = false
                                    viewModel.setSessionExtraKeysVisible(false)
                                }
                            ) { sc, dn, ext -> viewModel.sendKeyEvent(sc, dn, ext) }
                        }

                        // Small re-show handles — full control over hidden bars.
                        Row(
                            modifier = Modifier
                                .align(Alignment.TopEnd)
                                .windowInsetsPadding(WindowInsets.statusBars)
                                .padding(8.dp),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            AnimatedVisibility(visible = !showToolbar) {
                                SmallShowButton(
                                    icon = Icons.Default.KeyboardArrowDown,
                                    onClick = {
                                        showToolbar = true
                                        viewModel.setSessionToolbarVisible(true)
                                    }
                                )
                            }
                        }
                        if (!showExtraKeys) {
                            Box(
                                modifier = Modifier
                                    .align(Alignment.BottomEnd)
                                    .imePadding()
                                    .navigationBarsPadding()
                                    .padding(8.dp)
                            ) {
                                SmallShowButton(
                                    icon = Icons.Default.KeyboardArrowUp,
                                    onClick = {
                                        showExtraKeys = true
                                        viewModel.setSessionExtraKeysVisible(true)
                                    }
                                )
                            }
                        }
                    }
                }
                else -> Unit
            }
        }
    }
}

@Composable
private fun SmallShowButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    onClick: () -> Unit
) {
    val bg = DeepSpace
    val accent = PulsarCyan
    Surface(
        color    = bg.copy(alpha = 0.8f),
        shape    = RoundedCornerShape(8.dp),
        modifier = Modifier.clickable(onClick = onClick)
    ) {
        Icon(
            icon, null,
            tint     = accent,
            modifier = Modifier.size(28.dp).padding(4.dp)
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RDP Canvas — uses Compose Canvas + android.graphics for bitmap drawing
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun RdpCanvas(
    bitmap: Bitmap?,
    screenWidth: Int,
    screenHeight: Int,
    cursorStyle: String = "default",
    cursorSize: Int = 24,
    showCursor: Boolean = true,
    onMouseMove:  (Int, Int) -> Unit,
    onMouseClick: (Int, Int, MouseButton, Boolean) -> Unit,
    onScroll:     (Int, Int, Int) -> Unit,
    modifier: Modifier = Modifier
) {
    // Mutable state for cursor and viewport
    var cursorX by remember { mutableStateOf(screenWidth / 2f) }
    var cursorY by remember { mutableStateOf(screenHeight / 2f) }
    var scale   by remember { mutableStateOf(1f) }
    var offsetX by remember { mutableStateOf(0f) }
    var offsetY by remember { mutableStateOf(0f) }
    var lastPtrCount by remember { mutableStateOf(0) }

    // Theme colors must be read in composable scope (not inside Canvas' draw
    // lambda, which is not @Composable) and captured for use below.
    val backgroundColor = DeepSpace
    val cursorThemeColor = LocalSpaceColors.current.cursorColor

    // Build the cursor bitmap from the user's chosen style/size (issue #4 —
    // previously a single hardcoded crosshair was always drawn regardless of
    // the "Cursor Style" setting). Shared with the Settings picker preview.
    val cursorBitmap = remember(cursorStyle, cursorSize, cursorThemeColor) {
        com.gotohex.rdp.ui.components.buildCursorBitmap(cursorStyle, cursorSize, cursorThemeColor).asImageBitmap()
    }
    val cursorPxSize = cursorBitmap.width.toFloat()

    // Compose Canvas (androidx.compose.foundation.Canvas imported at top)
    Canvas(
        modifier = modifier
            .pointerInput(Unit) {
                detectTransformGestures { _, pan, zoom, _ ->
                    if (lastPtrCount >= 2) {
                        scale   = (scale * zoom).coerceIn(0.5f, 4f)
                        offsetX += pan.x
                        offsetY += pan.y
                    }
                }
            }
            .pointerInput(Unit) {
                awaitPointerEventScope {
                    while (true) {
                        val event    = awaitPointerEvent()
                        val active   = event.changes.filter { it.pressed }
                        lastPtrCount = active.size

                        when (event.type) {
                            PointerEventType.Move -> {
                                when (active.size) {
                                    1 -> {
                                        // Touchpad mode: relative movement
                                        val dx = (active[0].position.x - active[0].previousPosition.x) * 2f
                                        val dy = (active[0].position.y - active[0].previousPosition.y) * 2f
                                        cursorX = (cursorX + dx).coerceIn(0f, screenWidth.toFloat())
                                        cursorY = (cursorY + dy).coerceIn(0f, screenHeight.toFloat())
                                        onMouseMove(cursorX.toInt(), cursorY.toInt())
                                    }
                                    2 -> {
                                        // Two-finger scroll
                                        val dy = active.map { it.position.y - it.previousPosition.y }
                                            .average().toFloat()
                                        onScroll(cursorX.toInt(), cursorY.toInt(), if (dy > 0) -1 else 1)
                                    }
                                }
                                event.changes.forEach { it.consume() }
                            }
                            PointerEventType.Release -> {
                                if (active.isEmpty()) {
                                    onMouseClick(cursorX.toInt(), cursorY.toInt(), MouseButton.LEFT, true)
                                    onMouseClick(cursorX.toInt(), cursorY.toInt(), MouseButton.LEFT, false)
                                }
                            }
                            else -> {}
                        }
                    }
                }
            }
    ) {
        withTransform({
            translate(offsetX, offsetY)
            scale(scale, scale, Offset(size.width / 2f, size.height / 2f))
        }) {
            if (bitmap != null) {
                drawImage(
                    image   = bitmap.asImageBitmap(),
                    dstSize = androidx.compose.ui.unit.IntSize(size.width.toInt(), size.height.toInt())
                )
            } else {
                drawRect(color = backgroundColor)
            }

            // Draw cursor (issue #4 — now reflects the chosen style/size/visibility)
            if (showCursor) {
                val cx = cursorX / screenWidth  * size.width  - cursorPxSize / 2f
                val cy = cursorY / screenHeight * size.height - cursorPxSize / 2f
                drawImage(cursorBitmap, topLeft = Offset(cx, cy))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Session Toolbar
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun SessionToolbar(
    latency:      Long,
    profileName:  String,
    onCtrlAltDel: () -> Unit,
    onDisconnect: () -> Unit,
    onHide:       () -> Unit
) {
    Surface(
        color    = DeepSpace.copy(alpha = 0.93f),
        border   = BorderStroke(1.dp, HorizonGray),
        shape    = RoundedCornerShape(bottomStart = 16.dp, bottomEnd = 16.dp),
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp)
    ) {
        Row(
            modifier          = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    profileName,
                    style      = MaterialTheme.typography.labelLarge,
                    color      = StarDust,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    "${latency}ms",
                    style = MaterialTheme.typography.labelSmall,
                    color = when {
                        latency < 100  -> PlasmaGreen
                        latency < 300  -> ConnectingAmber
                        else           -> ErrorRed
                    }
                )
            }
            ToolbarIconButton(Icons.Outlined.Lock,  "CAD",  onCtrlAltDel)
            ToolbarIconButton(Icons.Default.Close,  "Exit", onDisconnect, tint = NovaPink)
            IconButton(onClick = onHide) {
                Icon(Icons.Default.ExpandLess, null, tint = CometTail, modifier = Modifier.size(20.dp))
            }
        }
    }
}

@Composable
fun ToolbarIconButton(
    icon:    androidx.compose.ui.graphics.vector.ImageVector,
    label:   String,
    onClick: () -> Unit,
    tint:    Color = PulsarCyan
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier.clickable(onClick = onClick).padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        Icon(icon, label, tint = tint, modifier = Modifier.size(22.dp))
        Text(label, style = MaterialTheme.typography.labelSmall, color = CometTail, fontSize = 9.sp)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Extra Keys Bar
// ─────────────────────────────────────────────────────────────────────────────

private data class SpecialKey(val label: String, val scanCode: Int, val extended: Boolean = false)

private val EXTRA_KEYS = listOf(
    SpecialKey("Esc",   0x01), SpecialKey("Tab",   0x0F),
    SpecialKey("Ctrl",  0x1D), SpecialKey("Alt",   0x38),
    SpecialKey("Win",   0x5B, true),
    SpecialKey("F1",  0x3B), SpecialKey("F2",  0x3C), SpecialKey("F3",  0x3D),
    SpecialKey("F4",  0x3E), SpecialKey("F5",  0x3F), SpecialKey("F6",  0x40),
    SpecialKey("F7",  0x41), SpecialKey("F8",  0x42), SpecialKey("F9",  0x43),
    SpecialKey("F10", 0x44), SpecialKey("F11", 0x57), SpecialKey("F12", 0x58),
    SpecialKey("Del",   0x53, true), SpecialKey("Home",  0x47, true),
    SpecialKey("End",   0x4F, true), SpecialKey("PgUp",  0x49, true),
    SpecialKey("PgDn",  0x51, true), SpecialKey("Ins",   0x52, true),
    SpecialKey("PrtSc", 0x37, true)
)

@Composable
fun ExtraKeysBar(onHide: () -> Unit = {}, onKeyEvent: (Int, Boolean, Boolean) -> Unit) {
    Surface(
        color    = DeepSpace.copy(alpha = 0.95f),
        border   = BorderStroke(1.dp, HorizonGray),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            LazyRow(
                modifier              = Modifier.weight(1f),
                contentPadding        = PaddingValues(horizontal = 8.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                items(EXTRA_KEYS.size) { i ->
                    val key     = EXTRA_KEYS[i]
                    var pressed by remember { mutableStateOf(false) }
                    Surface(
                        color    = if (pressed) PulsarCyan.copy(alpha = 0.2f) else NebulaSurface,
                        shape    = RoundedCornerShape(8.dp),
                        border   = BorderStroke(1.dp, if (pressed) PulsarCyan else HorizonGray),
                        modifier = Modifier.pointerInput(key.label) {
                            awaitPointerEventScope {
                                while (true) {
                                    val ev = awaitPointerEvent()
                                    when (ev.type) {
                                        PointerEventType.Press   -> { pressed = true;  onKeyEvent(key.scanCode, true,  key.extended) }
                                        PointerEventType.Release -> { pressed = false; onKeyEvent(key.scanCode, false, key.extended) }
                                        else -> {}
                                    }
                                }
                            }
                        }
                    ) {
                        Text(
                            key.label,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                            style    = MaterialTheme.typography.labelSmall,
                            color    = if (pressed) PulsarCyan else StarDust
                        )
                    }
                }
            }
            IconButton(onClick = onHide) {
                Icon(Icons.Default.ExpandMore, null, tint = CometTail, modifier = Modifier.size(20.dp))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Overlay Composables
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun ConnectingOverlay(name: String) {
    val infiniteTransition = rememberInfiniteTransition(label = "connect_pulse")
    val alpha by infiniteTransition.animateFloat(
        initialValue  = 0.4f,
        targetValue   = 1f,
        animationSpec = infiniteRepeatable(
            animation  = tween(900, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_alpha"
    )
    Box(Modifier.fillMaxSize().background(DeepSpace), Alignment.Center) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            CircularProgressIndicator(
                color       = PulsarCyan.copy(alpha = alpha),
                modifier    = Modifier.size(56.dp),
                strokeWidth = 3.dp
            )
            Text("Connecting to $name", style = MaterialTheme.typography.titleMedium, color = StarDust)
            Text("Please wait…", style = MaterialTheme.typography.bodySmall, color = CometTail)
        }
    }
}

@Composable
fun ErrorOverlay(message: String, onClose: () -> Unit) {
    // TEMPORARY diagnostic UI: lets the full connection trace (the same
    // text now bundled into `message`, see RdpClient.connect()) be copied
    // out of the device without adb/logcat. Remove once the underlying
    // connection issue is confirmed fixed.
    val context = androidx.compose.ui.platform.LocalContext.current
    var copied by remember { mutableStateOf(false) }

    Box(Modifier.fillMaxSize().background(DeepSpace), Alignment.Center) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp),
            modifier = Modifier
                .padding(32.dp)
                .fillMaxWidth()
        ) {
            Icon(Icons.Outlined.ErrorOutline, null, tint = NovaPink, modifier = Modifier.size(64.dp))
            Text(
                "Connection Failed",
                style      = MaterialTheme.typography.headlineSmall,
                color      = StarDust,
                fontWeight = FontWeight.Bold
            )

            // Scrollable box so a long trace doesn't push the buttons off-screen.
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 280.dp)
                    .background(DeepSpace.copy(alpha = 0.6f), RoundedCornerShape(8.dp))
                    .border(BorderStroke(1.dp, CometTail.copy(alpha = 0.3f)), RoundedCornerShape(8.dp))
                    .padding(12.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Text(
                    message,
                    style = MaterialTheme.typography.bodySmall,
                    color = CometTail,
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                )
            }

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                SpaceButton(
                    if (copied) "Copied ✓" else "Copy log",
                    onClick = {
                        val clipboard = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE)
                            as android.content.ClipboardManager
                        clipboard.setPrimaryClip(android.content.ClipData.newPlainText("RDP connection log", message))
                        copied = true
                    },
                    modifier = Modifier.width(150.dp),
                    variant = ButtonVariant.PRIMARY
                )
                SpaceButton("Close", onClose, Modifier.width(150.dp), variant = ButtonVariant.GHOST)
            }
        }
    }
}

@Composable
fun DisconnectedOverlay(onClose: () -> Unit) {
    Box(Modifier.fillMaxSize().background(DeepSpace), Alignment.Center) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Icon(Icons.Outlined.LinkOff, null, tint = DisconnectedGray, modifier = Modifier.size(56.dp))
            Text("Disconnected", style = MaterialTheme.typography.titleLarge, color = StarDust)
            SpaceButton("Close", onClose, Modifier.width(160.dp))
        }
    }
}
