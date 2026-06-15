package com.gotohex.rdp.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.scale
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.*
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavController
import com.gotohex.rdp.R
import com.gotohex.rdp.data.model.RdpProfile
import com.gotohex.rdp.ui.MainViewModel
import com.gotohex.rdp.ui.components.*
import com.gotohex.rdp.ui.theme.*
import kotlin.math.roundToInt

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    navController: NavController,
    viewModel: MainViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current

    var showAddDialog by remember { mutableStateOf(false) }
    var editingProfile by remember { mutableStateOf<RdpProfile?>(null) }
    var deletingProfile by remember { mutableStateOf<RdpProfile?>(null) }

    val layoutDirection = LocalLayoutDirection.current
    val isRtl = layoutDirection == LayoutDirection.Rtl
    val soundManager = LocalSoundManager.current
    val haptics = LocalHapticFeedback.current
    val density = LocalDensity.current

    // ── Swipe-to-open Settings (issue #10) ─────────────────────────────────
    // In LTR layouts, dragging from right to left (negative dx) opens
    // Settings — this mirrors the "forward" direction matching the NavHost
    // transition set up in MainActivity (Settings slides in from the right).
    // In RTL layouts the gesture is mirrored: dragging left to right
    // (positive dx) opens Settings. A small drag-following offset gives
    // immediate visual feedback before the threshold is reached, and a
    // haptic + sound cue confirms the trigger (issue #9).
    var dragOffsetPx by remember { mutableStateOf(0f) }
    val openThresholdPx = with(density) { 96.dp.toPx() }
    val animatedDrag by animateFloatAsState(
        targetValue = dragOffsetPx,
        animationSpec = spring(dampingRatio = Spring.DampingRatioMediumBouncy, stiffness = Spring.StiffnessMedium),
        label = "swipe_drag"
    )
    var settingsTriggered by remember { mutableStateOf(false) }

    val swipeModifier = Modifier.pointerInput(isRtl) {
        detectHorizontalDragGestures(
            onDragStart = { settingsTriggered = false },
            onDragEnd = {
                if (!settingsTriggered) dragOffsetPx = 0f
            },
            onDragCancel = { dragOffsetPx = 0f },
            onHorizontalDrag = { change, dragAmount ->
                val opening = if (isRtl) dragAmount > 0 else dragAmount < 0
                if (opening || dragOffsetPx != 0f) {
                    change.consume()
                    val newOffset = (dragOffsetPx + dragAmount)
                        .let { if (isRtl) it.coerceIn(0f, openThresholdPx * 1.5f) else it.coerceIn(-openThresholdPx * 1.5f, 0f) }
                    dragOffsetPx = newOffset
                    if (!settingsTriggered && kotlin.math.abs(newOffset) >= openThresholdPx) {
                        settingsTriggered = true
                        haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                        soundManager?.play(com.gotohex.rdp.audio.SoundManager.Sound.SWIPE, 0.5f)
                        navController.navigate("settings")
                        dragOffsetPx = 0f
                    }
                }
            }
        )
    }

    // Dialogs
    if (uiState.showFirstLaunchDialog) {
        SubscribeDialog(
            isFirstLaunch = true,
            onDismiss = { viewModel.dismissFirstLaunchDialog() },
            onSubscribe = {
                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/GoToHEX")))
                viewModel.dismissFirstLaunchDialog()
            }
        )
    } else if (uiState.showSubscribeDialog) {
        SubscribeDialog(
            isFirstLaunch = false,
            onDismiss = { viewModel.dismissSubscribeDialog() },
            onSubscribe = {
                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/GoToHEX")))
                viewModel.dismissSubscribeDialog()
            }
        )
    }

    if (showAddDialog) {
        ProfileFormDialog(
            onDismiss = { showAddDialog = false },
            onSave = { profile ->
                viewModel.addProfile(profile)
                showAddDialog = false
            }
        )
    }

    editingProfile?.let { profile ->
        ProfileFormDialog(
            profile = profile,
            onDismiss = { editingProfile = null },
            onSave = { updated ->
                viewModel.updateProfile(updated)
                editingProfile = null
            }
        )
    }

    deletingProfile?.let { profile ->
        DeleteConfirmDialog(
            profileName = profile.name,
            onConfirm = {
                viewModel.deleteProfile(profile)
                deletingProfile = null
            },
            onDismiss = { deletingProfile = null }
        )
    }

    Box(modifier = Modifier.fillMaxSize()) {
        // Edge "pull" indicator — fades in as the user drags toward the
        // open-Settings threshold, giving clear visual feedback that the
        // gesture is recognized (issue #10).
        val pullProgress = (kotlin.math.abs(animatedDrag) / openThresholdPx).coerceIn(0f, 1f)
        if (pullProgress > 0f) {
            Box(
                modifier = Modifier
                    .fillMaxHeight()
                    .width(64.dp)
                    .align(if (isRtl) Alignment.CenterStart else Alignment.CenterEnd)
                    .alpha(pullProgress),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    Icons.Outlined.Settings,
                    contentDescription = null,
                    tint = PulsarCyan,
                    modifier = Modifier
                        .size((20 + pullProgress * 12).dp)
                        .scale(scaleX = if (isRtl) -1f else 1f, scaleY = 1f)
                )
            }
        }

        StarfieldBackground(
            isDark = uiState.settings.isDarkMode,
            modifier = Modifier
                .fillMaxSize()
                .offset { IntOffset(animatedDrag.roundToInt(), 0) }
                .then(swipeModifier)
        ) {
            Scaffold(
                containerColor = androidx.compose.ui.graphics.Color.Transparent,
                topBar = {
                    HomeTopBar(
                        networkQuality = uiState.networkQuality,
                        onSettingsClick = { navController.navigate("settings") }
                    )
                },
                floatingActionButton = {
                    SpaceFab(onClick = { showAddDialog = true })
                }
            ) { padding ->
                if (uiState.isLoading) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = PulsarCyan)
                    }
                } else if (uiState.profiles.isEmpty()) {
                    EmptyState(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(padding),
                        onAddClick = { showAddDialog = true }
                    )
                } else {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(padding),
                        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        item {
                            // Network quality banner
                            NetworkBanner(quality = uiState.networkQuality)
                            Spacer(Modifier.height(4.dp))
                        }

                        items(
                            items = uiState.profiles,
                            key = { it.id }
                        ) { profile ->
                            AnimatedVisibility(
                                visible = true,
                                enter = fadeIn() + slideInVertically { it / 2 }
                            ) {
                                RdpProfileCard(
                                    profile = profile,
                                    onConnect = {
                                        val intent = Intent(context, RdpSessionActivity::class.java)
                                            .putExtra("profile_id", profile.id)
                                        context.startActivity(intent)
                                    },
                                    onEdit = { editingProfile = profile },
                                    onDelete = { deletingProfile = profile }
                                )
                            }
                        }

                        item { Spacer(Modifier.height(80.dp)) } // FAB clearance
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HomeTopBar(
    networkQuality: com.gotohex.rdp.ui.NetworkQuality,
    onSettingsClick: () -> Unit
) {
    TopAppBar(
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                // HEX logo mark
                Surface(
                    shape = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
                    color = PulsarCyan.copy(alpha = 0.15f),
                    modifier = Modifier.size(32.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Text("H", style = MaterialTheme.typography.titleMedium,
                            color = PulsarCyan, fontWeight = FontWeight.Bold)
                    }
                }
                Spacer(Modifier.width(10.dp))
                Text(
                    "HexRDP",
                    style = MaterialTheme.typography.titleLarge,
                    color = StarDust,
                    fontWeight = FontWeight.Bold
                )
            }
        },
        actions = {
            NetworkQualityBadge(networkQuality)
            Spacer(Modifier.width(8.dp))
            IconButton(onClick = onSettingsClick) {
                Icon(Icons.Outlined.Settings, contentDescription = null, tint = CometTail)
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = androidx.compose.ui.graphics.Color.Transparent
        )
    )
}

@Composable
private fun SpaceFab(onClick: () -> Unit) {
    FloatingActionButton(
        onClick = onClick,
        containerColor = PulsarCyan,
        contentColor = DeepSpace,
        shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp)
    ) {
        Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(28.dp))
    }
}

@Composable
private fun NetworkBanner(quality: com.gotohex.rdp.ui.NetworkQuality) {
    if (quality == com.gotohex.rdp.ui.NetworkQuality.POOR) {
        Surface(
            color = SolarFlare.copy(alpha = 0.15f),
            shape = androidx.compose.foundation.shape.RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Outlined.SignalWifiBad, null, tint = SolarFlare, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(
                    stringResource(R.string.poor_network_warning),
                    style = MaterialTheme.typography.bodySmall,
                    color = SolarFlare
                )
            }
        }
    }
}

@Composable
private fun EmptyState(modifier: Modifier = Modifier, onAddClick: () -> Unit) {
    val infiniteTransition = rememberInfiniteTransition(label = "empty")
    val floatY by infiniteTransition.animateFloat(
        initialValue = -8f, targetValue = 8f,
        animationSpec = infiniteRepeatable(
            animation = tween(2000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "float"
    )

    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Outlined.Computer,
            contentDescription = null,
            tint = PulsarCyan.copy(alpha = 0.5f),
            modifier = Modifier
                .size(96.dp)
                .offset(y = floatY.dp)
        )
        Spacer(Modifier.height(24.dp))
        Text(
            stringResource(R.string.no_connections),
            style = MaterialTheme.typography.headlineSmall,
            color = StarDust,
            fontWeight = FontWeight.SemiBold
        )
        Spacer(Modifier.height(8.dp))
        Text(
            stringResource(R.string.add_first_connection),
            style = MaterialTheme.typography.bodyMedium,
            color = CometTail
        )
        Spacer(Modifier.height(32.dp))
        SpaceButton(
            text = stringResource(R.string.add_connection),
            onClick = onAddClick,
            modifier = Modifier.width(200.dp)
        )
    }
}
