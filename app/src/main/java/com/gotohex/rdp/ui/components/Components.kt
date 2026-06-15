package com.gotohex.rdp.ui.components

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.*
import com.gotohex.rdp.R
import com.gotohex.rdp.data.model.RdpProfile
import com.gotohex.rdp.ui.theme.*
import kotlin.math.*
import kotlin.random.Random
import kotlinx.coroutines.withContext

// ── Shared Sound Manager Access (issue #9) ────────────────────────────────────
// Provided at the app root (MainActivity) so any composable — especially the
// shared `pressScale` modifier below — can play short UI feedback sounds
// without needing the SoundManager passed down explicitly. Defaults to null
// so previews / tests that don't provide it simply produce no sound.
val LocalSoundManager = staticCompositionLocalOf<com.gotohex.rdp.audio.SoundManager?> { null }

// ── Shared Press-Feedback Modifier (issue #8) ─────────────────────────────────
// A small, consistent "press scale" animation applied to every clickable
// surface in the app (cards, list rows, chips, toggles, menu items...) so
// interactions feel responsive and "alive" instead of the previous instant,
// jarring state changes. Usage:
//
//   Modifier.pressScale(onClick = { ... })
//
// This replaces a plain `.clickable { ... }` while adding the same subtle
// scale-down-on-press used by SpaceButton, with no visible ripple (the scale
// itself communicates the press).
@Composable
fun Modifier.pressScale(
    enabled: Boolean = true,
    scaleDown: Float = 0.97f,
    playSound: Boolean = true,
    onClick: () -> Unit
): Modifier {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (isPressed) scaleDown else 1f,
        animationSpec = spring(dampingRatio = Spring.DampingRatioMediumBouncy, stiffness = Spring.StiffnessHigh),
        label = "press_scale"
    )
    val soundManager = LocalSoundManager.current
    return this
        .scale(scale)
        .clickable(
            enabled = enabled,
            interactionSource = interactionSource,
            indication = null,
            onClick = {
                if (playSound) soundManager?.play(com.gotohex.rdp.audio.SoundManager.Sound.TAP, 0.35f)
                onClick()
            }
        )
}

// ── Shared Cursor Icon Generator (issue #4) ───────────────────────────────────
// Used by both the in-session RdpCanvas and the Settings "Cursor Style" picker
// so that the picker shows an accurate live preview of each cursor option
// instead of just a text label.

fun buildCursorBitmap(
    cursorStyle: String,
    cursorSize: Int,
    accentColor: Color
): android.graphics.Bitmap {
    val pxSize = (cursorSize * 2).coerceAtLeast(16)
    val center = pxSize / 2f
    val bmp = android.graphics.Bitmap.createBitmap(pxSize, pxSize, android.graphics.Bitmap.Config.ARGB_8888)
    val cvs = android.graphics.Canvas(bmp)
    val accent = accentColor.toArgb()
    val outline = android.graphics.Paint().apply {
        color = android.graphics.Color.BLACK; strokeWidth = 3f; isAntiAlias = true
        style = android.graphics.Paint.Style.STROKE
    }
    val highlight = android.graphics.Paint().apply {
        color = android.graphics.Color.WHITE; strokeWidth = 1.5f; isAntiAlias = true
        style = android.graphics.Paint.Style.STROKE
    }
    val fill = android.graphics.Paint().apply {
        color = accent; isAntiAlias = true
    }
    when (cursorStyle) {
        "crosshair" -> {
            cvs.drawLine(center, 2f, center, pxSize - 2f, outline)
            cvs.drawLine(2f, center, pxSize - 2f, center, outline)
            cvs.drawLine(center, 2f, center, pxSize - 2f, highlight)
            cvs.drawLine(2f, center, pxSize - 2f, center, highlight)
            cvs.drawCircle(center, center, 3f, fill)
        }
        "dot" -> {
            cvs.drawCircle(center, center, center - 3f, fill)
            cvs.drawCircle(center, center, center - 3f, outline)
        }
        "circle" -> {
            val ring = android.graphics.Paint().apply {
                color = accent; isAntiAlias = true; strokeWidth = 3f
                style = android.graphics.Paint.Style.STROKE
            }
            cvs.drawCircle(center, center, center - 3f, ring)
            cvs.drawCircle(center, center, 2.5f, fill)
        }
        else -> { // "default" — classic arrow/pointer shape
            val arrow = android.graphics.Path().apply {
                moveTo(2f, 2f)
                lineTo(2f, pxSize - 6f)
                lineTo(pxSize * 0.38f, pxSize * 0.74f)
                lineTo(pxSize * 0.52f, pxSize - 2f)
                lineTo(pxSize * 0.66f, pxSize * 0.92f)
                lineTo(pxSize * 0.50f, pxSize * 0.58f)
                lineTo(pxSize - 4f, pxSize * 0.50f)
                close()
            }
            val arrowFill = android.graphics.Paint().apply { color = android.graphics.Color.WHITE; isAntiAlias = true; style = android.graphics.Paint.Style.FILL }
            val arrowStroke = android.graphics.Paint().apply { color = android.graphics.Color.BLACK; isAntiAlias = true; style = android.graphics.Paint.Style.STROKE; strokeWidth = 2f }
            cvs.drawPath(arrow, arrowFill)
            cvs.drawPath(arrow, arrowStroke)
        }
    }
    return bmp
}

// ── Starfield Background ──────────────────────────────────────────────────────

@Composable
fun StarfieldBackground(
    modifier: Modifier = Modifier,
    starCount: Int = 80,
    isDark: Boolean? = null,
    content: @Composable BoxScope.() -> Unit
) {
    val spaceColors = LocalSpaceColors.current
    val dark = isDark ?: spaceColors.isDark
    val gradientColors = spaceColors.backgroundGradient
    val accentColor = spaceColors.accent
    val accentSecondary = spaceColors.accentSecondary

    val infiniteTransition = rememberInfiniteTransition(label = "stars")
    val twinkle by infiniteTransition.animateFloat(
        initialValue  = 0f,
        targetValue   = 1f,
        animationSpec = infiniteRepeatable(
            animation  = tween(3000, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "twinkle"
    )

    val stars = remember {
        List(starCount) {
            Triple(Random.nextFloat(), Random.nextFloat(), Random.nextFloat())
        }
    }

    Box(modifier = modifier) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            drawRect(
                brush = if (gradientColors.size > 1)
                    Brush.verticalGradient(gradientColors)
                else
                    Brush.verticalGradient(listOf(gradientColors[0], gradientColors[0]))
            )
            if (dark) {
                stars.forEach { (xFrac, yFrac, factor) ->
                    val brightness = 0.4f + factor * 0.6f *
                        (0.7f + 0.3f * sin(twinkle * PI.toFloat() * 2 + factor * 10))
                    drawCircle(
                        color  = Color.White.copy(alpha = brightness),
                        radius = 1f + factor * 2f,
                        center = Offset(xFrac * size.width, yFrac * size.height)
                    )
                }
                drawCircle(
                    brush  = Brush.radialGradient(
                        colors = listOf(accentColor.copy(alpha = 0.10f), Color.Transparent),
                        center = Offset(size.width * 0.8f, size.height * 0.2f),
                        radius = size.width * 0.4f
                    ),
                    radius = size.width * 0.4f,
                    center = Offset(size.width * 0.8f, size.height * 0.2f)
                )
                drawCircle(
                    brush  = Brush.radialGradient(
                        colors = listOf(accentSecondary.copy(alpha = 0.08f), Color.Transparent),
                        center = Offset(size.width * 0.2f, size.height * 0.7f),
                        radius = size.width * 0.3f
                    ),
                    radius = size.width * 0.3f,
                    center = Offset(size.width * 0.2f, size.height * 0.7f)
                )
            }
        }
        content()
    }
}

// ── RDP Profile Card ─────────────────────────────────────────────────────────

@Composable
fun RdpProfileCard(
    profile:   RdpProfile,
    onConnect: () -> Unit,
    onEdit:    () -> Unit,
    onDelete:  () -> Unit,
    modifier:  Modifier = Modifier
) {
    var showMenu by remember { mutableStateOf(false) }

    val statusColor = when {
        profile.isConnected    -> ConnectedGreen
        profile.lastConnected > 0 -> ConnectingAmber
        else                   -> DisconnectedGray
    }

    // ── Last-session screenshot blended into the card (issue #11) ─────────────
    // Loaded asynchronously from LastFrameStore (a small cached JPEG written by
    // RdpSessionViewModel). When present, it's drawn faintly at the bottom of
    // the card, fading into the card's own gradient, so the user gets a quick
    // visual reminder of "where they left off" without it dominating the card.
    val context = androidx.compose.ui.platform.LocalContext.current
    val lastFrame by produceState<androidx.compose.ui.graphics.ImageBitmap?>(initialValue = null, profile.id) {
        value = withContext(kotlinx.coroutines.Dispatchers.IO) {
            com.gotohex.rdp.util.LastFrameStore.load(context, profile.id)?.asImageBitmap()
        }
    }

    Box(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(
                brush = Brush.linearGradient(listOf(GradientCardStart, GradientCardEnd))
            )
            .border(
                width  = 1.dp,
                brush  = Brush.linearGradient(
                    listOf(PulsarCyan.copy(alpha = 0.3f), QuantumBlue.copy(alpha = 0.1f))
                ),
                shape  = RoundedCornerShape(16.dp)
            )
            .pressScale(onClick = onConnect)
    ) {
        // Faint last-frame backdrop, dimmed and gradient-faded so it reads as
        // a subtle texture rather than a competing image.
        lastFrame?.let { img ->
            Image(
                bitmap = img,
                contentDescription = null,
                contentScale = androidx.compose.ui.layout.ContentScale.Crop,
                modifier = Modifier
                    .matchParentSize()
                    .clip(RoundedCornerShape(16.dp))
                    .alpha(0.22f)
            )
            // Blend the screenshot into the card's own background colors so it
            // never looks like a harsh image overlay — strong at the edges,
            // transparent in the center where the image is most visible.
            Box(
                modifier = Modifier
                    .matchParentSize()
                    .background(
                        brush = Brush.verticalGradient(
                            colors = listOf(
                                GradientCardStart.copy(alpha = 0.85f),
                                GradientCardStart.copy(alpha = 0.35f),
                                GradientCardEnd.copy(alpha = 0.85f),
                            )
                        )
                    )
            )
        }

        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier              = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment     = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                    PulsingDot(color = statusColor)
                    Spacer(Modifier.width(10.dp))
                    Column {
                        Text(profile.name,  style = MaterialTheme.typography.titleMedium,
                            color = StarDust, fontWeight = FontWeight.SemiBold)
                        Text("${profile.host}:${profile.port}",
                            style = MaterialTheme.typography.bodySmall, color = CometTail)
                    }
                }
                Box {
                    IconButton(onClick = { showMenu = true }) {
                        Icon(Icons.Default.MoreVert, null, tint = CometTail)
                    }
                    DropdownMenu(
                        expanded          = showMenu,
                        onDismissRequest  = { showMenu = false },
                        containerColor    = StarfieldSurface
                    ) {
                        DropdownMenuItem(
                            text          = { Text(stringResource(R.string.edit), color = StarDust) },
                            leadingIcon   = { Icon(Icons.Outlined.Edit, null, tint = PulsarCyan) },
                            onClick       = { showMenu = false; onEdit() }
                        )
                        DropdownMenuItem(
                            text          = { Text(stringResource(R.string.delete), color = NovaPink) },
                            leadingIcon   = { Icon(Icons.Outlined.Delete, null, tint = NovaPink) },
                            onClick       = { showMenu = false; onDelete() }
                        )
                    }
                }
            }

            Spacer(Modifier.height(12.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                InfoChip(Icons.Outlined.Person,   profile.username.ifEmpty { "—" })
                InfoChip(Icons.Outlined.Security, if (profile.useNla) "NLA" else "RDP")
            }

            Spacer(Modifier.height(12.dp))

            SpaceButton(
                text     = stringResource(R.string.connect),
                onClick  = onConnect,
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

@Composable
fun PulsingDot(color: Color, size: Dp = 10.dp) {
    val infiniteTransition = rememberInfiniteTransition(label = "dot_pulse")
    val pulse by infiniteTransition.animateFloat(
        initialValue  = 0.6f,
        targetValue   = 1f,
        animationSpec = infiniteRepeatable(
            animation  = tween(1000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "dot_scale"
    )
    Box(
        Modifier
            .size(size)
            .drawBehind {
                drawCircle(color = color.copy(alpha = 0.3f * pulse), radius = this.size.minDimension / 2 * 1.8f)
                drawCircle(color = color)
            }
    )
}

@Composable
fun InfoChip(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .background(HorizonGray.copy(alpha = 0.5f), RoundedCornerShape(8.dp))
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        Icon(icon, null, tint = PulsarCyan, modifier = Modifier.size(14.dp))
        Spacer(Modifier.width(4.dp))
        Text(text, style = MaterialTheme.typography.labelSmall, color = CometTail)
    }
}

// ── Space Button ──────────────────────────────────────────────────────────────

enum class ButtonVariant { PRIMARY, DANGER, GHOST }

@Composable
fun SpaceButton(
    text:     String,
    onClick:  () -> Unit,
    modifier: Modifier = Modifier,
    enabled:  Boolean = true,
    variant:  ButtonVariant = ButtonVariant.PRIMARY
) {
    val gradient = when (variant) {
        ButtonVariant.PRIMARY -> Brush.horizontalGradient(listOf(PulsarCyan, QuantumBlue))
        ButtonVariant.DANGER  -> Brush.horizontalGradient(listOf(NovaPink,  SolarFlare))
        ButtonVariant.GHOST   -> Brush.horizontalGradient(listOf(Color.Transparent, Color.Transparent))
    }
    val textColor = when (variant) {
        ButtonVariant.PRIMARY -> DeepSpace
        ButtonVariant.DANGER  -> Color.White
        ButtonVariant.GHOST   -> PulsarCyan
    }

    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (isPressed) 0.96f else 1f,
        animationSpec = tween(120),
        label = "button_scale"
    )
    val soundManager = LocalSoundManager.current

    Box(
        modifier = modifier
            .scale(scale)
            .clip(RoundedCornerShape(12.dp))
            .background(brush = gradient)
            .then(
                if (variant == ButtonVariant.GHOST)
                    Modifier.border(1.dp, PulsarCyan.copy(0.5f), RoundedCornerShape(12.dp))
                else Modifier
            )
            .clickable(
                enabled = enabled,
                interactionSource = interactionSource,
                indication = null,
                onClick = {
                    soundManager?.play(com.gotohex.rdp.audio.SoundManager.Sound.TAP, 0.4f)
                    onClick()
                }
            )
            .padding(vertical = 12.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text       = text,
            style      = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.SemiBold,
            color      = if (enabled) textColor else textColor.copy(alpha = 0.4f)
        )
    }
}

// ── Network Quality Badge ─────────────────────────────────────────────────────

@Composable
fun NetworkQualityBadge(quality: com.gotohex.rdp.ui.NetworkQuality) {
    val (color, bars) = when (quality) {
        com.gotohex.rdp.ui.NetworkQuality.POOR      -> Pair(ErrorRed,        1)
        com.gotohex.rdp.ui.NetworkQuality.FAIR      -> Pair(ConnectingAmber, 2)
        com.gotohex.rdp.ui.NetworkQuality.GOOD      -> Pair(PlasmaGreen,     3)
        com.gotohex.rdp.ui.NetworkQuality.EXCELLENT -> Pair(PulsarCyan,      4)
        else                                         -> Pair(DisconnectedGray, 0)
    }
    Row(
        verticalAlignment     = Alignment.Bottom,
        horizontalArrangement = Arrangement.spacedBy(2.dp),
        modifier              = Modifier.height(16.dp)
    ) {
        for (i in 1..4) {
            Box(
                Modifier
                    .width(4.dp)
                    .height((4 + i * 3).dp)
                    .background(
                        color = if (i <= bars) color else color.copy(alpha = 0.2f),
                        shape = RoundedCornerShape(1.dp)
                    )
            )
        }
    }
}

// ── Subscribe Dialog ──────────────────────────────────────────────────────────

@Composable
fun SubscribeDialog(
    isFirstLaunch: Boolean = false,
    onDismiss:     () -> Unit,
    onSubscribe:   () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor   = StarfieldSurface,
        shape            = RoundedCornerShape(24.dp),
        title = {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(Icons.Default.RocketLaunch, null, tint = PulsarCyan, modifier = Modifier.size(48.dp))
                Spacer(Modifier.height(8.dp))
                Text(
                    text       = if (isFirstLaunch) stringResource(R.string.welcome_title)
                                 else stringResource(R.string.subscribe_title),
                    style      = MaterialTheme.typography.headlineSmall,
                    color      = StarDust,
                    fontWeight = FontWeight.Bold
                )
            }
        },
        text = {
            Text(
                text  = if (isFirstLaunch) stringResource(R.string.welcome_message)
                        else stringResource(R.string.subscribe_message),
                style = MaterialTheme.typography.bodyMedium,
                color = CometTail
            )
        },
        confirmButton = {
            SpaceButton(stringResource(R.string.join_channel), onSubscribe, Modifier.fillMaxWidth())
        },
        dismissButton = {
            if (!isFirstLaunch) {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.later), color = CometTail)
                }
            }
        }
    )
}

// ── Profile Form Dialog ───────────────────────────────────────────────────────

@Composable
fun ProfileFormDialog(
    profile:  RdpProfile? = null,
    onDismiss: () -> Unit,
    onSave:    (RdpProfile) -> Unit
) {
    var name            by remember { mutableStateOf(profile?.name     ?: "") }
    var host            by remember { mutableStateOf(profile?.host     ?: "") }
    var port            by remember { mutableStateOf(profile?.port?.toString() ?: "3389") }
    var username        by remember { mutableStateOf(profile?.username ?: "") }
    var password        by remember { mutableStateOf(profile?.password ?: "") }
    var useNla          by remember { mutableStateOf(profile?.useNla   ?: true) }
    var passwordVisible by remember { mutableStateOf(false) }

    val isValid = name.isNotBlank() && host.isNotBlank() && username.isNotBlank()

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor   = StarfieldSurface,
        shape            = RoundedCornerShape(24.dp),
        modifier         = Modifier.fillMaxWidth(0.95f),
        title = {
            Text(
                if (profile != null) stringResource(R.string.edit_profile)
                else stringResource(R.string.new_connection),
                style = MaterialTheme.typography.titleLarge,
                color = StarDust
            )
        },
        text = {
            Column(
                modifier            = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                SpaceTextField(name,     { name = it },     stringResource(R.string.connection_name), Icons.Outlined.Label)
                SpaceTextField(host,     { host = it },     stringResource(R.string.host_ip),         Icons.Outlined.Computer)
                SpaceTextField(port,     { port = it.filter(Char::isDigit) }, stringResource(R.string.port), Icons.Outlined.SettingsEthernet)
                SpaceTextField(username, { username = it }, stringResource(R.string.username),         Icons.Outlined.Person)
                SpaceTextField(
                    value           = password,
                    onValueChange   = { password = it },
                    label           = stringResource(R.string.password),
                    icon            = Icons.Outlined.Lock,
                    isPassword      = true,
                    passwordVisible = passwordVisible,
                    onTogglePassword = { passwordVisible = !passwordVisible }
                )

                Row(
                    Modifier.fillMaxWidth(),
                    verticalAlignment     = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(stringResource(R.string.use_nla), color = CometTail,
                        style = MaterialTheme.typography.bodyMedium)
                    Switch(
                        checked         = useNla,
                        onCheckedChange = { useNla = it },
                        colors          = SwitchDefaults.colors(
                            checkedThumbColor  = DeepSpace,
                            checkedTrackColor  = PulsarCyan
                        )
                    )
                }
            }
        },
        confirmButton = {
            SpaceButton(
                text    = stringResource(R.string.save),
                onClick = {
                    val base = profile ?: RdpProfile(name = "", host = "", username = "", password = "")
                    onSave(
                        base.copy(
                            name     = name.trim(),
                            host     = host.trim(),
                            port     = port.toIntOrNull() ?: 3389,
                            username = username.trim(),
                            password = password,
                            useNla   = useNla,
                        )
                    )
                },
                enabled  = isValid,
                modifier = Modifier.fillMaxWidth()
            )
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel), color = CometTail)
            }
        }
    )
}

@Composable
fun SpaceTextField(
    value:           String,
    onValueChange:   (String) -> Unit,
    label:           String,
    icon:            androidx.compose.ui.graphics.vector.ImageVector,
    isPassword:      Boolean = false,
    passwordVisible: Boolean = false,
    onTogglePassword: (() -> Unit)? = null,
    modifier:        Modifier = Modifier
) {
    OutlinedTextField(
        value         = value,
        onValueChange = onValueChange,
        label         = { Text(label, color = CometTail) },
        leadingIcon   = { Icon(icon, null, tint = PulsarCyan, modifier = Modifier.size(20.dp)) },
        trailingIcon  = if (isPassword && onTogglePassword != null) ({
            IconButton(onClick = onTogglePassword) {
                Icon(
                    if (passwordVisible) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                    null, tint = CometTail
                )
            }
        }) else null,
        visualTransformation = if (isPassword && !passwordVisible)
            PasswordVisualTransformation() else VisualTransformation.None,
        singleLine    = true,
        modifier      = modifier.fillMaxWidth(),
        colors        = OutlinedTextFieldDefaults.colors(
            focusedBorderColor      = PulsarCyan,
            unfocusedBorderColor    = HorizonGray,
            focusedLabelColor       = PulsarCyan,
            cursorColor             = PulsarCyan,
            focusedTextColor        = StarDust,
            unfocusedTextColor      = StarDust,
            focusedContainerColor   = NebulaSurface,
            unfocusedContainerColor = NebulaSurface,
        ),
        shape = RoundedCornerShape(12.dp)
    )
}

// ── Delete Confirm Dialog ─────────────────────────────────────────────────────

@Composable
fun DeleteConfirmDialog(
    profileName: String,
    onConfirm:   () -> Unit,
    onDismiss:   () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor   = StarfieldSurface,
        shape            = RoundedCornerShape(20.dp),
        icon  = { Icon(Icons.Outlined.Warning, null, tint = SolarFlare, modifier = Modifier.size(36.dp)) },
        title = { Text(stringResource(R.string.delete_confirm_title), color = StarDust) },
        text  = {
            Text(
                stringResource(R.string.delete_confirm_message, profileName),
                color = CometTail
            )
        },
        confirmButton = {
            SpaceButton(
                text     = stringResource(R.string.delete),
                onClick  = onConfirm,
                variant  = ButtonVariant.DANGER,
                modifier = Modifier.fillMaxWidth()
            )
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel), color = CometTail)
            }
        }
    )
}
