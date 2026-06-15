package com.gotohex.rdp.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.compose.animation.*
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.*
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavController
import com.gotohex.rdp.R
import com.gotohex.rdp.ui.components.LocalSoundManager
import com.gotohex.rdp.ui.components.pressScale
import com.gotohex.rdp.ui.MainViewModel
import com.gotohex.rdp.ui.components.StarfieldBackground
import com.gotohex.rdp.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    navController: NavController,
    viewModel: MainViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val settings = uiState.settings
    val context = LocalContext.current

    StarfieldBackground(isDark = settings.isDarkMode, modifier = Modifier.fillMaxSize()) {
        Scaffold(
            containerColor = Color.Transparent,
            topBar = {
                TopAppBar(
                    title = {
                        Text(
                            stringResource(R.string.settings),
                            style = MaterialTheme.typography.titleLarge,
                            color = StarDust,
                            fontWeight = FontWeight.Bold
                        )
                    },
                    navigationIcon = {
                        IconButton(onClick = { navController.popBackStack() }) {
                            Icon(Icons.Default.ArrowBack, null, tint = CometTail)
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent)
                )
            }
        ) { padding ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                // ── Appearance ──────────────────────────────────────────
                SettingsSection(title = stringResource(R.string.appearance))

                SettingsToggle(
                    icon = if (settings.isDarkMode) Icons.Outlined.DarkMode else Icons.Outlined.LightMode,
                    title = stringResource(R.string.dark_mode),
                    subtitle = if (settings.isDarkMode) stringResource(R.string.dark) else stringResource(R.string.light),
                    checked = settings.isDarkMode,
                    onCheckedChange = viewModel::updateDarkMode
                )

                SettingsChoice(
                    icon = Icons.Outlined.Palette,
                    title = stringResource(R.string.theme),
                    options = listOf("space" to stringResource(R.string.theme_space),
                        "nebula" to stringResource(R.string.theme_nebula),
                        "aurora" to stringResource(R.string.theme_aurora)),
                    selected = settings.themeVariant,
                    onSelect = viewModel::updateTheme
                )

                SettingsChoice(
                    icon = Icons.Outlined.Language,
                    title = stringResource(R.string.language),
                    options = listOf("system" to stringResource(R.string.lang_system),
                        "en" to "English", "ar" to "العربية"),
                    selected = settings.language,
                    onSelect = viewModel::updateLanguage
                )

                Spacer(Modifier.height(8.dp))

                // ── Cursor & Input ──────────────────────────────────────
                SettingsSection(title = stringResource(R.string.cursor_input))

                SettingsCursorPicker(
                    title = stringResource(R.string.cursor_style),
                    options = listOf(
                        "default" to stringResource(R.string.cursor_default),
                        "crosshair" to stringResource(R.string.cursor_crosshair),
                        "dot" to stringResource(R.string.cursor_dot),
                        "circle" to stringResource(R.string.cursor_circle)
                    ),
                    selected = settings.cursorStyle,
                    cursorSize = settings.cursorSize,
                    onSelect = viewModel::updateCursorStyle
                )

                SettingsSlider(
                    icon = Icons.Outlined.ZoomOutMap,
                    title = stringResource(R.string.cursor_size),
                    value = settings.cursorSize.toFloat(),
                    valueRange = 16f..48f,
                    onValueChange = { viewModel.updateCursorSize(it.toInt()) },
                    valueLabel = { "${it.toInt()}dp" }
                )

                SettingsSlider(
                    icon = Icons.Outlined.TouchApp,
                    title = stringResource(R.string.touchpad_sensitivity),
                    value = settings.touchpadSensitivity,
                    valueRange = 0.3f..3f,
                    onValueChange = viewModel::updateTouchpadSensitivity
                )

                SettingsToggle(
                    icon = Icons.Outlined.Vibration,
                    title = stringResource(R.string.haptic_feedback),
                    checked = settings.hapticFeedback,
                    onCheckedChange = viewModel::updateHapticFeedback
                )

                SettingsToggle(
                    icon = if (settings.soundEnabled) Icons.Outlined.VolumeUp else Icons.Outlined.VolumeOff,
                    title = stringResource(R.string.sound_effects),
                    subtitle = stringResource(R.string.sound_effects_desc),
                    checked = settings.soundEnabled,
                    onCheckedChange = viewModel::updateSoundEnabled
                )

                Spacer(Modifier.height(8.dp))

                // ── Connection ──────────────────────────────────────────
                SettingsSection(title = stringResource(R.string.connection))

                SettingsToggle(
                    icon = Icons.Outlined.Autorenew,
                    title = stringResource(R.string.auto_reconnect),
                    checked = settings.autoReconnect,
                    onCheckedChange = viewModel::updateAutoReconnect
                )

                SettingsSlider(
                    icon = Icons.Outlined.HighQuality,
                    title = stringResource(R.string.compression_quality),
                    value = settings.compressionQuality.toFloat(),
                    valueRange = 10f..100f,
                    onValueChange = { viewModel.updateCompressionQuality(it.toInt()) },
                    valueLabel = { "${it.toInt()}%" }
                )

                SettingsChoice(
                    icon = Icons.Outlined.AspectRatio,
                    title = stringResource(R.string.default_resolution),
                    options = listOf(
                        "auto" to stringResource(R.string.resolution_auto),
                        "1280x720" to "1280 × 720 (HD)",
                        "1366x768" to "1366 × 768",
                        "1600x900" to "1600 × 900",
                        "1920x1080" to "1920 × 1080 (Full HD)",
                        "2560x1440" to "2560 × 1440 (QHD)",
                    ),
                    selected = settings.defaultResolution,
                    onSelect = viewModel::updateDefaultResolution
                )

                SettingsToggle(
                    icon = Icons.Outlined.CloudSync,
                    title = stringResource(R.string.run_in_background),
                    subtitle = stringResource(R.string.run_in_background_desc),
                    checked = settings.runInBackground,
                    onCheckedChange = viewModel::updateRunInBackground
                )

                Spacer(Modifier.height(8.dp))

                // ── In-session controls ──────────────────────────────────
                SettingsSection(title = stringResource(R.string.session_controls))

                SettingsToggle(
                    icon = Icons.Outlined.ViewAgenda,
                    title = stringResource(R.string.show_toolbar_by_default),
                    checked = settings.sessionToolbarVisible,
                    onCheckedChange = viewModel::updateSessionToolbarVisible
                )

                SettingsToggle(
                    icon = Icons.Outlined.SpaceBar,
                    title = stringResource(R.string.show_extra_keys_by_default),
                    checked = settings.sessionExtraKeysVisible,
                    onCheckedChange = viewModel::updateSessionExtraKeysVisible
                )

                Spacer(Modifier.height(8.dp))

                // ── Developer ───────────────────────────────────────────
                SettingsSection(title = stringResource(R.string.developer))

                SettingsItem(
                    icon = Icons.Outlined.Send,
                    title = "Telegram",
                    subtitle = stringResource(R.string.developer_telegram),
                    onClick = {
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/GoToHEX")))
                    },
                    tint = Color(0xFF2AABEEL)
                )

                SettingsItem(
                    icon = Icons.Outlined.SmartDisplay,
                    title = "YouTube",
                    subtitle = stringResource(R.string.developer_youtube),
                    onClick = {
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://youtube.com/@dev-hex404?si=OEvGo4kfTkXWJgGF")))
                    },
                    tint = Color(0xFFFF0000L)
                )

                SettingsItem(
                    icon = Icons.Outlined.Info,
                    title = stringResource(R.string.about),
                    subtitle = "HexRDP v1.0.0 — ${stringResource(R.string.by_developer)}",
                    onClick = {}
                )

                Spacer(Modifier.height(32.dp))
            }
        }
    }
}

@Composable
fun SettingsSection(title: String) {
    Text(
        text = title.uppercase(),
        style = MaterialTheme.typography.labelSmall,
        color = PulsarCyan,
        fontWeight = FontWeight.Bold,
        letterSpacing = 1.5.sp,
        modifier = Modifier.padding(top = 8.dp, bottom = 4.dp, start = 4.dp)
    )
}

@Composable
fun SettingsCard(content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(NebulaSurface, RoundedCornerShape(16.dp))
            .padding(4.dp),
        content = content
    )
}

@Composable
fun SettingsToggle(
    icon: ImageVector,
    title: String,
    subtitle: String? = null,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    val soundManager = LocalSoundManager.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(NebulaSurface, RoundedCornerShape(12.dp))
            .pressScale(playSound = false, onClick = {
                soundManager?.play(com.gotohex.rdp.audio.SoundManager.Sound.TOGGLE, 0.4f)
                onCheckedChange(!checked)
            })
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, null, tint = PulsarCyan, modifier = Modifier.size(22.dp))
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyMedium, color = StarDust)
            if (subtitle != null) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = CometTail)
            }
        }
        Switch(
            checked = checked,
            onCheckedChange = {
                soundManager?.play(com.gotohex.rdp.audio.SoundManager.Sound.TOGGLE, 0.4f)
                onCheckedChange(it)
            },
            colors = SwitchDefaults.colors(
                checkedThumbColor = DeepSpace,
                checkedTrackColor = PulsarCyan
            )
        )
    }
}

@Composable
fun SettingsCursorPicker(
    title: String,
    options: List<Pair<String, String>>,
    selected: String,
    cursorSize: Int,
    onSelect: (String) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    val selectedLabel = options.find { it.first == selected }?.second ?: selected
    val accent = PulsarCyan

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(NebulaSurface, RoundedCornerShape(12.dp))
    ) {
        val chevronRotation by animateFloatAsState(
            targetValue = if (expanded) 180f else 0f,
            animationSpec = tween(250),
            label = "chevron_rotation"
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .pressScale(onClick = { expanded = !expanded })
                .padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Live preview of the currently selected cursor (issue #4 — show the
            // actual cursor shape, not just its name).
            CursorPreviewIcon(cursorStyle = selected, cursorSize = cursorSize, accent = accent)
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyMedium, color = StarDust)
                Text(selectedLabel, style = MaterialTheme.typography.bodySmall, color = PulsarCyan)
            }
            Icon(
                Icons.Default.ExpandMore,
                null, tint = CometTail,
                modifier = Modifier.size(20.dp).rotate(chevronRotation)
            )
        }
        AnimatedVisibility(
            visible = expanded,
            enter = expandVertically(animationSpec = tween(250)) + fadeIn(tween(250)),
            exit = shrinkVertically(animationSpec = tween(200)) + fadeOut(tween(150))
        ) {
            Column(modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 8.dp)) {
                options.forEach { (key, label) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .pressScale(onClick = { onSelect(key); expanded = false })
                            .padding(vertical = 8.dp, horizontal = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CursorPreviewIcon(cursorStyle = key, cursorSize = cursorSize, accent = accent)
                        Spacer(Modifier.width(12.dp))
                        Text(label, style = MaterialTheme.typography.bodyMedium, color = StarDust, modifier = Modifier.weight(1f))
                        RadioButton(
                            selected = key == selected,
                            onClick = { onSelect(key); expanded = false },
                            colors = RadioButtonDefaults.colors(selectedColor = PulsarCyan)
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun CursorPreviewIcon(cursorStyle: String, cursorSize: Int, accent: Color) {
    val previewBitmap = remember(cursorStyle, cursorSize, accent) {
        com.gotohex.rdp.ui.components.buildCursorBitmap(cursorStyle, cursorSize.coerceIn(16, 32), accent)
            .asImageBitmap()
    }
    Box(
        modifier = Modifier
            .size(36.dp)
            .background(DeepSpace, RoundedCornerShape(8.dp)),
        contentAlignment = Alignment.Center
    ) {
        Image(
            bitmap = previewBitmap,
            contentDescription = null,
            modifier = Modifier.size(22.dp)
        )
    }
}

@Composable
fun SettingsChoice(
    icon: ImageVector,
    title: String,
    options: List<Pair<String, String>>,
    selected: String,
    onSelect: (String) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    val selectedLabel = options.find { it.first == selected }?.second ?: selected

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(NebulaSurface, RoundedCornerShape(12.dp))
    ) {
        val chevronRotation by animateFloatAsState(
            targetValue = if (expanded) 180f else 0f,
            animationSpec = tween(250),
            label = "chevron_rotation"
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .pressScale(onClick = { expanded = !expanded })
                .padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(icon, null, tint = PulsarCyan, modifier = Modifier.size(22.dp))
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyMedium, color = StarDust)
                Text(selectedLabel, style = MaterialTheme.typography.bodySmall, color = PulsarCyan)
            }
            Icon(
                Icons.Default.ExpandMore,
                null, tint = CometTail,
                modifier = Modifier.size(20.dp).rotate(chevronRotation)
            )
        }
        AnimatedVisibility(
            visible = expanded,
            enter = expandVertically(animationSpec = tween(250)) + fadeIn(tween(250)),
            exit = shrinkVertically(animationSpec = tween(200)) + fadeOut(tween(150))
        ) {
            Column(modifier = Modifier.padding(start = 50.dp, end = 16.dp, bottom = 8.dp)) {
                options.forEach { (key, label) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .pressScale(onClick = { onSelect(key); expanded = false })
                            .padding(vertical = 10.dp, horizontal = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = key == selected,
                            onClick = { onSelect(key); expanded = false },
                            colors = RadioButtonDefaults.colors(selectedColor = PulsarCyan)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(label, style = MaterialTheme.typography.bodyMedium, color = StarDust)
                    }
                }
            }
        }
    }
}

@Composable
fun SettingsSlider(
    icon: ImageVector,
    title: String,
    value: Float,
    valueRange: ClosedFloatingPointRange<Float>,
    onValueChange: (Float) -> Unit,
    valueLabel: (Float) -> String = { "%.1f".format(it) }
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(NebulaSurface, RoundedCornerShape(12.dp))
            .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, tint = PulsarCyan, modifier = Modifier.size(22.dp))
            Spacer(Modifier.width(12.dp))
            Text(title, style = MaterialTheme.typography.bodyMedium, color = StarDust, modifier = Modifier.weight(1f))
            Text(valueLabel(value), style = MaterialTheme.typography.labelMedium, color = PulsarCyan)
        }
        Slider(
            value = value,
            onValueChange = onValueChange,
            valueRange = valueRange,
            colors = SliderDefaults.colors(
                thumbColor = PulsarCyan,
                activeTrackColor = PulsarCyan,
                inactiveTrackColor = HorizonGray
            )
        )
    }
}

@Composable
fun SettingsItem(
    icon: ImageVector,
    title: String,
    subtitle: String? = null,
    onClick: () -> Unit,
    tint: Color = PulsarCyan
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(NebulaSurface, RoundedCornerShape(12.dp))
            .pressScale(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, null, tint = tint, modifier = Modifier.size(22.dp))
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyMedium, color = StarDust)
            if (subtitle != null) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = CometTail)
            }
        }
        Icon(Icons.Default.ChevronRight, null, tint = CometTail, modifier = Modifier.size(20.dp))
    }
}
