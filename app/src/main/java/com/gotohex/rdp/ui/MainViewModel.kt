package com.gotohex.rdp.ui

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.gotohex.rdp.audio.SoundManager
import com.gotohex.rdp.data.model.RdpPerformance
import com.gotohex.rdp.data.model.RdpProfile
import com.gotohex.rdp.data.repository.AppSettingsRepository
import com.gotohex.rdp.data.repository.AppSettings
import com.gotohex.rdp.data.repository.RdpProfileRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import java.util.concurrent.TimeUnit
import javax.inject.Inject

data class HomeUiState(
    val profiles: List<RdpProfile> = emptyList(),
    val settings: AppSettings = AppSettings(),
    val showSubscribeDialog: Boolean = false,
    val showFirstLaunchDialog: Boolean = false,
    val networkQuality: NetworkQuality = NetworkQuality.UNKNOWN,
    val isLoading: Boolean = true,
)

enum class NetworkQuality { UNKNOWN, POOR, FAIR, GOOD, EXCELLENT }

@HiltViewModel
class MainViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val profileRepository: RdpProfileRepository,
    private val settingsRepository: AppSettingsRepository,
    val soundManager: SoundManager,
) : ViewModel() {

    private val _uiState = MutableStateFlow(HomeUiState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    init {
        observeData()
        detectNetwork()
    }

    private fun observeData() {
        viewModelScope.launch {
            combine(
                profileRepository.getAllProfiles(),
                settingsRepository.settingsFlow
            ) { profiles, settings ->
                val shouldShowSubscribe = settings.showSubscribePopup &&
                        shouldShowSubscribeDialog(settings)
                val shouldShowFirstLaunch = !settings.hasShownFirstLaunch

                // Keep the sound manager's mute state in sync with the
                // persisted "Sound Effects" setting (issue #9) so every call
                // to soundManager.play(...) across the app automatically
                // respects the user's choice without each call site needing
                // to check the setting.
                soundManager.enabled = settings.soundEnabled

                HomeUiState(
                    profiles = profiles,
                    settings = settings,
                    showSubscribeDialog = shouldShowSubscribe && !shouldShowFirstLaunch,
                    showFirstLaunchDialog = shouldShowFirstLaunch,
                    networkQuality = _uiState.value.networkQuality,
                    isLoading = false
                )
            }.collect { state ->
                _uiState.value = state
            }
        }
    }

    private fun shouldShowSubscribeDialog(settings: AppSettings): Boolean {
        if (settings.lastSubscribePromptTime == 0L) return true
        val daysSinceLastPrompt = TimeUnit.MILLISECONDS.toDays(
            System.currentTimeMillis() - settings.lastSubscribePromptTime
        )
        return daysSinceLastPrompt >= settings.subscribePromptIntervalDays
    }

    private fun detectNetwork() {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork
        val caps = cm.getNetworkCapabilities(network)
        val quality = when {
            caps == null -> NetworkQuality.UNKNOWN
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkQuality.EXCELLENT
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkQuality.EXCELLENT
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> {
                when {
                    caps.linkDownstreamBandwidthKbps > 5000 -> NetworkQuality.GOOD
                    caps.linkDownstreamBandwidthKbps > 1000 -> NetworkQuality.FAIR
                    else -> NetworkQuality.POOR
                }
            }
            else -> NetworkQuality.UNKNOWN
        }
        _uiState.update { it.copy(networkQuality = quality) }
    }

    fun getRecommendedPerformance(): Int {
        return when (_uiState.value.networkQuality) {
            NetworkQuality.POOR -> RdpPerformance.LOW_BANDWIDTH
            NetworkQuality.FAIR -> RdpPerformance.MEDIUM
            NetworkQuality.GOOD -> RdpPerformance.WIFI
            NetworkQuality.EXCELLENT -> RdpPerformance.LAN
            NetworkQuality.UNKNOWN -> RdpPerformance.AUTO
        }
    }

    fun addProfile(profile: RdpProfile) = viewModelScope.launch {
        profileRepository.saveProfile(profile.copy(
            performanceFlags = getRecommendedPerformance()
        ))
    }

    fun updateProfile(profile: RdpProfile) = viewModelScope.launch {
        profileRepository.updateProfile(profile)
    }

    fun deleteProfile(profile: RdpProfile) = viewModelScope.launch {
        profileRepository.deleteProfile(profile)
    }

    fun dismissSubscribeDialog() = viewModelScope.launch {
        settingsRepository.markSubscribePromptShown()
        _uiState.update { it.copy(showSubscribeDialog = false) }
    }

    fun dismissFirstLaunchDialog() = viewModelScope.launch {
        settingsRepository.markFirstLaunchShown()
        _uiState.update { it.copy(showFirstLaunchDialog = false) }
    }

    fun updateDarkMode(enabled: Boolean) = viewModelScope.launch {
        settingsRepository.updateDarkMode(enabled)
    }

    fun updateLanguage(lang: String) = viewModelScope.launch {
        settingsRepository.updateLanguage(lang)
    }

    fun updateTheme(theme: String) = viewModelScope.launch {
        settingsRepository.updateThemeVariant(theme)
    }

    fun updateCursorStyle(style: String) = viewModelScope.launch {
        settingsRepository.updateCursorStyle(style)
    }

    fun updateCursorSize(size: Int) = viewModelScope.launch {
        settingsRepository.updateCursorSize(size)
    }

    fun updateTouchpadSensitivity(v: Float) = viewModelScope.launch {
        settingsRepository.updateTouchpadSensitivity(v)
    }

    fun updateHapticFeedback(v: Boolean) = viewModelScope.launch {
        settingsRepository.updateHapticFeedback(v)
    }

    fun updateAutoReconnect(v: Boolean) = viewModelScope.launch {
        settingsRepository.updateAutoReconnect(v)
    }

    fun updateCompressionQuality(v: Int) = viewModelScope.launch {
        settingsRepository.updateCompressionQuality(v)
    }

    fun updateDefaultResolution(v: String) = viewModelScope.launch {
        settingsRepository.updateDefaultResolution(v)
    }

    fun updateSessionToolbarVisible(v: Boolean) = viewModelScope.launch {
        settingsRepository.updateSessionToolbarVisible(v)
    }

    fun updateSessionExtraKeysVisible(v: Boolean) = viewModelScope.launch {
        settingsRepository.updateSessionExtraKeysVisible(v)
    }

    fun updateRunInBackground(v: Boolean) = viewModelScope.launch {
        settingsRepository.updateRunInBackground(v)
    }

    fun updateSoundEnabled(v: Boolean) = viewModelScope.launch {
        settingsRepository.updateSoundEnabled(v)
    }
}
