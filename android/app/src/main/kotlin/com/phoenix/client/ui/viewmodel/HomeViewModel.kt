package com.phoenix.client.ui.viewmodel

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.phoenix.client.domain.model.ClientConfig
import com.phoenix.client.domain.repository.ConfigRepository
import com.phoenix.client.service.PhoenixService
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

enum class ConnectionStatus { DISCONNECTED, CONNECTING, CONNECTED, ERROR }
enum class ConnectionMode { SOCKS5, VPN }

private const val MAX_LOG_LINES = 200
private const val CONNECT_TIMEOUT_MS = 20_000L

data class HomeUiState(
    val connectionStatus: ConnectionStatus = ConnectionStatus.DISCONNECTED,
    val mode: ConnectionMode = ConnectionMode.SOCKS5,
    val errorMessage: String? = null,
    // Stats
    val connectionAttempts: Int = 0,
    val uptimeSeconds: Long = 0L,
    // Logs
    val logs: List<String> = emptyList(),
    /** Non-null when we need the UI to launch the VPN permission intent. */
    val vpnPermissionIntent: Intent? = null,
)

@HiltViewModel
class HomeViewModel @Inject constructor(
    application: Application,
    configRepository: ConfigRepository,
) : AndroidViewModel(application) {

    private val _uiState = MutableStateFlow(HomeUiState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    val config: StateFlow<ClientConfig> = configRepository
        .observeConfig()
        .stateIn(viewModelScope, SharingStarted.Eagerly, ClientConfig())

    private var uptimeJob: Job? = null
    private var timeoutJob: Job? = null

    // ── Broadcast receivers ────────────────────────────────────────────────────

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val statusName = intent.getStringExtra(PhoenixService.STATUS_EXTRA) ?: return
            val status = runCatching {
                PhoenixService.ServiceStatus.valueOf(statusName)
            }.getOrNull() ?: return

            timeoutJob?.cancel()

            when (status) {
                PhoenixService.ServiceStatus.CONNECTED -> {
                    _uiState.update { it.copy(connectionStatus = ConnectionStatus.CONNECTED, errorMessage = null) }
                    startUptimeClock()
                }
                PhoenixService.ServiceStatus.DISCONNECTED -> {
                    stopUptimeClock()
                    _uiState.update { it.copy(connectionStatus = ConnectionStatus.DISCONNECTED, errorMessage = null) }
                }
                PhoenixService.ServiceStatus.ERROR -> {
                    stopUptimeClock()
                    _uiState.update {
                        it.copy(
                            connectionStatus = ConnectionStatus.ERROR,
                            errorMessage = intent.getStringExtra(PhoenixService.ERROR_EXTRA),
                        )
                    }
                }
            }
        }
    }

    private val logReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val line = intent.getStringExtra(PhoenixService.LOG_LINE_EXTRA) ?: return
            _uiState.update { state ->
                val newLogs = (state.logs + line).takeLast(MAX_LOG_LINES)
                state.copy(logs = newLogs)
            }
        }
    }

    init {
        val app = application
        ContextCompat.registerReceiver(
            app, statusReceiver,
            IntentFilter(PhoenixService.STATUS_ACTION),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        ContextCompat.registerReceiver(
            app, logReceiver,
            IntentFilter(PhoenixService.LOG_ACTION),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    // ── Public actions ─────────────────────────────────────────────────────────

    fun setMode(mode: ConnectionMode) {
        if (_uiState.value.connectionStatus != ConnectionStatus.DISCONNECTED) return
        _uiState.update { it.copy(mode = mode) }
    }

    /** Called when user taps the main button. Handles connect/cancel/disconnect. */
    fun onMainButtonClicked() {
        when (_uiState.value.connectionStatus) {
            ConnectionStatus.CONNECTED, ConnectionStatus.CONNECTING -> disconnect()
            ConnectionStatus.DISCONNECTED, ConnectionStatus.ERROR -> connect()
        }
    }

    /** Called by the UI after the VPN permission dialog returns RESULT_OK. */
    fun onVpnPermissionGranted() {
        _uiState.update { it.copy(vpnPermissionIntent = null) }
        startConnection()
    }

    /** Called by the UI when the VPN permission dialog is dismissed/denied. */
    fun onVpnPermissionDenied() {
        _uiState.update { it.copy(vpnPermissionIntent = null, connectionStatus = ConnectionStatus.DISCONNECTED) }
    }

    /** Called by the UI immediately after consuming the vpnPermissionIntent. */
    fun clearVpnPermissionIntent() {
        _uiState.update { it.copy(vpnPermissionIntent = null) }
    }

    fun clearLogs() {
        _uiState.update { it.copy(logs = emptyList()) }
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    private fun connect() {
        val currentConfig = config.value
        if (currentConfig.remoteAddr.isBlank()) {
            _uiState.update {
                it.copy(connectionStatus = ConnectionStatus.ERROR, errorMessage = "Server address is required — go to Configuration")
            }
            return
        }

        if (_uiState.value.mode == ConnectionMode.VPN) {
            val vpnIntent = VpnService.prepare(getApplication())
            if (vpnIntent != null) {
                // Emit intent for the UI to launch; actual connection starts in onVpnPermissionGranted()
                _uiState.update { it.copy(vpnPermissionIntent = vpnIntent) }
                return
            }
            // Permission already granted — fall through
        }

        startConnection()
    }

    private fun startConnection() {
        _uiState.update { current ->
            current.copy(
                connectionStatus = ConnectionStatus.CONNECTING,
                errorMessage = null,
                connectionAttempts = current.connectionAttempts + 1,
                uptimeSeconds = 0L,
            )
        }

        // Safety timeout — revert if no CONNECTED/ERROR broadcast arrives within 20 s
        timeoutJob?.cancel()
        timeoutJob = viewModelScope.launch {
            delay(CONNECT_TIMEOUT_MS)
            if (_uiState.value.connectionStatus == ConnectionStatus.CONNECTING) {
                _uiState.update {
                    it.copy(connectionStatus = ConnectionStatus.ERROR, errorMessage = "Connection timed out after 20 s")
                }
            }
        }

        val ctx = getApplication<Application>()
        ctx.startForegroundService(PhoenixService.startIntent(ctx, config.value))
    }

    private fun disconnect() {
        timeoutJob?.cancel()
        stopUptimeClock()
        val ctx = getApplication<Application>()
        ctx.startService(PhoenixService.stopIntent(ctx))
        _uiState.update { it.copy(connectionStatus = ConnectionStatus.DISCONNECTED, errorMessage = null) }
    }

    private fun startUptimeClock() {
        uptimeJob?.cancel()
        uptimeJob = viewModelScope.launch {
            while (isActive) {
                delay(1_000)
                _uiState.update { it.copy(uptimeSeconds = it.uptimeSeconds + 1) }
            }
        }
    }

    private fun stopUptimeClock() {
        uptimeJob?.cancel()
        uptimeJob = null
        _uiState.update { it.copy(uptimeSeconds = 0L) }
    }

    override fun onCleared() {
        super.onCleared()
        val app = getApplication<Application>()
        app.unregisterReceiver(statusReceiver)
        app.unregisterReceiver(logReceiver)
    }
}
