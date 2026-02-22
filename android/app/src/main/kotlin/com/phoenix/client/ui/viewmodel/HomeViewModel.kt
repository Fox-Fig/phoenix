package com.phoenix.client.ui.viewmodel

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.phoenix.client.domain.model.ClientConfig
import com.phoenix.client.domain.repository.ConfigRepository
import com.phoenix.client.service.PhoenixService
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import javax.inject.Inject

data class HomeUiState(
    val connectionStatus: ConnectionStatus = ConnectionStatus.DISCONNECTED,
    val errorMessage: String? = null,
)

enum class ConnectionStatus { DISCONNECTED, CONNECTING, CONNECTED, ERROR }

@HiltViewModel
class HomeViewModel @Inject constructor(
    application: Application,
    configRepository: ConfigRepository,
) : AndroidViewModel(application) {

    private val _uiState = MutableStateFlow(HomeUiState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    val config: StateFlow<ClientConfig> = configRepository
        .observeConfig()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ClientConfig())

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val statusName = intent.getStringExtra(PhoenixService.STATUS_EXTRA) ?: return
            val status = runCatching {
                PhoenixService.ServiceStatus.valueOf(statusName)
            }.getOrNull() ?: return

            _uiState.update { current ->
                when (status) {
                    PhoenixService.ServiceStatus.CONNECTED ->
                        current.copy(connectionStatus = ConnectionStatus.CONNECTED, errorMessage = null)
                    PhoenixService.ServiceStatus.DISCONNECTED ->
                        current.copy(connectionStatus = ConnectionStatus.DISCONNECTED, errorMessage = null)
                    PhoenixService.ServiceStatus.ERROR ->
                        current.copy(
                            connectionStatus = ConnectionStatus.ERROR,
                            errorMessage = intent.getStringExtra(PhoenixService.ERROR_EXTRA),
                        )
                }
            }
        }
    }

    init {
        ContextCompat.registerReceiver(
            application,
            statusReceiver,
            IntentFilter(PhoenixService.STATUS_ACTION),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    fun connect() {
        val currentConfig = config.value
        if (currentConfig.remoteAddr.isBlank()) {
            _uiState.update { it.copy(connectionStatus = ConnectionStatus.ERROR, errorMessage = "Server address is required") }
            return
        }
        _uiState.update { it.copy(connectionStatus = ConnectionStatus.CONNECTING, errorMessage = null) }
        val ctx = getApplication<Application>()
        ctx.startForegroundService(PhoenixService.startIntent(ctx, currentConfig))
    }

    fun disconnect() {
        val ctx = getApplication<Application>()
        ctx.startService(PhoenixService.stopIntent(ctx))
        _uiState.update { it.copy(connectionStatus = ConnectionStatus.DISCONNECTED, errorMessage = null) }
    }

    override fun onCleared() {
        super.onCleared()
        getApplication<Application>().unregisterReceiver(statusReceiver)
    }
}
