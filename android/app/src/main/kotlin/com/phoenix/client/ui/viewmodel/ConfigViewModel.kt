package com.phoenix.client.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.phoenix.client.domain.model.ClientConfig
import com.phoenix.client.domain.repository.ConfigRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class ConfigUiState(
    val saved: Boolean = false,
)

@HiltViewModel
class ConfigViewModel @Inject constructor(
    private val configRepository: ConfigRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(ConfigUiState())
    val uiState: StateFlow<ConfigUiState> = _uiState.asStateFlow()

    val config: StateFlow<ClientConfig> = configRepository
        .observeConfig()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ClientConfig())

    fun save(config: ClientConfig) {
        viewModelScope.launch {
            configRepository.saveConfig(config)
            _uiState.update { it.copy(saved = true) }
        }
    }

    fun consumeSavedEvent() {
        _uiState.update { it.copy(saved = false) }
    }
}
