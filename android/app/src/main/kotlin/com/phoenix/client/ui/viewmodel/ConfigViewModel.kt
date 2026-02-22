package com.phoenix.client.ui.viewmodel

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.phoenix.client.domain.model.ClientConfig
import com.phoenix.client.domain.repository.ConfigRepository
import com.phoenix.client.util.KeyManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject

data class ConfigUiState(
    val saved: Boolean = false,
    val isGeneratingKeys: Boolean = false,
    /** Non-null after key generation succeeds — shown to user so they can copy to server. */
    val generatedPublicKey: String? = null,
    val keyGenError: String? = null,
)

@HiltViewModel
class ConfigViewModel @Inject constructor(
    application: Application,
    private val configRepository: ConfigRepository,
) : AndroidViewModel(application) {

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

    /**
     * Runs the Go binary with `-gen-keys`, writes `client.private.key` to filesDir,
     * and exposes the public key via [ConfigUiState.generatedPublicKey].
     *
     * On success, both the private key filename and public key are auto-saved to DataStore.
     */
    fun generateKeys() {
        if (_uiState.value.isGeneratingKeys) return
        _uiState.update { it.copy(isGeneratingKeys = true, keyGenError = null, generatedPublicKey = null) }

        viewModelScope.launch {
            runCatching {
                KeyManager.generateKeys(getApplication())
            }.onSuccess { pair ->
                val currentConfig = config.value
                configRepository.saveConfig(
                    currentConfig.copy(
                        privateKeyFile = pair.privateKeyFile,
                        clientPublicKey = pair.publicKey,
                    ),
                )
                _uiState.update {
                    it.copy(
                        isGeneratingKeys = false,
                        generatedPublicKey = pair.publicKey,
                    )
                }
            }.onFailure { e ->
                _uiState.update {
                    it.copy(
                        isGeneratingKeys = false,
                        keyGenError = e.message ?: "Unknown error",
                    )
                }
            }
        }
    }

    /**
     * Copies the file at [uri] (content:// URI from the file picker) into the app's
     * private filesDir as `client.private.key` and auto-saves the filename to DataStore.
     * clientPublicKey is cleared because it cannot be derived from an imported file.
     */
    fun onKeyFilePicked(uri: Uri) {
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    val ctx = getApplication<Application>()
                    val destFile = File(ctx.filesDir, "client.private.key")
                    ctx.contentResolver.openInputStream(uri)?.use { input ->
                        destFile.outputStream().use { input.copyTo(it) }
                    } ?: throw IllegalStateException("Cannot open selected file")
                    val currentConfig = config.value
                    configRepository.saveConfig(
                        currentConfig.copy(
                            privateKeyFile = "client.private.key",
                            clientPublicKey = "",
                        ),
                    )
                }
            }.onFailure { e ->
                _uiState.update { it.copy(keyGenError = "Failed to import key: ${e.message}") }
            }
        }
    }

    fun dismissPublicKeyDialog() {
        _uiState.update { it.copy(generatedPublicKey = null, keyGenError = null) }
    }
}
