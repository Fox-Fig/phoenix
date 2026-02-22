package com.phoenix.client.ui.screen

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.phoenix.client.R
import com.phoenix.client.domain.model.ClientConfig
import com.phoenix.client.ui.viewmodel.ConfigViewModel

@Composable
fun ConfigScreen(viewModel: ConfigViewModel = hiltViewModel()) {
    val savedConfig by viewModel.config.collectAsState()
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val savedMessage = stringResource(R.string.config_saved)

    // Populate local form state once config loads from DataStore
    var remoteAddr by remember(savedConfig.remoteAddr) { mutableStateOf(savedConfig.remoteAddr) }
    var serverPubKey by remember(savedConfig.serverPubKey) { mutableStateOf(savedConfig.serverPubKey) }
    var privateKeyFile by remember(savedConfig.privateKeyFile) { mutableStateOf(savedConfig.privateKeyFile) }
    var localSocksAddr by remember(savedConfig.localSocksAddr) { mutableStateOf(savedConfig.localSocksAddr) }
    var enableUdp by remember(savedConfig.enableUdp) { mutableStateOf(savedConfig.enableUdp) }

    LaunchedEffect(uiState.saved) {
        if (uiState.saved) {
            snackbarHostState.showSnackbar(savedMessage)
            viewModel.consumeSavedEvent()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
    ) {
        Text(
            text = stringResource(R.string.nav_config),
            style = MaterialTheme.typography.headlineLarge,
        )

        Spacer(Modifier.height(24.dp))

        OutlinedTextField(
            value = remoteAddr,
            onValueChange = { remoteAddr = it },
            label = { Text(stringResource(R.string.config_server_address)) },
            placeholder = { Text(stringResource(R.string.config_server_address_hint)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(16.dp))

        OutlinedTextField(
            value = serverPubKey,
            onValueChange = { serverPubKey = it },
            label = { Text(stringResource(R.string.config_server_pubkey)) },
            placeholder = { Text(stringResource(R.string.config_server_pubkey_hint)) },
            modifier = Modifier.fillMaxWidth(),
            maxLines = 3,
        )

        Spacer(Modifier.height(16.dp))

        OutlinedTextField(
            value = privateKeyFile,
            onValueChange = { privateKeyFile = it },
            label = { Text(stringResource(R.string.config_private_key_path)) },
            placeholder = { Text(stringResource(R.string.config_private_key_hint)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(16.dp))

        OutlinedTextField(
            value = localSocksAddr,
            onValueChange = { localSocksAddr = it },
            label = { Text(stringResource(R.string.config_server_address)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(16.dp))

        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                text = stringResource(R.string.config_enable_udp),
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodyMedium,
            )
            Switch(checked = enableUdp, onCheckedChange = { enableUdp = it })
        }

        Spacer(Modifier.height(32.dp))

        Button(
            onClick = {
                viewModel.save(
                    ClientConfig(
                        remoteAddr = remoteAddr.trim(),
                        serverPubKey = serverPubKey.trim(),
                        privateKeyFile = privateKeyFile.trim(),
                        localSocksAddr = localSocksAddr.trim(),
                        enableUdp = enableUdp,
                    ),
                )
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.config_save))
        }
    }

    SnackbarHost(hostState = snackbarHostState)
}
