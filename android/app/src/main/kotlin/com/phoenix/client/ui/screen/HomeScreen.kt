package com.phoenix.client.ui.screen

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.phoenix.client.R
import com.phoenix.client.ui.theme.PhoenixGreen
import com.phoenix.client.ui.theme.PhoenixOrange
import com.phoenix.client.ui.theme.PhoenixRed
import com.phoenix.client.ui.viewmodel.ConnectionStatus
import com.phoenix.client.ui.viewmodel.HomeViewModel

@Composable
fun HomeScreen(viewModel: HomeViewModel = hiltViewModel()) {
    val uiState by viewModel.uiState.collectAsState()

    val buttonColor by animateColorAsState(
        targetValue = when (uiState.connectionStatus) {
            ConnectionStatus.CONNECTED -> PhoenixGreen
            ConnectionStatus.ERROR -> PhoenixRed
            else -> PhoenixOrange
        },
        animationSpec = tween(400),
        label = "buttonColor",
    )

    val statusLabel = stringResource(
        when (uiState.connectionStatus) {
            ConnectionStatus.DISCONNECTED -> R.string.status_disconnected
            ConnectionStatus.CONNECTING -> R.string.status_connecting
            ConnectionStatus.CONNECTED -> R.string.status_connected
            ConnectionStatus.ERROR -> R.string.status_error
        },
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = "Phoenix",
            style = MaterialTheme.typography.headlineLarge,
            color = PhoenixOrange,
        )

        Spacer(Modifier.height(8.dp))

        Text(
            text = statusLabel,
            style = MaterialTheme.typography.titleMedium,
            color = buttonColor,
        )

        uiState.errorMessage?.let { err ->
            Spacer(Modifier.height(4.dp))
            Text(
                text = err,
                style = MaterialTheme.typography.bodyMedium,
                color = PhoenixRed,
            )
        }

        Spacer(Modifier.height(48.dp))

        // Big connect / disconnect button
        Button(
            onClick = {
                if (uiState.connectionStatus == ConnectionStatus.CONNECTED) {
                    viewModel.disconnect()
                } else {
                    viewModel.connect()
                }
            },
            modifier = Modifier.size(140.dp),
            shape = CircleShape,
            colors = ButtonDefaults.buttonColors(containerColor = buttonColor),
            enabled = uiState.connectionStatus != ConnectionStatus.CONNECTING,
        ) {
            Text(
                text = if (uiState.connectionStatus == ConnectionStatus.CONNECTED) {
                    stringResource(R.string.disconnect)
                } else {
                    stringResource(R.string.connect)
                },
                style = MaterialTheme.typography.titleMedium,
            )
        }

        if (uiState.connectionStatus == ConnectionStatus.CONNECTED) {
            Spacer(Modifier.height(24.dp))
            Text(
                text = stringResource(R.string.socks5_info),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
            )
        }
    }
}
