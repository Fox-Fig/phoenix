package com.phoenix.client.ui.screen

import android.app.Activity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.phoenix.client.ui.theme.PhoenixGreen
import com.phoenix.client.ui.theme.PhoenixOrange
import com.phoenix.client.ui.theme.PhoenixRed
import com.phoenix.client.ui.theme.PhoenixSurface
import com.phoenix.client.ui.viewmodel.ConnectionMode
import com.phoenix.client.ui.viewmodel.ConnectionStatus
import com.phoenix.client.ui.viewmodel.HomeViewModel

@Composable
fun HomeScreen(viewModel: HomeViewModel = hiltViewModel()) {
    val uiState by viewModel.uiState.collectAsState()

    // VPN permission launcher
    val vpnLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.onVpnPermissionGranted()
        } else {
            viewModel.onVpnPermissionDenied()
        }
    }

    // Launch VPN permission dialog when ViewModel requests it
    LaunchedEffect(uiState.vpnPermissionIntent) {
        uiState.vpnPermissionIntent?.let { intent ->
            viewModel.clearVpnPermissionIntent()
            vpnLauncher.launch(intent)
        }
    }

    val statusColor by animateColorAsState(
        targetValue = when (uiState.connectionStatus) {
            ConnectionStatus.CONNECTED -> PhoenixGreen
            ConnectionStatus.ERROR -> PhoenixRed
            ConnectionStatus.CONNECTING -> PhoenixOrange
            ConnectionStatus.DISCONNECTED -> Color.Gray
        },
        animationSpec = tween(400),
        label = "statusColor",
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp, vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {

        // ── Header: title + mode chips ─────────────────────────────────────
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("Phoenix", style = MaterialTheme.typography.headlineLarge, color = PhoenixOrange)

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                val chipEnabled = uiState.connectionStatus == ConnectionStatus.DISCONNECTED ||
                    uiState.connectionStatus == ConnectionStatus.ERROR

                FilterChip(
                    selected = uiState.mode == ConnectionMode.SOCKS5,
                    onClick = { if (chipEnabled) viewModel.setMode(ConnectionMode.SOCKS5) },
                    label = { Text("Proxy", fontSize = 12.sp) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = PhoenixOrange,
                        selectedLabelColor = Color.Black,
                    ),
                )
                FilterChip(
                    selected = uiState.mode == ConnectionMode.VPN,
                    onClick = { if (chipEnabled) viewModel.setMode(ConnectionMode.VPN) },
                    label = { Text("VPN", fontSize = 12.sp) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = PhoenixOrange,
                        selectedLabelColor = Color.Black,
                    ),
                )
            }
        }

        Spacer(Modifier.height(32.dp))

        // ── Status indicator ───────────────────────────────────────────────
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(10.dp)
                    .clip(CircleShape)
                    .background(statusColor),
            )
            Spacer(Modifier.width(8.dp))
            Text(
                text = when (uiState.connectionStatus) {
                    ConnectionStatus.DISCONNECTED -> "Disconnected"
                    ConnectionStatus.CONNECTING -> "Connecting…"
                    ConnectionStatus.CONNECTED -> "Connected"
                    ConnectionStatus.ERROR -> "Error"
                },
                style = MaterialTheme.typography.titleMedium,
                color = statusColor,
            )
        }

        uiState.errorMessage?.let { err ->
            Spacer(Modifier.height(4.dp))
            Text(
                text = err,
                style = MaterialTheme.typography.bodyMedium,
                color = PhoenixRed,
            )
        }

        Spacer(Modifier.height(40.dp))

        // ── Main button — always enabled; CONNECTING tap = cancel ──────────
        val buttonColor by animateColorAsState(
            targetValue = when (uiState.connectionStatus) {
                ConnectionStatus.CONNECTED -> PhoenixRed
                ConnectionStatus.CONNECTING -> Color.Gray
                else -> PhoenixOrange
            },
            animationSpec = tween(400),
            label = "btnColor",
        )

        Button(
            onClick = viewModel::onMainButtonClicked,
            modifier = Modifier.size(140.dp),
            shape = CircleShape,
            colors = ButtonDefaults.buttonColors(containerColor = buttonColor),
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                when (uiState.connectionStatus) {
                    ConnectionStatus.CONNECTING -> {
                        CircularProgressIndicator(
                            modifier = Modifier.size(22.dp),
                            color = Color.White,
                            strokeWidth = 2.dp,
                        )
                        Spacer(Modifier.height(4.dp))
                        Text("Cancel", style = MaterialTheme.typography.labelSmall)
                    }
                    ConnectionStatus.CONNECTED ->
                        Text("Disconnect", style = MaterialTheme.typography.titleMedium)
                    else ->
                        Text("Connect", style = MaterialTheme.typography.titleMedium)
                }
            }
        }

        Spacer(Modifier.height(32.dp))

        // ── Stats card (always visible after first attempt) ────────────────
        if (uiState.connectionAttempts > 0 || uiState.connectionStatus == ConnectionStatus.CONNECTED) {
            StatsCard(uiState = uiState)
        }

        Spacer(Modifier.weight(1f))

        // ── Developer log panel (collapsible) ─────────────────────────────
        DevLogPanel(
            logs = uiState.logs,
            onClear = viewModel::clearLogs,
        )
    }
}

// ── Stats card ─────────────────────────────────────────────────────────────────

@Composable
private fun StatsCard(uiState: com.phoenix.client.ui.viewmodel.HomeUiState) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = PhoenixSurface,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Status", style = MaterialTheme.typography.labelSmall, color = Color.Gray)
            Spacer(Modifier.height(8.dp))

            StatRow(label = "State", value = uiState.connectionStatus.name.lowercase().replaceFirstChar { it.uppercase() })
            StatRow(label = "Attempts", value = uiState.connectionAttempts.toString())
            StatRow(label = "Mode", value = if (uiState.mode == ConnectionMode.VPN) "VPN" else "SOCKS5 Proxy")

            if (uiState.connectionStatus == ConnectionStatus.CONNECTED) {
                StatRow(label = "Uptime", value = formatUptime(uiState.uptimeSeconds))
                StatRow(label = "Local proxy", value = "127.0.0.1:10080")
            }
        }
    }
}

@Composable
private fun StatRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = Color.Gray)
        Text(value, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
    }
}

private fun formatUptime(seconds: Long): String {
    val h = seconds / 3600
    val m = (seconds % 3600) / 60
    val s = seconds % 60
    return "%02d:%02d:%02d".format(h, m, s)
}

// ── Developer log panel ────────────────────────────────────────────────────────

@Composable
private fun DevLogPanel(logs: List<String>, onClear: () -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()

    // Auto-scroll to bottom on new log lines
    LaunchedEffect(logs.size) {
        if (expanded && logs.isNotEmpty()) {
            listState.animateScrollToItem(logs.size - 1)
        }
    }

    Column(modifier = Modifier.fillMaxWidth()) {
        HorizontalDivider(color = Color.Gray.copy(alpha = 0.3f))
        Spacer(Modifier.height(4.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            TextButton(onClick = { expanded = !expanded }) {
                Text(
                    text = if (expanded) "▼ Developer Logs (${logs.size})" else "▶ Developer Logs (${logs.size})",
                    style = MaterialTheme.typography.labelSmall,
                    color = Color.Gray,
                )
            }
            if (expanded && logs.isNotEmpty()) {
                TextButton(onClick = onClear) {
                    Text("Clear", style = MaterialTheme.typography.labelSmall, color = Color.Gray)
                }
            }
        }

        AnimatedVisibility(visible = expanded) {
            Surface(
                shape = RoundedCornerShape(8.dp),
                color = Color(0xFF0A0A0A),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(200.dp),
            ) {
                if (logs.isEmpty()) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text("No logs yet", style = MaterialTheme.typography.labelSmall, color = Color.Gray)
                    }
                } else {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier.padding(8.dp),
                    ) {
                        items(logs) { line ->
                            Text(
                                text = line,
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.sp,
                                ),
                                color = Color(0xFF88FF88),
                                modifier = Modifier.padding(vertical = 1.dp),
                            )
                        }
                    }
                }
            }
        }
    }
}
