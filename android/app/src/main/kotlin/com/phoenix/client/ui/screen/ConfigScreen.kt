package com.phoenix.client.ui.screen

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.phoenix.client.domain.model.ClientConfig
import com.phoenix.client.ui.theme.PhoenixOrange
import com.phoenix.client.ui.viewmodel.ConfigViewModel

@Composable
fun ConfigScreen(viewModel: ConfigViewModel = hiltViewModel()) {
    val savedConfig by viewModel.config.collectAsState()
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    // Local form state — seeded from DataStore on first load
    var remoteAddr by remember(savedConfig.remoteAddr) { mutableStateOf(savedConfig.remoteAddr) }
    var serverPubKey by remember(savedConfig.serverPubKey) { mutableStateOf(savedConfig.serverPubKey) }
    var localSocksAddr by remember(savedConfig.localSocksAddr) { mutableStateOf(savedConfig.localSocksAddr) }
    var enableUdp by remember(savedConfig.enableUdp) { mutableStateOf(savedConfig.enableUdp) }

    // mTLS state — ON when a private key file is configured
    var useMtls by remember(savedConfig.privateKeyFile) {
        mutableStateOf(savedConfig.privateKeyFile.isNotBlank())
    }
    var privateKeyFile by remember(savedConfig.privateKeyFile) {
        mutableStateOf(savedConfig.privateKeyFile)
    }

    // Sync mTLS state when DataStore auto-saves (e.g., after key generation or file import)
    LaunchedEffect(savedConfig.privateKeyFile) {
        privateKeyFile = savedConfig.privateKeyFile
        if (savedConfig.privateKeyFile.isNotBlank()) useMtls = true
    }

    LaunchedEffect(uiState.saved) {
        if (uiState.saved) {
            snackbarHostState.showSnackbar("Configuration saved")
            viewModel.consumeSavedEvent()
        }
    }

    // File picker — lets user select an existing Ed25519 private key from device storage
    val keyFilePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        uri?.let { viewModel.onKeyFilePicked(it) }
    }

    // Public key dialog — shown after successful key generation
    uiState.generatedPublicKey?.let { pubKey ->
        PublicKeyDialog(
            publicKey = pubKey,
            onCopy = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Phoenix Public Key", pubKey))
            },
            onDismiss = viewModel::dismissPublicKeyDialog,
        )
    }

    // Error dialog for key generation / file import failures
    uiState.keyGenError?.let { err ->
        AlertDialog(
            onDismissRequest = viewModel::dismissPublicKeyDialog,
            title = { Text("Key operation failed") },
            text = { Text(err) },
            confirmButton = {
                TextButton(onClick = viewModel::dismissPublicKeyDialog) { Text("OK") }
            },
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 16.dp),
    ) {
        Text("Configuration", style = MaterialTheme.typography.headlineLarge)

        Spacer(Modifier.height(24.dp))

        // ── Server ──────────────────────────────────────────────────────────
        SectionLabel("Server")

        OutlinedTextField(
            value = remoteAddr,
            onValueChange = { remoteAddr = it },
            label = { Text("Server Address") },
            placeholder = { Text("host:port") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        FieldDescription("Address and port of your Phoenix server (e.g. example.com:443).")

        Spacer(Modifier.height(24.dp))

        // ── TLS & Authentication ─────────────────────────────────────────────
        SectionLabel("TLS & Authentication")

        OutlinedTextField(
            value = serverPubKey,
            onValueChange = { serverPubKey = it },
            label = { Text("Server Public Key") },
            placeholder = { Text("Base64-encoded Ed25519 public key") },
            modifier = Modifier.fillMaxWidth(),
            maxLines = 3,
        )
        FieldDescription(
            "The server's Ed25519 public key. Run ./bin/server -gen-keys on the server to obtain it.\n" +
                "• Empty → h2c mode (cleartext HTTP/2, for CDN-fronted deployments)\n" +
                "• Set → TLS mode (One-Way TLS or mTLS)"
        )

        Spacer(Modifier.height(16.dp))

        // mTLS toggle
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text("Mutual TLS (mTLS)", style = MaterialTheme.typography.bodyLarge)
                Text(
                    "Enable only if your server has authorized_clients set.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                )
            }
            Spacer(Modifier.width(8.dp))
            Switch(
                checked = useMtls,
                onCheckedChange = { enabled ->
                    useMtls = enabled
                    if (!enabled) privateKeyFile = ""
                },
            )
        }

        // mTLS key section — visible only when mTLS is enabled
        if (useMtls) {
            Spacer(Modifier.height(12.dp))

            val keyPath = if (privateKeyFile.isNotBlank())
                "${context.filesDir.absolutePath}/$privateKeyFile"
            else
                "No key file selected"

            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(Modifier.padding(12.dp)) {
                    Text(
                        "Private Key Path",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                    )
                    Spacer(Modifier.height(4.dp))
                    SelectionContainer {
                        Text(
                            text = keyPath,
                            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                            color = if (privateKeyFile.isNotBlank()) PhoenixOrange
                                    else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                        )
                    }
                }
            }

            Spacer(Modifier.height(8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = viewModel::generateKeys,
                    enabled = !uiState.isGeneratingKeys,
                    modifier = Modifier.weight(1f),
                    border = androidx.compose.foundation.BorderStroke(1.dp, PhoenixOrange),
                ) {
                    if (uiState.isGeneratingKeys) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp,
                            color = PhoenixOrange,
                        )
                    } else {
                        Text("Generate Key", color = PhoenixOrange)
                    }
                }

                OutlinedButton(
                    onClick = { keyFilePicker.launch(arrayOf("*/*")) },
                    enabled = !uiState.isGeneratingKeys,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Choose File")
                }
            }

            FieldDescription(
                "Your client Ed25519 private key. Generate a new one or import an existing PEM file. " +
                    "After generating, copy the public key shown in the dialog to the server's authorized_clients list."
            )
        }

        Spacer(Modifier.height(24.dp))

        // ── Network ──────────────────────────────────────────────────────────
        SectionLabel("Network")

        OutlinedTextField(
            value = localSocksAddr,
            onValueChange = { localSocksAddr = it },
            label = { Text("Local SOCKS5 Address") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        FieldDescription("Local address where Phoenix listens for SOCKS5 connections. Default: 127.0.0.1:10080.")

        Spacer(Modifier.height(16.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text("Enable UDP (SOCKS5)", style = MaterialTheme.typography.bodyLarge)
                Text(
                    "Allow UDP ASSOCIATE for DNS and other UDP traffic.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                )
            }
            Spacer(Modifier.width(8.dp))
            Switch(checked = enableUdp, onCheckedChange = { enableUdp = it })
        }

        Spacer(Modifier.height(32.dp))

        Button(
            onClick = {
                viewModel.save(
                    ClientConfig(
                        remoteAddr = remoteAddr.trim(),
                        serverPubKey = serverPubKey.trim(),
                        privateKeyFile = if (useMtls) privateKeyFile.trim() else "",
                        localSocksAddr = localSocksAddr.trim(),
                        enableUdp = enableUdp,
                    ),
                )
            },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = PhoenixOrange),
        ) {
            Text("Save Configuration", color = Color.Black)
        }
    }

    SnackbarHost(hostState = snackbarHostState)
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text = text.uppercase(),
        style = MaterialTheme.typography.labelSmall,
        color = PhoenixOrange,
        modifier = Modifier.padding(bottom = 8.dp),
    )
}

@Composable
private fun FieldDescription(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
        modifier = Modifier.padding(top = 4.dp, start = 4.dp),
    )
}

@Composable
private fun PublicKeyDialog(
    publicKey: String,
    onCopy: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Keys Generated") },
        text = {
            Column {
                Text(
                    text = "Your client key pair has been created. " +
                        "Add this public key to your server's authorized_clients list:",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(12.dp))
                SelectionContainer {
                    Text(
                        text = publicKey,
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                        color = PhoenixOrange,
                    )
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "Private key saved to app storage as client.private.key",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onCopy()
                    onDismiss()
                },
                colors = ButtonDefaults.buttonColors(containerColor = PhoenixOrange),
            ) {
                Text("Copy & Close", color = Color.Black)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        },
    )
}
