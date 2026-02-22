package com.phoenix.client.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.util.Log
import com.phoenix.client.R
import com.phoenix.client.domain.model.ClientConfig
import com.phoenix.client.ui.MainActivity
import com.phoenix.client.util.BinaryExtractor
import com.phoenix.client.util.ConfigWriter
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.InterruptedIOException
import java.util.concurrent.atomic.AtomicBoolean

class PhoenixService : Service() {

    companion object {
        private const val TAG = "PhoenixService"
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "phoenix_proxy"

        const val ACTION_START = "com.phoenix.client.START"
        const val ACTION_STOP = "com.phoenix.client.STOP"

        // Config extras
        const val EXTRA_REMOTE_ADDR = "remote_addr"
        const val EXTRA_SERVER_PUBKEY = "server_pub_key"
        const val EXTRA_PRIVATE_KEY_FILE = "private_key_file"
        const val EXTRA_LOCAL_SOCKS_ADDR = "local_socks_addr"
        const val EXTRA_ENABLE_UDP = "enable_udp"

        fun startIntent(context: Context, config: ClientConfig): Intent =
            Intent(context, PhoenixService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_REMOTE_ADDR, config.remoteAddr)
                putExtra(EXTRA_SERVER_PUBKEY, config.serverPubKey)
                putExtra(EXTRA_PRIVATE_KEY_FILE, config.privateKeyFile)
                putExtra(EXTRA_LOCAL_SOCKS_ADDR, config.localSocksAddr)
                putExtra(EXTRA_ENABLE_UDP, config.enableUdp)
            }

        fun stopIntent(context: Context): Intent =
            Intent(context, PhoenixService::class.java).apply { action = ACTION_STOP }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var process: Process? = null

    /**
     * Set to true before we intentionally destroy the process so that the
     * InterruptedIOException thrown by forEachLine is not treated as an error.
     */
    private val intentionallyStopped = AtomicBoolean(false)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                intentionallyStopped.set(false)
                val config = intent.toClientConfig()
                startForeground(NOTIFICATION_ID, buildNotification())
                scope.launch { launchGoProcess(config) }
            }
            ACTION_STOP -> {
                intentionallyStopped.set(true)
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        intentionallyStopped.set(true)
        killProcess()
        stopForeground(STOP_FOREGROUND_REMOVE)
        scope.cancel()
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    private fun launchGoProcess(config: ClientConfig) {
        killProcess()

        val binary = try {
            BinaryExtractor.extract(this)
        } catch (e: Exception) {
            ServiceEvents.emitLog("ERROR: binary not found — ${e.message}")
            ServiceEvents.emitStatus(ServiceEvents.StatusEvent.Error("Binary not found: ${e.message}"))
            stopSelf()
            return
        }

        val configResult = try {
            ConfigWriter.write(this, config)
        } catch (e: Exception) {
            ServiceEvents.emitLog("ERROR: config write failed — ${e.message}")
            ServiceEvents.emitStatus(ServiceEvents.StatusEvent.Error("Config write failed: ${e.message}"))
            stopSelf()
            return
        }

        // Log the exact TOML so developers can verify the config in the UI panel
        ServiceEvents.emitLog("=== client.toml ===")
        configResult.tomlContent.lines().forEach { ServiceEvents.emitLog(it) }
        ServiceEvents.emitLog("==================")

        val cmd = arrayOf(
            binary.absolutePath,
            "-config", configResult.file.absolutePath,
            "-files-dir", filesDir.absolutePath,
        )
        ServiceEvents.emitLog("CMD: ${cmd.joinToString(" ")}")
        Log.i(TAG, "Launching: ${cmd.joinToString(" ")}")

        try {
            process = ProcessBuilder(*cmd)
                .redirectErrorStream(true)
                .start()

            // Wait for the Go binary to confirm it is actually listening before
            // broadcasting CONNECTED. This gives users accurate status and avoids
            // showing "Connected" during early startup/TLS handshake phases.
            var listenerStarted = false

            process!!.inputStream.bufferedReader().forEachLine { line ->
                Log.i(TAG, "[go] $line")
                ServiceEvents.emitLog(line)

                if (!listenerStarted && "Listening on" in line) {
                    listenerStarted = true
                    ServiceEvents.emitStatus(ServiceEvents.StatusEvent.Connected)
                }
            }

            val exitCode = process!!.waitFor()
            val exitMsg = "Process exited (code $exitCode)"
            Log.i(TAG, exitMsg)
            ServiceEvents.emitLog(exitMsg)

            if (!intentionallyStopped.get()) {
                if (!listenerStarted) {
                    // Process died before ever becoming ready
                    ServiceEvents.emitStatus(
                        ServiceEvents.StatusEvent.Error(
                            "Process exited before listening (code $exitCode) — check logs",
                        ),
                    )
                } else {
                    ServiceEvents.emitStatus(ServiceEvents.StatusEvent.Disconnected)
                }
            }
        } catch (e: InterruptedIOException) {
            // Expected when killProcess() calls process.destroy() while forEachLine is
            // blocking. Only log it — do NOT emit an error to the user.
            Log.d(TAG, "Stream closed (expected on stop): ${e.message}")
        } catch (e: Exception) {
            if (!intentionallyStopped.get()) {
                val msg = "Process error: ${e.message}"
                Log.e(TAG, msg)
                ServiceEvents.emitLog("ERROR: $msg")
                ServiceEvents.emitStatus(ServiceEvents.StatusEvent.Error(msg))
            }
        } finally {
            if (!intentionallyStopped.get()) {
                stopSelf()
            }
        }
    }

    private fun killProcess() {
        intentionallyStopped.set(true)
        process?.destroy()
        process = null
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        )
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val openIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(openIntent)
            .setOngoing(true)
            .build()
    }

    private fun Intent.toClientConfig() = ClientConfig(
        remoteAddr = getStringExtra(EXTRA_REMOTE_ADDR) ?: "",
        serverPubKey = getStringExtra(EXTRA_SERVER_PUBKEY) ?: "",
        privateKeyFile = getStringExtra(EXTRA_PRIVATE_KEY_FILE) ?: "",
        localSocksAddr = getStringExtra(EXTRA_LOCAL_SOCKS_ADDR) ?: "127.0.0.1:10080",
        enableUdp = getBooleanExtra(EXTRA_ENABLE_UDP, false),
    )
}
