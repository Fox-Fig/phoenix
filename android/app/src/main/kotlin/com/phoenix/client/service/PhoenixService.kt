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

        // Status broadcast
        const val STATUS_ACTION = "com.phoenix.client.SERVICE_STATUS"
        const val STATUS_EXTRA = "status"
        const val ERROR_EXTRA = "error_message"

        // Log broadcast — one intent per line from Go stdout
        const val LOG_ACTION = "com.phoenix.client.LOG"
        const val LOG_LINE_EXTRA = "log_line"

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

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val config = intent.toClientConfig()
                startForeground(NOTIFICATION_ID, buildNotification())
                scope.launch { launchGoProcess(config) }
            }
            ACTION_STOP -> stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        killProcess()
        scope.cancel()
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    private fun launchGoProcess(config: ClientConfig) {
        killProcess()

        val binary = try {
            BinaryExtractor.extract(this)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to locate binary: $e")
            broadcastError("Binary not found: ${e.message}")
            stopSelf()
            return
        }

        val configFile = try {
            ConfigWriter.write(this, config)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to write config: $e")
            broadcastError("Config write failed: ${e.message}")
            stopSelf()
            return
        }

        val cmd = arrayOf(
            binary.absolutePath,
            "-config", configFile.absolutePath,
            "-files-dir", filesDir.absolutePath,
        )
        broadcastLog("Starting: ${cmd.joinToString(" ")}")

        try {
            process = ProcessBuilder(*cmd)
                .redirectErrorStream(true)
                .start()

            broadcastStatus(ServiceStatus.CONNECTED)

            // Stream every line from Go stdout to both Logcat and the UI log panel.
            process!!.inputStream.bufferedReader().forEachLine { line ->
                Log.i(TAG, "[go] $line")
                broadcastLog(line)
            }

            val exitCode = process!!.waitFor()
            val msg = "Process exited with code $exitCode"
            Log.i(TAG, msg)
            broadcastLog(msg)
            broadcastStatus(ServiceStatus.DISCONNECTED)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to run Go process: $e")
            broadcastError("Process error: ${e.message}")
        } finally {
            stopSelf()
        }
    }

    private fun killProcess() {
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

    private fun broadcastStatus(status: ServiceStatus) {
        sendBroadcast(Intent(STATUS_ACTION).putExtra(STATUS_EXTRA, status.name))
    }

    private fun broadcastError(message: String) {
        sendBroadcast(
            Intent(STATUS_ACTION)
                .putExtra(STATUS_EXTRA, ServiceStatus.ERROR.name)
                .putExtra(ERROR_EXTRA, message),
        )
    }

    private fun broadcastLog(line: String) {
        sendBroadcast(Intent(LOG_ACTION).putExtra(LOG_LINE_EXTRA, line))
    }

    private fun Intent.toClientConfig() = ClientConfig(
        remoteAddr = getStringExtra(EXTRA_REMOTE_ADDR) ?: "",
        serverPubKey = getStringExtra(EXTRA_SERVER_PUBKEY) ?: "",
        privateKeyFile = getStringExtra(EXTRA_PRIVATE_KEY_FILE) ?: "",
        localSocksAddr = getStringExtra(EXTRA_LOCAL_SOCKS_ADDR) ?: "127.0.0.1:10080",
        enableUdp = getBooleanExtra(EXTRA_ENABLE_UDP, false),
    )

    enum class ServiceStatus { CONNECTED, DISCONNECTED, ERROR }
}
