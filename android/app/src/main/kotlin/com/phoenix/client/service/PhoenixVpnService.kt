package com.phoenix.client.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.LocalServerSocket
import android.net.VpnService
import android.os.IBinder
import android.os.ParcelFileDescriptor
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

class PhoenixVpnService : VpnService() {

    companion object {
        private const val TAG = "PhoenixVpnService"
        private const val NOTIFICATION_ID = 2
        private const val CHANNEL_ID = "phoenix_vpn"

        const val ACTION_START = "com.phoenix.client.VPN_START"
        const val ACTION_STOP = "com.phoenix.client.VPN_STOP"

        const val EXTRA_REMOTE_ADDR = "remote_addr"
        const val EXTRA_SERVER_PUBKEY = "server_pub_key"
        const val EXTRA_PRIVATE_KEY_FILE = "private_key_file"
        const val EXTRA_LOCAL_SOCKS_ADDR = "local_socks_addr"
        const val EXTRA_ENABLE_UDP = "enable_udp"

        fun startIntent(context: Context, config: ClientConfig): Intent =
            Intent(context, PhoenixVpnService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_REMOTE_ADDR, config.remoteAddr)
                putExtra(EXTRA_SERVER_PUBKEY, config.serverPubKey)
                putExtra(EXTRA_PRIVATE_KEY_FILE, config.privateKeyFile)
                putExtra(EXTRA_LOCAL_SOCKS_ADDR, config.localSocksAddr)
                putExtra(EXTRA_ENABLE_UDP, config.enableUdp)
            }

        fun stopIntent(context: Context): Intent =
            Intent(context, PhoenixVpnService::class.java).apply { action = ACTION_STOP }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var process: Process? = null
    private var tunInterface: ParcelFileDescriptor? = null
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
                // startForeground() is required by Android to avoid a crash,
                // but we immediately remove it — the active VPN session keeps
                // the service alive without a visible notification.
                startForeground(NOTIFICATION_ID, buildNotification())
                stopForeground(STOP_FOREGROUND_REMOVE)
                scope.launch { launchVpn(config) }
            }
            ACTION_STOP -> {
                intentionallyStopped.set(true)
                // Kill Go process first so it releases its copy of the TUN fd,
                // then close the Kotlin-side PFD. Both must be closed before
                // Android removes the VPN key icon from the status bar.
                killProcess()
                closeTun()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        intentionallyStopped.set(true)
        killProcess()
        closeTun()
        stopForeground(STOP_FOREGROUND_REMOVE)
        scope.cancel()
    }

    override fun onRevoke() {
        super.onRevoke()
        intentionallyStopped.set(true)
        killProcess()
        closeTun()
        ServiceEvents.emitStatus(ServiceEvents.StatusEvent.Disconnected)
        stopSelf()
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    private fun launchVpn(config: ClientConfig) {
        killProcess()
        closeTun()

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

        ServiceEvents.emitLog("=== client.toml ===")
        configResult.tomlContent.lines().forEach { ServiceEvents.emitLog(it) }
        ServiceEvents.emitLog("==================")

        // Establish the TUN interface.
        val tunPfd = try {
            Builder()
                .setSession("Phoenix VPN")
                .addAddress("10.233.233.1", 30)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .setMtu(1500)
                .addDisallowedApplication(packageName) // exclude Phoenix itself → no routing loop
                .establish()
        } catch (e: Exception) {
            ServiceEvents.emitLog("ERROR: TUN setup failed — ${e.message}")
            ServiceEvents.emitStatus(ServiceEvents.StatusEvent.Error("TUN setup failed: ${e.message}"))
            stopSelf()
            return
        }

        if (tunPfd == null) {
            ServiceEvents.emitLog("ERROR: VPN establish() returned null — permission not granted?")
            ServiceEvents.emitStatus(ServiceEvents.StatusEvent.Error("VPN permission not granted"))
            stopSelf()
            return
        }

        tunInterface = tunPfd
        ServiceEvents.emitLog("TUN interface established (fd=${tunPfd.fd})")

        // Use an abstract Unix socket to pass the TUN fd to the Go subprocess via SCM_RIGHTS.
        // This is the standard approach on Android — direct fd inheritance is blocked
        // (Android closes non-stdio fds before exec) and /proc/<pid>/fd/ is blocked by SELinux.
        val socketName = "phoenix-tun-${android.os.Process.myPid()}"
        val server = LocalServerSocket(socketName)

        // Daemon thread: accept Go's connection and send the TUN fd.
        // Runs concurrently with process output reading below.
        val fdSender = Thread {
            try {
                val peer = server.accept()
                peer.setFileDescriptorsForSend(arrayOf(tunPfd.fileDescriptor))
                peer.outputStream.write(1) // any byte triggers ancillary data delivery
                peer.outputStream.flush()
                peer.close()
                ServiceEvents.emitLog("TUN fd sent to Go via SCM_RIGHTS")
            } catch (e: Exception) {
                if (!intentionallyStopped.get()) {
                    ServiceEvents.emitLog("WARN: fd socket transfer failed: ${e.message}")
                }
            } finally {
                try { server.close() } catch (_: Exception) {}
            }
        }
        fdSender.isDaemon = true
        fdSender.start()

        val cmd = arrayOf(
            binary.absolutePath,
            "-config", configResult.file.absolutePath,
            "-files-dir", filesDir.absolutePath,
            "-tun-socket", socketName,
        )
        ServiceEvents.emitLog("CMD: ${cmd.joinToString(" ")}")
        Log.i(TAG, "Launching VPN: ${cmd.joinToString(" ")}")

        try {
            process = ProcessBuilder(*cmd)
                .redirectErrorStream(true)
                .start()

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
            ServiceEvents.emitLog("VPN process exited (code $exitCode)")

            if (!intentionallyStopped.get()) {
                if (!listenerStarted) {
                    ServiceEvents.emitStatus(
                        ServiceEvents.StatusEvent.Error(
                            "VPN process exited before listening (code $exitCode) — check logs",
                        ),
                    )
                } else {
                    ServiceEvents.emitStatus(ServiceEvents.StatusEvent.Disconnected)
                }
            }
        } catch (e: InterruptedIOException) {
            Log.d(TAG, "Stream closed (expected on stop): ${e.message}")
        } catch (e: Exception) {
            if (!intentionallyStopped.get()) {
                val msg = "VPN process error: ${e.message}"
                Log.e(TAG, msg)
                ServiceEvents.emitLog("ERROR: $msg")
                ServiceEvents.emitStatus(ServiceEvents.StatusEvent.Error(msg))
            }
        } finally {
            // Close the server socket to unblock accept() in fdSender if Go never connected.
            try { server.close() } catch (_: Exception) {}
            if (!intentionallyStopped.get()) stopSelf()
        }
    }

    private fun killProcess() {
        process?.destroy()
        process = null
    }

    private fun closeTun() {
        try { tunInterface?.close() } catch (_: Exception) {}
        tunInterface = null
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Phoenix VPN",
            // IMPORTANCE_MIN: no status bar icon. Android already shows the VPN
            // key icon system-wide; an extra app icon is redundant in VPN mode.
            NotificationManager.IMPORTANCE_MIN,
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
            .setContentText("VPN mode active — all traffic tunnelled")
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
