package com.phoenix.client.util

import android.content.Context
import com.phoenix.client.domain.model.ClientConfig
import java.io.File

/**
 * Writes a TOML config file compatible with the Phoenix Go client binary.
 * Returns the [File] path to pass via the `-config` flag.
 */
object ConfigWriter {

    private const val CONFIG_FILE = "client.toml"

    fun write(context: Context, config: ClientConfig): File {
        val file = File(context.filesDir, CONFIG_FILE)

        val privKeyLine = if (config.privateKeyFile.isNotBlank()) {
            val absPath = File(context.filesDir, config.privateKeyFile).absolutePath
            "private_key_path = \"$absPath\""
        } else {
            ""
        }

        val serverPubKeyLine = if (config.serverPubKey.isNotBlank()) {
            "server_public_key = \"${config.serverPubKey}\""
        } else {
            ""
        }

        val toml = buildString {
            appendLine("remote_addr = \"${config.remoteAddr}\"")
            if (privKeyLine.isNotBlank()) appendLine(privKeyLine)
            if (serverPubKeyLine.isNotBlank()) appendLine(serverPubKeyLine)
            appendLine()
            appendLine("[[inbounds]]")
            appendLine("protocol = \"socks5\"")
            appendLine("local_addr = \"${config.localSocksAddr}\"")
            appendLine("enable_udp = ${config.enableUdp}")
        }

        file.writeText(toml)
        return file
    }
}
