package com.phoenix.client.util

import android.content.Context
import java.io.File

/**
 * Extracts the bundled Go binary from assets to the app's private files directory
 * and marks it executable. Safe to call multiple times — only re-extracts when the
 * asset changes (detected by size mismatch, which covers most updates).
 */
object BinaryExtractor {

    private const val ASSET_NAME = "phoenix-client"

    /**
     * Returns the [File] pointing to the extracted binary, ready to execute.
     */
    fun extract(context: Context): File {
        val dest = File(context.filesDir, ASSET_NAME)

        context.assets.openFd(ASSET_NAME).use { fd ->
            val assetSize = fd.length
            if (dest.exists() && dest.length() == assetSize) {
                return dest // Already up-to-date.
            }
        }

        context.assets.open(ASSET_NAME).use { input ->
            dest.outputStream().use { output ->
                input.copyTo(output)
            }
        }
        dest.setExecutable(true, true)
        return dest
    }
}
