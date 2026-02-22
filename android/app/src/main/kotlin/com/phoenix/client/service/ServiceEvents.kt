package com.phoenix.client.service

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow

/**
 * In-process event bus between [PhoenixService] and [HomeViewModel].
 *
 * Using SharedFlow instead of Android broadcasts avoids broadcast throttling
 * and delivery issues present on some OEM ROMs (notably Samsung).
 * Both Service and ViewModel are in the same process so no IPC is needed.
 */
object ServiceEvents {

    // replay=1 so a new subscriber instantly gets the last known status
    private val _status = MutableSharedFlow<StatusEvent>(replay = 1, extraBufferCapacity = 8)
    val status = _status.asSharedFlow()

    // logs: no replay — only lines arriving while the screen is open matter
    private val _log = MutableSharedFlow<String>(replay = 0, extraBufferCapacity = 500)
    val log = _log.asSharedFlow()

    fun emitStatus(event: StatusEvent) {
        _status.tryEmit(event)
    }

    fun emitLog(line: String) {
        _log.tryEmit(line)
    }

    sealed class StatusEvent {
        data object Connected : StatusEvent()
        data object Disconnected : StatusEvent()
        data class Error(val message: String) : StatusEvent()
    }
}
