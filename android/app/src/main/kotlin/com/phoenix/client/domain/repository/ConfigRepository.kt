package com.phoenix.client.domain.repository

import com.phoenix.client.domain.model.ClientConfig
import kotlinx.coroutines.flow.Flow

interface ConfigRepository {
    fun observeConfig(): Flow<ClientConfig>
    suspend fun saveConfig(config: ClientConfig)
}
