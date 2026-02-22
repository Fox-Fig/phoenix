package com.phoenix.client.data.repository

import com.phoenix.client.data.datastore.ConfigDataStore
import com.phoenix.client.domain.model.ClientConfig
import com.phoenix.client.domain.repository.ConfigRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class ConfigRepositoryImpl @Inject constructor(
    private val dataStore: ConfigDataStore,
) : ConfigRepository {

    override fun observeConfig(): Flow<ClientConfig> = dataStore.configFlow

    override suspend fun saveConfig(config: ClientConfig) = dataStore.save(config)
}
