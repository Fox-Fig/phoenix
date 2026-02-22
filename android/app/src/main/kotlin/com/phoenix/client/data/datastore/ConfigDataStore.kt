package com.phoenix.client.data.datastore

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.phoenix.client.domain.model.ClientConfig
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "phoenix_config")

@Singleton
class ConfigDataStore @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private object Keys {
        val REMOTE_ADDR = stringPreferencesKey("remote_addr")
        val SERVER_PUB_KEY = stringPreferencesKey("server_pub_key")
        val PRIVATE_KEY_FILE = stringPreferencesKey("private_key_file")
        val LOCAL_SOCKS_ADDR = stringPreferencesKey("local_socks_addr")
        val ENABLE_UDP = booleanPreferencesKey("enable_udp")
    }

    val configFlow: Flow<ClientConfig> = context.dataStore.data.map { prefs ->
        ClientConfig(
            remoteAddr = prefs[Keys.REMOTE_ADDR] ?: "",
            serverPubKey = prefs[Keys.SERVER_PUB_KEY] ?: "",
            privateKeyFile = prefs[Keys.PRIVATE_KEY_FILE] ?: "",
            localSocksAddr = prefs[Keys.LOCAL_SOCKS_ADDR] ?: "127.0.0.1:10080",
            enableUdp = prefs[Keys.ENABLE_UDP] ?: false,
        )
    }

    suspend fun save(config: ClientConfig) {
        context.dataStore.edit { prefs ->
            prefs[Keys.REMOTE_ADDR] = config.remoteAddr
            prefs[Keys.SERVER_PUB_KEY] = config.serverPubKey
            prefs[Keys.PRIVATE_KEY_FILE] = config.privateKeyFile
            prefs[Keys.LOCAL_SOCKS_ADDR] = config.localSocksAddr
            prefs[Keys.ENABLE_UDP] = config.enableUdp
        }
    }
}
