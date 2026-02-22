package com.phoenix.client.domain.model

/**
 * Domain model representing the Phoenix client configuration.
 *
 * @param remoteAddr      Server address in host:port format.
 * @param serverPubKey    Server Ed25519 public key (Base64). Empty string = h2c mode.
 * @param privateKeyFile  File name (inside filesDir) of the client Ed25519 private key.
 *                        Empty string = one-way TLS or h2c (no client auth).
 * @param clientPublicKey Base64 client Ed25519 public key — populated after key generation,
 *                        empty when a key file was imported from device storage.
 * @param localSocksAddr  Local SOCKS5 listen address. Default: 127.0.0.1:10080.
 * @param enableUdp       Whether to allow SOCKS5 UDP ASSOCIATE.
 */
data class ClientConfig(
    val remoteAddr: String = "",
    val serverPubKey: String = "",
    val privateKeyFile: String = "",
    val clientPublicKey: String = "",
    val localSocksAddr: String = "127.0.0.1:10080",
    val enableUdp: Boolean = false,
)
