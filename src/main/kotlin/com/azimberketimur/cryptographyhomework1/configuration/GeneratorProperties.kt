package com.azimberketimur.cryptographyhomework1.configuration

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "diffie-hellman")
data class DiffieHellmanProperties(
    val generator: Int,
    val prime: Int,
)