package com.azimberketimur.cryptographyhomework1.configuration

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "auth.jwt")
data class SecurityProperties(
    val secretKey: String,
    val expirationTimeMs: Long,
)
