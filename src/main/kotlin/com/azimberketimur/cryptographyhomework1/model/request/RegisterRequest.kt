package com.azimberketimur.cryptographyhomework1.model.request

data class RegisterRequest(
    val email: String,
    val password: String,
    val diffieHellmanExchangeKey: String,
    val publicKey: String
)