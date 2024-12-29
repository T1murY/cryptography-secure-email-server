package com.azimberketimur.cryptographyhomework1.model.request

data class SendEmailRequest(
    val email: String,
    val message: String,
    val signature: String
)
