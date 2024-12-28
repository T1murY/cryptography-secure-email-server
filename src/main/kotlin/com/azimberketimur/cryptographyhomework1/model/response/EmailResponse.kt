package com.azimberketimur.cryptographyhomework1.model.response

import java.util.*

data class EmailResponse(
    val id: UUID,
    val fromUser: String,
    val toUser: String,
    val encryptedMessage: String,
    val signature: String,
    val diffieHellmanPublicKey: String,
    val rsaPublicKey: String
)