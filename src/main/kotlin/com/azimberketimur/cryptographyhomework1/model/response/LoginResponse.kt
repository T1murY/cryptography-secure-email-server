package com.azimberketimur.cryptographyhomework1.model.response

import java.util.UUID

data class LoginResponse(
    val userId: UUID,
    val email: String,
    val accessToken: String
)
