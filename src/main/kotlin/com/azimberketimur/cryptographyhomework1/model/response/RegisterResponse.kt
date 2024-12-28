package com.azimberketimur.cryptographyhomework1.model.response

import java.util.UUID

data class RegisterResponse(
    val id: UUID,
    val email: String
)
