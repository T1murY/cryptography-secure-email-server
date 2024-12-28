package com.azimberketimur.cryptographyhomework1.exception

import com.fasterxml.jackson.annotation.JsonInclude
import java.time.LocalDateTime

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ErrorResponse(
    val code: Int,
    val message: String,
    val timestamp: LocalDateTime,
    val exception: String,
    val path: String
)
