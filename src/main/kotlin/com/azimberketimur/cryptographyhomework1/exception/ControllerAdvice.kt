package com.azimberketimur.cryptographyhomework1.exception

import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import java.time.LocalDateTime

@ControllerAdvice
class ControllerAdvice {

    @ExceptionHandler(BaseException::class)
    fun handleGeneralException(ex: BaseException, req: HttpServletRequest): ResponseEntity<ErrorResponse> {
        return ResponseEntity.status(ex.status).body(getErrorResponse(ex, req))
    }

    @ExceptionHandler(Exception::class)
    fun handleException(ex: Exception, req: HttpServletRequest): ResponseEntity<ErrorResponse> {
        val errorResponse = ErrorResponse(
            HttpStatus.INTERNAL_SERVER_ERROR.value(),
            GENERAL_EXCEPTION_MESSAGE,
            LocalDateTime.now(),
            ex.javaClass.simpleName,
            req.requestURI
        )

        return ResponseEntity.status(500).body(errorResponse)
    }

    private fun getErrorResponse(ex: BaseException, httpRequest: HttpServletRequest) =
        ErrorResponse(
            ex.code,
            ex.message ?: GENERAL_EXCEPTION_MESSAGE,
            LocalDateTime.now(),
            ex.javaClass.simpleName,
            httpRequest.requestURI
        )


    companion object {
        const val GENERAL_EXCEPTION_MESSAGE = "An unknown error occurred"
    }
}