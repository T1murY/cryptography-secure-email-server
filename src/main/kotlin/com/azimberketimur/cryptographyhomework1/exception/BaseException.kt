package com.azimberketimur.cryptographyhomework1.exception

import org.springframework.http.HttpStatus
import java.time.LocalDateTime

open class BaseException : RuntimeException {
    var code: Int
    var status: HttpStatus
    var args: Array<Any> = emptyArray()
    var timestamp: LocalDateTime? = null
    var exception: String? = null
    var path: String? = null

    constructor(status: HttpStatus, message: String) : super(message) {
        this.status = status
        this.code = status.value()
    }

    constructor(status: HttpStatus, message: String, args: Array<Any>) : super(message) {
        this.status = status
        this.code = status.value()
        this.args = args
    }

    constructor(errorResponse: ErrorResponse) : super(errorResponse.message) {
        this.status = HttpStatus.valueOf(errorResponse.code)
        this.code = errorResponse.code
        this.timestamp = errorResponse.timestamp
        this.exception = errorResponse.exception
        this.path = errorResponse.path
    }
}