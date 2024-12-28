package com.azimberketimur.cryptographyhomework1.exception

import org.springframework.http.HttpStatus

class CredentialException(message: String) : BaseException(HttpStatus.UNAUTHORIZED, message)

class JwtTokenExpiredException : BaseException(HttpStatus.UNAUTHORIZED, "JWT Token Expired")

class UserAlreadyExistsException : BaseException(HttpStatus.CONFLICT, "User already exists")

class UserNotFoundException : BaseException(HttpStatus.NOT_FOUND, "User not found")