package com.azimberketimur.cryptographyhomework1.validator

import com.azimberketimur.cryptographyhomework1.exception.UserAlreadyExistsException
import com.azimberketimur.cryptographyhomework1.model.request.RegisterRequest
import com.azimberketimur.cryptographyhomework1.persistence.repository.UserRepository
import org.springframework.stereotype.Component

@Component
class AuthValidator(
    private val userRepository: UserRepository
) {
    fun validateUser(registerRequest: RegisterRequest) {
        if (userRepository.existsByEmail(registerRequest.email)) {
            throw UserAlreadyExistsException()
        }
    }
}