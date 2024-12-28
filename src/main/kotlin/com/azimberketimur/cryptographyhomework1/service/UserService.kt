package com.azimberketimur.cryptographyhomework1.service

import com.azimberketimur.cryptographyhomework1.exception.CredentialException
import com.azimberketimur.cryptographyhomework1.model.response.UserResponse
import com.azimberketimur.cryptographyhomework1.persistence.repository.UserRepository
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Service
import java.util.*
import kotlin.jvm.optionals.getOrNull

@Service
class UserService(
    private val userRepository: UserRepository,
) {
    fun getCurrentUser(): UserResponse {
        val userId = SecurityContextHolder.getContext().authentication.name as String
        val user = userRepository.findById(UUID.fromString(userId)).getOrNull()
            ?: throw CredentialException("Invalid credentials")
        return UserResponse(user.id.toString(), user.email)
    }
}