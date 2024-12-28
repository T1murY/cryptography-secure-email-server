package com.azimberketimur.cryptographyhomework1.service

import com.azimberketimur.cryptographyhomework1.exception.CredentialException
import com.azimberketimur.cryptographyhomework1.persistence.repository.UserRepository
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service
import java.util.*
import kotlin.jvm.optionals.getOrNull

@Service
class UserDetailsServiceImpl(
    private val userRepository: UserRepository
) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        val user = userRepository.findById(UUID.fromString(username)).getOrNull()
            ?: throw CredentialException("Invalid credentials")

        return org.springframework.security.core.userdetails.User(
            user.id.toString(),
            user.password,
            listOf(SimpleGrantedAuthority("USER"))
        )
    }
}