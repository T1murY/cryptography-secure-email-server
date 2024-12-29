package com.azimberketimur.cryptographyhomework1.service

import com.azimberketimur.cryptographyhomework1.configuration.DiffieHellmanProperties
import com.azimberketimur.cryptographyhomework1.exception.CredentialException
import com.azimberketimur.cryptographyhomework1.model.request.LoginRequest
import com.azimberketimur.cryptographyhomework1.model.request.RegisterRequest
import com.azimberketimur.cryptographyhomework1.model.response.DiffieHellmanParamsResponse
import com.azimberketimur.cryptographyhomework1.model.response.LoginResponse
import com.azimberketimur.cryptographyhomework1.model.response.RegisterResponse
import com.azimberketimur.cryptographyhomework1.persistence.entity.User
import com.azimberketimur.cryptographyhomework1.persistence.repository.UserRepository
import com.azimberketimur.cryptographyhomework1.security.JwtService
import com.azimberketimur.cryptographyhomework1.validator.AuthValidator
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class AuthService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtService: JwtService,
    private val authValidator: AuthValidator,
    private val diffieHellmanProperties: DiffieHellmanProperties
) {

    fun diffieHellmanParams(): DiffieHellmanParamsResponse {
        return DiffieHellmanParamsResponse(
            generator = diffieHellmanProperties.generator,
            prime = diffieHellmanProperties.prime
        )
    }

    fun register(request: RegisterRequest): RegisterResponse {
        authValidator.validateUser(request)

        val cryptPassword = passwordEncoder.encode(request.password)
        val user = userRepository.save(
            User(
                id = null,
                email = request.email,
                password = cryptPassword,
                diffieHellmanExchangeKey = request.diffieHellmanExchangeKey,
                rsaPublicKey = request.rsaPublicKey
            )
        )

        return RegisterResponse(id = user.id!!, email = user.email)
    }

    fun login(request: LoginRequest): LoginResponse {
        val user = checkAndGetUser(request.email, request.password)
        val token = jwtService.generateToken(user.id.toString())

        return LoginResponse(user.id!!, user.email, token)
    }

    private fun checkAndGetUser(email: String, password: String) =
        userRepository.findByEmail(email)?.also { checkPassword(password, it.password) }
            ?: throw CredentialException("Invalid credentials")

    private fun checkPassword(password: String, userPassword: String) {
        if (!passwordEncoder.matches(password, userPassword)) {
            throw CredentialException("Invalid credentials")
        }
    }
}