package com.azimberketimur.cryptographyhomework1.service

import com.azimberketimur.cryptographyhomework1.exception.UserNotFoundException
import com.azimberketimur.cryptographyhomework1.model.response.CheckEmailAndGetDiffieHellmanInfoResponse
import com.azimberketimur.cryptographyhomework1.model.response.EmailResponse
import com.azimberketimur.cryptographyhomework1.persistence.entity.Email
import com.azimberketimur.cryptographyhomework1.persistence.repository.EmailRepository
import com.azimberketimur.cryptographyhomework1.persistence.repository.UserRepository
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Service
import java.util.*
import kotlin.jvm.optionals.getOrNull

@Service
class EmailService(
    private val userRepository: UserRepository,
    private val emailRepository: EmailRepository
) {

    fun checkEmailAndGetDiffieHellmanInfo(
        email: String
    ): CheckEmailAndGetDiffieHellmanInfoResponse {
        val user = userRepository.findByEmail(email) ?: throw UserNotFoundException()

        val userId = SecurityContextHolder.getContext().authentication.name as String
        if (userId == user.id.toString()) {
            throw UserNotFoundException()
        }

        return CheckEmailAndGetDiffieHellmanInfoResponse(
            user.diffieHellmanExchangeKey
        )
    }

    fun sendEmailWithSignature(
        email: String,
        message: String,
        signature: String
    ) {
        val user = userRepository.findByEmail(email) ?: throw UserNotFoundException()

        val userId = SecurityContextHolder.getContext().authentication.name as String
        if (userId == user.id.toString()) {
            throw UserNotFoundException()
        }

        var email = Email(
            id = null,
            fromUser = UUID.fromString(userId),
            toUser = user.id!!,
            encryptedMessage = message,
            signature = signature
        )

        emailRepository.save(email)
    }

    fun getMyEmails(): List<EmailResponse> {
        val userId = SecurityContextHolder.getContext().authentication.name as String
        val user = userRepository.findById(UUID.fromString(userId)).getOrNull() ?: throw UserNotFoundException()

        val emails = emailRepository.findAllByToUser(UUID.fromString(userId))
        val emailResponses = mutableListOf<EmailResponse>()

        emails.forEach { email ->
            val fromUser = userRepository.findById(email.fromUser).get()
            emailResponses.add(
                EmailResponse(
                    id = email.id!!,
                    fromUser.email,
                    user.email,
                    email.encryptedMessage,
                    email.signature,
                    fromUser.diffieHellmanExchangeKey,
                    fromUser.publicKey
                )
            )
        }

        return emailResponses
    }
}