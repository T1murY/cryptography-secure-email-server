package com.azimberketimur.cryptographyhomework1.persistence.repository

import com.azimberketimur.cryptographyhomework1.persistence.entity.Email
import org.springframework.data.jpa.repository.JpaRepository
import java.util.*

interface EmailRepository : JpaRepository<Email, UUID> {
    fun findAllByToUser(toUser: UUID): List<Email>
}