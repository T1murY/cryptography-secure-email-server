package com.azimberketimur.cryptographyhomework1.persistence.repository

import com.azimberketimur.cryptographyhomework1.persistence.entity.User
import org.springframework.data.jpa.repository.JpaRepository
import java.util.*

interface UserRepository : JpaRepository<User, UUID> {

    fun findByEmail(email: String): User?
    fun existsByEmail(email: String): Boolean
}