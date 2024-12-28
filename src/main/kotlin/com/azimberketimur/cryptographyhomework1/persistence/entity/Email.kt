package com.azimberketimur.cryptographyhomework1.persistence.entity

import jakarta.persistence.*
import java.util.*

@Entity
@Table(name = "emails")
data class Email(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    val id: UUID?,

    @Column(nullable = false)
    val fromUser: UUID,

    @Column(nullable = false)
    val toUser: UUID,

    @Column(nullable = false)
    val encryptedMessage: String,

    @Column(nullable = false)
    val signature: String
)