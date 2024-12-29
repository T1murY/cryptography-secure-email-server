package com.azimberketimur.cryptographyhomework1.persistence.entity

import jakarta.persistence.*
import java.util.*

@Entity
@Table(name = "users")
data class User(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    val id: UUID?,

    @Column(nullable = false, unique = true)
    val email: String,

    @Column(nullable = false)
    val password: String,

    @Column(nullable = false, length = 2048)
    val diffieHellmanExchangeKey: String,

    @Column(nullable = false, length = 2048)
    val rsaPublicKey: String
)