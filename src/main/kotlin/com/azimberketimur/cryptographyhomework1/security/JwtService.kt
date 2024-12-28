package com.azimberketimur.cryptographyhomework1.security

import com.azimberketimur.cryptographyhomework1.configuration.SecurityProperties
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.SecretKey

@Component
class JwtService(
    private val securityProperties: SecurityProperties
) {

    fun generateToken(userId: String) = buildToken(userId, emptyMap())

    fun generateToken(userId: String, authorities: List<String>): String {
        return buildToken(userId, mapOf(ROLES_CLAIM_KEY to authorities))
    }

    private fun buildToken(userId: String, claims: Map<String, Any>): String {
        return Jwts.builder()
            .claims(claims)
            .subject(userId)
            .issuedAt(Date(System.currentTimeMillis()))
            .expiration(Date(System.currentTimeMillis() + securityProperties.expirationTimeMs))
            .signWith(getSigningKey(), Jwts.SIG.HS256)
            .compact()
    }

    private fun getSigningKey(): SecretKey {
        return Keys.hmacShaKeyFor(securityProperties.secretKey.toByteArray())
    }

    fun getUserIdFromToken(token: String): String {
        return getClaimFromToken(token, Claims::getSubject)
    }

    fun getExpirationDateFromToken(token: String): Date {
        return getClaimFromToken(token, Claims::getExpiration)
    }

    fun validateToken(token: String): Boolean {
        return !isTokenExpired(token)
    }

    private fun isTokenExpired(token: String): Boolean {
        val expiration = getExpirationDateFromToken(token)
        return expiration.before(Date())
    }

    fun <T> getClaimFromToken(token: String, claimsResolver: (Claims) -> T): T {
        val claims = getAllClaimsFromToken(token)
        return claimsResolver(claims)
    }

    private fun getAllClaimsFromToken(token: String): Claims {
        return Jwts.parser()
            .verifyWith(getSigningKey())
            .build()
            .parseSignedClaims(token)
            .payload
    }

    private companion object {
        const val ROLES_CLAIM_KEY = "roles"
    }
}