package com.azimberketimur.cryptographyhomework1.security

import com.azimberketimur.cryptographyhomework1.exception.JwtTokenExpiredException
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.JwtException
import io.jsonwebtoken.security.SignatureException
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class AuthTokenFilter(
    private val jwtService: JwtService,
    private val userDetailsService: UserDetailsService
) : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val header = request.getHeader("Authorization")

        header?.takeIf { it.startsWith(TOKEN_PREFIX) }?.let {
            val token = it.substring(TOKEN_PREFIX.length)

            try {
                val username = jwtService.getUserIdFromToken(token)

                if (SecurityContextHolder.getContext().authentication == null) {
                    val userDetails = userDetailsService.loadUserByUsername(username)
                    if (jwtService.validateToken(token)) {
                        val authentication =
                            UsernamePasswordAuthenticationToken(userDetails, null, userDetails.authorities)
                        SecurityContextHolder.getContext().authentication = authentication
                    }
                }
            } catch (e: SignatureException) {
                throw JwtTokenExpiredException()
            } catch (e: ExpiredJwtException) {
                throw JwtTokenExpiredException()
            } catch (e: JwtException) {
                throw JwtTokenExpiredException()
            } catch (e: Exception) {
                throw e
            }
        }

        filterChain.doFilter(request, response)
    }

    companion object {
        const val TOKEN_PREFIX = "Bearer "
    }
}