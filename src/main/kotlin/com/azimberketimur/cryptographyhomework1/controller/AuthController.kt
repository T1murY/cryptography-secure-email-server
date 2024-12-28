package com.azimberketimur.cryptographyhomework1.controller

import com.azimberketimur.cryptographyhomework1.model.request.LoginRequest
import com.azimberketimur.cryptographyhomework1.model.request.RegisterRequest
import com.azimberketimur.cryptographyhomework1.service.AuthService
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/auth")
class AuthController(
    private val authService: AuthService
) {

    @GetMapping("/diffie-hellman-info")
    fun generatorInfo() = authService.diffieHellmanInfo()

    @PostMapping("/register")
    fun register(
        @RequestBody registerRequest: RegisterRequest
    ) = authService.register(registerRequest)

    @PostMapping("/login")
    fun login(
        @RequestBody loginRequest: LoginRequest
    ) = authService.login(loginRequest)
}