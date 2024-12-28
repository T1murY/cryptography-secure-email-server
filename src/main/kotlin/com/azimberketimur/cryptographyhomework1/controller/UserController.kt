package com.azimberketimur.cryptographyhomework1.controller

import com.azimberketimur.cryptographyhomework1.service.UserService
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/users")
class UserController(
    private val userService: UserService
) {

    @GetMapping("/validate")
    fun validate() = Unit

    @GetMapping("/current-user")
    fun getCurrentUser() = userService.getCurrentUser()
}