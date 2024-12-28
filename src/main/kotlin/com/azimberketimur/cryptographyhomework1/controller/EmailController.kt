package com.azimberketimur.cryptographyhomework1.controller

import com.azimberketimur.cryptographyhomework1.service.EmailService
import org.springframework.web.bind.annotation.*


@RestController
@RequestMapping("/email")
class EmailController(
    private val emailService: EmailService
) {

    @GetMapping("/checkEmailAndGetDiffieHellmanInfo")
    fun checkEmailAndGetDiffieHellmanInfo(
        @RequestParam email: String
    ) = emailService.checkEmailAndGetDiffieHellmanInfo(email)

    @PostMapping("/sendEmailWithSignature")
    fun sendEmailWithSignature(
        @RequestParam email: String,
        @RequestParam message: String,
        @RequestParam signature: String
    ) = emailService.sendEmailWithSignature(email, message, signature)

    @GetMapping("/getMyEmails")
    fun getMyEmails() = emailService.getMyEmails()
}