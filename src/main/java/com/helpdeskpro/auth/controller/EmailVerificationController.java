
package com.helpdeskpro.auth.controller;

import com.helpdeskpro.auth.dto.ResendVerificationRequest;
import com.helpdeskpro.auth.service.EmailVerificationService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class EmailVerificationController {

    private final EmailVerificationService emailVerificationService;

    public EmailVerificationController(
            EmailVerificationService emailVerificationService
    ) {
        this.emailVerificationService = emailVerificationService;
    }

    @GetMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(
            @RequestParam String token
    ) {
        emailVerificationService.verifyEmail(token);

        return ResponseEntity.ok(
                "Your email has been successfully verified. You can now log in."
        );
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<String> resendVerificationEmail(
            @Valid @RequestBody ResendVerificationRequest request
    ) {

        emailVerificationService.resendVerificationEmail(
                request.email()
        );

        return ResponseEntity.ok(
                "If an unverified account exists with that email, " +
                        "a verification email will be sent."
        );
    }
}
