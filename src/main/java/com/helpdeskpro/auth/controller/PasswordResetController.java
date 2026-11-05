
package com.helpdeskpro.auth.controller;


import com.helpdeskpro.auth.dto.ForgotPasswordRequest;
import com.helpdeskpro.auth.service.PasswordResetService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class PasswordResetController {

    private final PasswordResetService passwordResetService;

    public PasswordResetController(
            PasswordResetService passwordResetService
    ) {
        this.passwordResetService = passwordResetService;
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request
    ) {

        passwordResetService.requestPasswordReset(request.email());

        return ResponseEntity.ok(
                "If an eligible account exists with that email, " +
                        "a password reset link will be sent."
        );
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(
            @Valid @RequestBody com.helpdeskpro.auth.dto.request.ResetPasswordRequest request
    ) {

        passwordResetService.resetPassword(
                request.token(),
                request.newPassword()
        );

        return ResponseEntity.ok(
                "Your password has been successfully reset. You can now log in."
        );
    }
}
