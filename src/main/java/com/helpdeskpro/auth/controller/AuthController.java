
package com.helpdeskpro.auth.controller;


import com.helpdeskpro.auth.dto.*;
import com.helpdeskpro.auth.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // REGISTER

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(
            @Valid @RequestBody RegisterRequest request
    ) {
        UserResponse response = authService.register(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }

    // LOGIN

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request
    ) {
        AuthResponse response = authService.login(request);

        return ResponseEntity.ok(response);
    }

    // REFRESH TOKEN

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        AuthResponse response = authService.refresh(request);

        return ResponseEntity.ok(response);
    }

    // LOGOUT

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        authService.logout(request);

        return ResponseEntity.noContent().build();
    }

    // CURRENT USER

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(
            @AuthenticationPrincipal Jwt jwt
    ) {
        Map<String, Object> userDetails = Map.of(
                "userId", jwt.getSubject(),
                "email", jwt.getClaimAsString("email"),
                "role", jwt.getClaimAsString("role")
        );

        return ResponseEntity.ok(userDetails);
    }
}
