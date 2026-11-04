package com.helpdeskpro.auth.controller;

import com.helpdeskpro.auth.dto.AuthResponse;
import com.helpdeskpro.auth.dto.LoginRequest;
import com.helpdeskpro.auth.dto.RegisterRequest;
import com.helpdeskpro.auth.dto.UserResponse;
import com.helpdeskpro.auth.service.AuthService;
import jakarta.validation.Valid;
import org.apache.coyote.Response;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(
            @Valid @RequestBody RegisterRequest request
    ) {

        UserResponse response = authService.register(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request
            ){
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }
}