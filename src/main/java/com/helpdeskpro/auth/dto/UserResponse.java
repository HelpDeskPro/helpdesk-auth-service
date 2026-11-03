package com.helpdeskpro.auth.dto;

import com.helpdeskpro.auth.enums.Role;

import java.time.LocalDateTime;
import java.util.UUID;

public record UserResponse(

        UUID id,
        String firstName,
        String lastName,
        String email,
        Role role,
        boolean enabled,
        LocalDateTime createdAt

) {
}