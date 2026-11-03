package com.helpdeskpro.auth.service;

import com.helpdeskpro.auth.config.PasswordConfig;
import com.helpdeskpro.auth.dto.RegisterRequest;
import com.helpdeskpro.auth.dto.UserResponse;
import com.helpdeskpro.auth.entity.User;
import com.helpdeskpro.auth.enums.Role;
import com.helpdeskpro.auth.exception.EmailAlreadyRegisteredException;
import com.helpdeskpro.auth.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.hibernate.boot.model.naming.IllegalIdentifierException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Locale;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, PasswordConfig passwordConfig, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public UserResponse register(RegisterRequest request)
    {
        String email = request.email()
                .trim()
                .toLowerCase(Locale.ROOT);
        if(userRepository.existsByEmail(email))
        {
            throw new EmailAlreadyRegisteredException(
                    "An account with this email already exists"
            );
        }

        String hashedPassword = passwordEncoder.encode(
                request.password()
        );

        User user = new User(
                request.firstName().trim(),
                request.lastName().trim(),
                email,
                hashedPassword,
                Role.EMPLOYEE
        );

        User savedUser = userRepository.save(user);

        return new UserResponse(
                savedUser.getId(),
                savedUser.getFirstName(),
                savedUser.getLastName(),
                savedUser.getEmail(),
                savedUser.getRole(),
                savedUser.isEnabled(),
                savedUser.getCreatedAt()
        );
    }
}
