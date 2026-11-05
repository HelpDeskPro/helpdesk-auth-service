
package com.helpdeskpro.auth.service;


import com.helpdeskpro.auth.dto.*;
import com.helpdeskpro.auth.entity.User;
import com.helpdeskpro.auth.enums.Role;
import com.helpdeskpro.auth.exception.EmailAlreadyRegisteredException;
import com.helpdeskpro.auth.exception.InvalidCredentialsException;
import com.helpdeskpro.auth.repository.UserRepository;
import com.helpdeskpro.auth.security.JwtService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.helpdeskpro.auth.mapper.UserMapper;
import com.helpdeskpro.auth.service.EmailVerificationService;
import java.util.Locale;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final EmailVerificationService emailVerificationService;
    private final UserMapper userMapper;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            RefreshTokenService refreshTokenService, EmailVerificationService emailVerificationService, UserMapper userMapper
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.emailVerificationService = emailVerificationService;
        this.userMapper = userMapper;
    }

    // REGISTRATION

    @Transactional
    public UserResponse register(RegisterRequest request) {

        String normalizedEmail = request.email()
                .trim()
                .toLowerCase();

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new EmailAlreadyRegisteredException(
                    "Email is already registered"
            );
        }

        String encodedPassword =
                passwordEncoder.encode(request.password());

        User user = new User(
                request.firstName(),
                request.lastName(),
                normalizedEmail,
                encodedPassword,
                Role.EMPLOYEE
        );

        User savedUser = userRepository.save(user);

        // Generate a verification token and send the email.
        emailVerificationService.createAndSendVerificationToken(savedUser);

        // Convert the entity into a response DTO.
        return userMapper.toResponse(savedUser);
    }

    // LOGIN

    @Transactional
    public AuthResponse login(LoginRequest request) {

        String email = request.email()
                .trim()
                .toLowerCase(Locale.ROOT);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidCredentialsException(
                        "Invalid email or password"
                ));

        if (!passwordEncoder.matches(
                request.password(),
                user.getPassword()
        )) {
            throw new InvalidCredentialsException(
                    "Invalid email or password"
            );
        }

        if (!user.isEnabled()) {
            throw new InvalidCredentialsException(
                    "Invalid email or password"
            );
        }

        String accessToken = jwtService.generateToken(user);

        String refreshToken = refreshTokenService.createRefreshToken(user);

        return buildAuthResponse(user, accessToken, refreshToken);
    }

    // REFRESH TOKENS

    @Transactional
    public AuthResponse refresh(RefreshTokenRequest request) {

        RefreshTokenService.RotatedRefreshToken rotatedToken =
                refreshTokenService.rotateRefreshToken(
                        request.refreshToken()
                );

        User user = rotatedToken.user();

        String accessToken = jwtService.generateToken(user);

        return buildAuthResponse(
                user,
                accessToken,
                rotatedToken.rawToken()
        );
    }

    // LOGOUT

    @Transactional
    public void logout(RefreshTokenRequest request) {

        refreshTokenService.revokeRefreshToken(
                request.refreshToken()
        );
    }

    // BUILD AUTHENTICATION RESPONSE

    private AuthResponse buildAuthResponse(
            User user,
            String accessToken,
            String refreshToken
    ) {
        return new AuthResponse(
                accessToken,
                refreshToken,
                "Bearer",
                jwtService.getExpirationSeconds(),
                user.getId(),
                user.getEmail(),
                user.getRole().name()
        );
    }
}
