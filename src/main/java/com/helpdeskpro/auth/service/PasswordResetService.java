
package com.helpdeskpro.auth.service;

import com.helpdeskpro.auth.entity.PasswordResetToken;
import com.helpdeskpro.auth.entity.User;
import com.helpdeskpro.auth.exception.InvalidPasswordResetTokenException;
import com.helpdeskpro.auth.repository.PasswordResetTokenRepository;
import com.helpdeskpro.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;

@Service
public class PasswordResetService {

    private final PasswordResetTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final long expirationMinutes;

    private final SecureRandom secureRandom = new SecureRandom();

    public PasswordResetService(
            PasswordResetTokenRepository tokenRepository,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            EmailService emailService,
            @Value("${app.password-reset.expiration-minutes}") long expirationMinutes
    ) {
        this.tokenRepository = tokenRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.expirationMinutes = expirationMinutes;
    }

    @Transactional
    public void requestPasswordReset(String email) {

        String normalizedEmail = email.trim().toLowerCase();

        User user = userRepository.findByEmail(normalizedEmail)
                .orElse(null);

        if (user == null || !user.isEnabled()) {
            return;
        }

        // Invalidate previous unused tokens.
        var existingTokens =
                tokenRepository.findAllByUserAndUsedFalse(user);

        for (PasswordResetToken token : existingTokens) {
            token.markAsUsed();
        }

        tokenRepository.saveAll(existingTokens);

        // Generate a new secure token.
        String rawToken = generateSecureToken();
        String tokenHash = hashToken(rawToken);

        LocalDateTime expiresAt =
                LocalDateTime.now().plusMinutes(expirationMinutes);

        PasswordResetToken resetToken =
                new PasswordResetToken(user, tokenHash, expiresAt);

        tokenRepository.save(resetToken);

        // Send the raw token by email.
        emailService.sendPasswordResetEmail(
                user.getEmail(),
                rawToken
        );
    }

    @Transactional
    public void resetPassword(String rawToken, String newPassword) {

        String tokenHash = hashToken(rawToken);

        PasswordResetToken resetToken =
                tokenRepository.findByTokenHashForUpdate(tokenHash)
                        .orElseThrow(InvalidPasswordResetTokenException::new);

        if (resetToken.isUsed() || resetToken.isExpired()) {
            throw new InvalidPasswordResetTokenException();
        }

        User user = resetToken.getUser();

        String encodedPassword = passwordEncoder.encode(newPassword);

        user.changePassword(encodedPassword);
        resetToken.markAsUsed();

        userRepository.save(user);
        tokenRepository.save(resetToken);
    }

    private String generateSecureToken() {

        byte[] randomBytes = new byte[32];

        secureRandom.nextBytes(randomBytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(randomBytes);
    }

    private String hashToken(String rawToken) {

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] hashedBytes = digest.digest(
                    rawToken.getBytes(StandardCharsets.UTF_8)
            );

            return HexFormat.of().formatHex(hashedBytes);

        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(
                    "SHA-256 algorithm is not available",
                    exception
            );
        }
    }
}
