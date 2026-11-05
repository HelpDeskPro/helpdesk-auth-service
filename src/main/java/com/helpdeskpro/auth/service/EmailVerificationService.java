
package com.helpdeskpro.auth.service;

import com.helpdeskpro.auth.entity.EmailVerificationToken;
import com.helpdeskpro.auth.entity.User;
import com.helpdeskpro.auth.exception.InvalidEmailVerificationTokenException;
import com.helpdeskpro.auth.repository.EmailVerificationTokenRepository;
import com.helpdeskpro.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
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
public class EmailVerificationService {

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final long expirationMinutes;

    private final SecureRandom secureRandom = new SecureRandom();

    public EmailVerificationService(
            EmailVerificationTokenRepository tokenRepository,
            UserRepository userRepository,
            EmailService emailService,
            @Value("${app.verification.expiration-minutes}") long expirationMinutes
    ) {
        this.tokenRepository = tokenRepository;
        this.userRepository = userRepository;
        this.emailService = emailService;
        this.expirationMinutes = expirationMinutes;
    }

    @Transactional
    public void createAndSendVerificationToken(User user) {

        String rawToken = generateSecureToken();
        String tokenHash = hashToken(rawToken);

        LocalDateTime expiresAt =
                LocalDateTime.now().plusMinutes(expirationMinutes);

        EmailVerificationToken verificationToken =
                new EmailVerificationToken(user, tokenHash, expiresAt);

        tokenRepository.save(verificationToken);

        emailService.sendVerificationEmail(user.getEmail(), rawToken);
    }

    @Transactional
    public void verifyEmail(String rawToken) {

        String tokenHash = hashToken(rawToken);

        EmailVerificationToken verificationToken =
                tokenRepository.findByTokenHashForUpdate(tokenHash)
                        .orElseThrow(InvalidEmailVerificationTokenException::new);

        if (verificationToken.isUsed() || verificationToken.isExpired()) {
            throw new InvalidEmailVerificationTokenException();
        }

        User user = verificationToken.getUser();

        user.setEnabled(true);
        verificationToken.markAsUsed();

        userRepository.save(user);
        tokenRepository.save(verificationToken);
    }

    @Transactional
    public void resendVerificationEmail(String email) {

        String normalizedEmail = email.trim().toLowerCase();

        User user = userRepository.findByEmail(normalizedEmail)
                .orElse(null);

        if (user == null || user.isEnabled()) {
            return;
        }

        var existingTokens =
                tokenRepository.findAllByUserAndUsedFalse(user);

        for (EmailVerificationToken token : existingTokens) {
            token.markAsUsed();
        }

        tokenRepository.saveAll(existingTokens);

        createAndSendVerificationToken(user);
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
