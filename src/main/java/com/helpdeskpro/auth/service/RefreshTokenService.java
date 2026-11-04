
package com.helpdeskpro.auth.service;

import com.helpdeskpro.auth.entity.RefreshToken;
import com.helpdeskpro.auth.entity.User;
import com.helpdeskpro.auth.exception.InvalidRefreshTokenException;
import com.helpdeskpro.auth.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final long expirationDays;

    private final SecureRandom secureRandom = new SecureRandom();

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            @Value("${security.jwt.refresh-expiration-days}") long expirationDays
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.expirationDays = expirationDays;
    }

    // CREATE A NEW REFRESH TOKEN

    @Transactional
    public String createRefreshToken(User user) {

        String rawToken = generateRandomToken();

        String tokenHash = hashToken(rawToken);

        RefreshToken refreshToken = new RefreshToken(
                user,
                tokenHash,
                LocalDateTime.now().plusDays(expirationDays)
        );

        refreshTokenRepository.save(refreshToken);

        return rawToken;
    }

    // ROTATE AN EXISTING REFRESH TOKEN

    @Transactional
    public RotatedRefreshToken rotateRefreshToken(String rawToken) {

        String tokenHash = hashToken(rawToken);

        RefreshToken existingToken = refreshTokenRepository
                .findByTokenHashForUpdate(tokenHash)
                .orElseThrow(() -> new InvalidRefreshTokenException(
                        "Invalid refresh token"
                ));

        if (existingToken.isRevoked() || existingToken.isExpired()) {
            throw new InvalidRefreshTokenException(
                    "Refresh token is expired or revoked"
            );
        }

        User user = existingToken.getUser();

        if (!user.isEnabled()) {
            existingToken.revoke();

            throw new InvalidRefreshTokenException(
                    "User account is disabled"
            );
        }

        // Revoke the old token
        existingToken.revoke();

        // Generate a replacement token
        String newRawToken = createRefreshToken(user);

        return new RotatedRefreshToken(user, newRawToken);
    }

    // LOGOUT / REVOKE REFRESH TOKEN

    @Transactional
    public void revokeRefreshToken(String rawToken) {

        String tokenHash = hashToken(rawToken);

        RefreshToken refreshToken = refreshTokenRepository
                .findByTokenHashForUpdate(tokenHash)
                .orElseThrow(() -> new InvalidRefreshTokenException(
                        "Invalid refresh token"
                ));

        if (refreshToken.isRevoked() || refreshToken.isExpired()) {
            throw new InvalidRefreshTokenException(
                    "Refresh token is already expired or revoked"
            );
        }

        refreshToken.revoke();
    }

    // GENERATE A RANDOM TOKEN

    private String generateRandomToken() {

        byte[] randomBytes = new byte[64];

        secureRandom.nextBytes(randomBytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(randomBytes);
    }

    // HASH THE TOKEN USING SHA-256

    private String hashToken(String rawToken) {

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] hash = digest.digest(
                    rawToken.getBytes(StandardCharsets.UTF_8)
            );

            return java.util.HexFormat.of().formatHex(hash);

        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(
                    "SHA-256 algorithm is not available",
                    exception
            );
        }
    }

    public record RotatedRefreshToken(
            User user,
            String rawToken
    ) {}
}
