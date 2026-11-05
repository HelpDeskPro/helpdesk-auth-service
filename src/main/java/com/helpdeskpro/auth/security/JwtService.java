
package com.helpdeskpro.auth.security;

import com.helpdeskpro.auth.entity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class JwtService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final long expirationMinutes;

    public JwtService(
            JwtEncoder jwtEncoder,
            JwtDecoder jwtDecoder,
            @Value("${app.jwt.expiration-minutes}") long expirationMinutes
    ) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.expirationMinutes = expirationMinutes;
    }

    public String generateToken(User user) {

        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("helpdesk-pro")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expirationMinutes * 60))
                .subject(user.getEmail())
                .claim("userId", user.getId().toString())
                .claim("role", user.getRole().name())
                .build();

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();

        return jwtEncoder.encode(
                JwtEncoderParameters.from(header, claims)
        ).getTokenValue();
    }

    public String extractEmail(String token) {
        return decodeToken(token).getSubject();
    }

    public String extractRole(String token) {
        return decodeToken(token).getClaimAsString("role");
    }

    public boolean isTokenValid(String token) {
        try {
            Jwt jwt = decodeToken(token);
            return jwt.getExpiresAt() != null
                    && jwt.getExpiresAt().isAfter(Instant.now());
        } catch (JwtException | IllegalArgumentException exception) {
            return false;
        }
    }

    private Jwt decodeToken(String token) {
        return jwtDecoder.decode(token);
    }
    public long getExpirationSeconds() {
        return expirationMinutes * 60;
    }
}
