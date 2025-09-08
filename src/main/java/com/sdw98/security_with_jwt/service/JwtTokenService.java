package com.sdw98.security_with_jwt.service;

import com.sdw98.security_with_jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JwtTokenService {
    private final JwtEncoder jwtEncoder;

    @Value("${jwt.expiration:3600}")
    private long jwtExpiration;

    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();
        Instant expiry = now.plus(jwtExpiration, ChronoUnit.SECONDS);

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("jwt-demo-app")
                .subject(authentication.getName())
                .audience(List.of("jwt-demo-client"))
                .issuedAt(now)
                .expiresAt(expiry)
                .notBefore(now)
                .id(UUID.randomUUID().toString())
                .claim("username", authentication.getName())
                .claim("authorities", authorities)
                .claim("tokenType", "access")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public String generateToken(User user) {
        Instant now = Instant.now();
        Instant expiry = now.plus(jwtExpiration, ChronoUnit.SECONDS);

        String authorities = user.getAuthoritiesAsString();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("jwt-demo-app")
                .subject(user.getUsername())
                .audience(List.of("jwt-demo-client"))
                .issuedAt(now)
                .expiresAt(expiry)
                .notBefore(now)
                .id(UUID.randomUUID().toString())
                .claim("username", user.getUsername())
                .claim("authorities", authorities)
                .claim("roles", user.getRoles())
                .claim("displayName", user.getDisplayName() != null ? user.getDisplayName() : "")
                .claim("email", user.getEmail()  != null ? user.getEmail() : "")
                .claim("tokenType", "access")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public String generateTokenForUser(String username, List<String> roles) {
        User user = User.builder()
                .username(username)
                .authorities(roles
                        .stream()
                        .map(
                                role -> role
                                        .startsWith("ROLE_") ? role : "ROLE_" + role)
                        .collect(Collectors.toList()
                        )
                )
                .build();

        return generateToken(user);
    }

    public long getTokenExpiration() {
        return jwtExpiration;
    }
}