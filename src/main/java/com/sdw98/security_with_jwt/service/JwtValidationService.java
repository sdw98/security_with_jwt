package com.sdw98.security_with_jwt.service;

import com.sdw98.security_with_jwt.dto.JwtValidationResult;
import com.sdw98.security_with_jwt.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtValidationService {
    private final JwtDecoder jwtDecoder;

    public JwtValidationResult validationToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            log.info("JWT 토큰 검증 성공: subject={}, expires={}", jwt.getSubject(), jwt.getExpiresAt());

            return JwtValidationResult.success(jwt);
        } catch (Exception e) {
            log.error("JWT 토큰 검증 중 예외 발생:", e);
            return JwtValidationResult.failure("토큰 검증 중 오류 발생");
        }
    }

    public User extractUserInfo(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);

            String username = jwt.getClaimAsString("username");
            List<String> roles = jwt.getClaimAsStringList("roles");
            String authorities = jwt.getClaimAsString("authorities");
            String displayName = jwt.getClaimAsString("displayName");
            String email = jwt.getClaimAsString("email");

            List<String> authoritiesList = Collections.emptyList();
            if (authorities != null && !authorities.trim().isEmpty()) {
                authoritiesList = List.of(authorities.split(" "));
            } else if (roles != null) {
                authoritiesList = roles.stream()
                        .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role)
                        .toList();
            }

            return User.builder()
                    .username(username != null ? username : jwt.getSubject())
                    .authorities(authoritiesList)
                    .displayName(displayName)
                    .email(email)
                    .issuedAt(jwt.getIssuedAt())
                    .expiresAt(jwt.getExpiresAt())
                    .jwtId(jwt.getId())
                    .build();
        } catch(Exception e) {
            log.error("사용자 정보 추출 실패:", e);
            throw new RuntimeException("토큰에서 사용자 정보를 추출할 수 없습니다:", e);
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            assert jwt.getExpiresAt() != null;
            return jwt.getExpiresAt().isBefore(Instant.now());
        } catch(Exception e) {
            return true;
        }
    }

    public <T> T getClaimFromToken(String token, String claimName, Class<T> claimType) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getClaimAsString(claimName) != null ? jwt.getClaim(claimName) : null;
        } catch (Exception e) {
            log.error("클래임 추출 실패: {}", claimName, e);
            return null;
        }
    }
}