package com.sdw98.security_with_jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.oauth2.jwt.Jwt;

@Getter
@AllArgsConstructor
public class JwtValidationResult {
    private final boolean valid;
    private final String errorMessage;
    private final Jwt jwt;

    public static JwtValidationResult success(Jwt jwt) {
        return new JwtValidationResult(true, null, jwt);
    }

    public static JwtValidationResult failure(String errorMessage) {
        return new JwtValidationResult(false, errorMessage, null);
    }
}