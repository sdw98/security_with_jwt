package com.sdw98.security_with_jwt.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
public class AuthResponse {
    private boolean success;
    private String accessToken;
    private String tokenType;
    private long expiresIn;
    private String username;
    private List<String> roles;
    private String errorMessage;
    private Instant timestamp;

    public AuthResponse() {
        this.timestamp = Instant.now();
    }

    public AuthResponse(String accessToken, String tokenType, long expiresIn, String username, List<String> roles) {
        this();
        this.success = true;
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
        this.username = username;
        this.roles = roles;
    }

    public static AuthResponse error(String message) {
        AuthResponse response = new AuthResponse();
        response.success = false;
        response.errorMessage = message;
        return response;
    }
}