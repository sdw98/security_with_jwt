package com.sdw98.security_with_jwt.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {
    private String username;
    private String password;
    private List<String> authorities;
    private String displayName;
    private String email;

    private Instant issuedAt;
    private Instant expiresAt;
    private String jwtId;

    public List<String> getRoles() {
        return authorities != null ? authorities : List.of();
    }

    public String getAuthoritiesAsString() {
        return authorities != null ? String.join(" ", authorities) : "";
    }

    public boolean hasRole(String role) {
        return authorities != null && authorities.contains(role);
    }

    public boolean isAdmin() {
        return hasRole("ROLE_ADMIN");
    }

    public static User fromJwt(String username, List<String> authorities, Instant issuedAt, Instant expiresAt, String jwtId) {
        return User.builder()
                .username(username)
                .authorities(authorities)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .jwtId(jwtId)
                .build();
    }

    public static User createAccount(String username, String encodedPassword, List<String> authorities, String displayName, String email) {
        return User.builder()
                .username(username)
                .password(encodedPassword)
                .authorities(authorities)
                .displayName(displayName)
                .email(email)
                .build();
    }
}