package com.sdw98.security_with_jwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class ProtectedController {
    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> getProfile(Authentication authentication) {
        Map<String, Object> profile = new HashMap<>();

        profile.put("username", authentication.getName());
        profile.put("authorities", authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        profile.put("authenticated", authentication.isAuthenticated());
        profile.put("timestamp", Instant.now());

        if (authentication instanceof JwtAuthenticationToken jwtAuth) {

            assert jwtAuth.getToken().getIssuedAt() != null;
            assert jwtAuth.getToken().getExpiresAt() != null;

            profile.put("tokenInfo", Map.of(
//                    "issuer", jwtAuth.getToken().getIssuer(),
                    "subject", jwtAuth.getToken().getSubject(),
                    "issuedAt", jwtAuth.getToken().getIssuedAt(),
                    "expiresAt", jwtAuth.getToken().getExpiresAt(),
                    "tokenId", jwtAuth.getToken().getId()
            ));
        }

        return ResponseEntity.ok(profile);
    }

    @GetMapping("/user/data")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Map<String, Object>> getUserData(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "사용자 전용 데이터",
                "username", authentication.getName(),
                "accessLevel", "USER",
                "data", List.of("user-item-1", "user-item-2", "user-item-3"),
                "timestamp", Instant.now()
        ));
    }

    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Map<String, Object>>> getAllUsers() {
        List<Map<String, Object>> users = List.of(
                Map.of("username", "user", "roles", List.of("ROLE_USER"), "active", true),
                Map.of("username", "admin", "roles", List.of("ROLE_USER", "ROLE_ADMIN"), "active", true),
                Map.of("username", "manager", "roles", List.of("ROLE_USER", "ROLE_MANAGER"), "active", true)
        );

        return ResponseEntity.ok(users);
    }

    @GetMapping("/user/{username}/data")
    @PreAuthorize("#username == authentication.name or hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getUserSpecificData(
            @PathVariable String username,
            Authentication authentication) {

        return ResponseEntity.ok(Map.of(
                "targetUser", username,
                "requestedBy", authentication.getName(),
                "personalData", Map.of(
                        "settings", Map.of("theme", "dark", "language", "ko"),
                        "preferences", List.of("notification", "privacy")
                ),
                "accessReason", username.equals(authentication.getName()) ? "본인" : "관리자 권한",
                "timestamp", Instant.now()
        ));
    }

    @PostMapping("/posts")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Map<String, Object>> createPost(
            @RequestBody Map<String, Object> postData,
            Authentication authentication) {

        Map<String, Object> result = new HashMap<>(postData);
        result.put("id", UUID.randomUUID().toString());
        result.put("author", authentication.getName());
        result.put("createdAt", Instant.now());
        result.put("status", "published");

        return ResponseEntity.ok(result);
    }

    @DeleteMapping("/posts/{postId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> deletePost(
            @PathVariable String postId,
            Authentication authentication) {

        return ResponseEntity.ok(Map.of(
                "postId", postId,
                "deletedBy", authentication.getName(),
                "deletedAt", Instant.now(),
                "status", "deleted"
        ));
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "service", "JWT Token Demo",
                "timestamp", Instant.now()
        ));
    }
}