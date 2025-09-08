package com.sdw98.security_with_jwt.controller;

import com.sdw98.security_with_jwt.dto.AuthResponse;
import com.sdw98.security_with_jwt.dto.JwtValidationResult;
import com.sdw98.security_with_jwt.dto.LoginRequest;
import com.sdw98.security_with_jwt.model.User;
import com.sdw98.security_with_jwt.service.JwtTokenService;
import com.sdw98.security_with_jwt.service.JwtValidationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenService jwtTokenService;
    private final JwtValidationService jwtValidationService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );

            String token = jwtTokenService.generateToken(authentication);

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            AuthResponse response = new AuthResponse(
                    token,
                    "Bearer",
                    jwtTokenService.getTokenExpiration(),
                    userDetails.getUsername(),
                    roles
            );

            return ResponseEntity.ok(response);
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(AuthResponse.error("사용자명 또는 비밀먼호가 올바르지 않습니다"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(AuthResponse.error("로그인 처리 중 오류가 발생했습니다"));
        }
    }

    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication authentication) {
        Map<String, Object> userInfo = Map.of(
                "username", authentication.getName(),
                "authorities", authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()),
                "authenticated", authentication.isAuthenticated(),
                "timestamp", Instant.now()
        );

        return ResponseEntity.ok(userInfo);
    }

    @PostMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(@RequestBody Map<String, String> request) {
        String token = request.get("token");

        if (token == null || token.trim().isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "valid", false,
                            "error", "토큰이 제공되지 않았습니다",
                            "timestamp", Instant.now()
                    ));
        }

        JwtValidationResult result = jwtValidationService.validationToken(token);

        if (result.isValid()) {
            User user = jwtValidationService.extractUserInfo(token);

            return ResponseEntity.ok(
                    Map.of(
                            "valid", true,
                            "username", user.getUsername(),
                            "roles", user.getRoles(),
                            "authorities", user.getAuthorities(),
                            "issuedAt", user.getIssuedAt(),
                            "expiresAt", user.getExpiresAt(),
                            "jwtId", user.getJwtId(),
                            "timestamp", Instant.now()
                    )
            );
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "valid", false,
                            "error", result.getErrorMessage(),
                            "timestamp", Instant.now()
                    ));
        }
    }

    @PostMapping("/generate-test-token")
    public ResponseEntity<Map<String, Object>> generateTestToken(@RequestBody Map<String, Object> request) {
        String username = (String) request.get("username");
        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>)  request.get("roles");

        if (username == null || username.trim().isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "사용자명이 필요합니다"));
        }

        if (roles == null || roles.isEmpty()) {
            roles = List.of("USER");
        }

        String token = jwtTokenService.generateTokenForUser(username, roles);

        return ResponseEntity.ok(Map.of(
                "token", token,
                "tokenType", "Bearer",
                "expiresIn", jwtTokenService.getTokenExpiration(),
                "username", username,
                "roles", roles,
                "timestamp", Instant.now()
        ));
    }
}