package com.sdw98.security_with_jwt.service;

import com.sdw98.security_with_jwt.model.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final PasswordEncoder passwordEncoder;
    private final Map<String, User> users;

    public CustomUserDetailsService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        this.users = initializeUsers();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = users.get(username);

        if(user == null) {
            throw new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username);
        }

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(user.getAuthorities().toArray(new String[0]))
                .build();
    }

    public User findByUsername(String username) {
        return users.get(username);
    }

    public List<User> getAllUsers() {
        return new ArrayList<>(users.values());
    }

    public User authenticate(String username, String rawPassword) {
        User user = users.get(username);
        if(user != null && passwordEncoder.matches(rawPassword, user.getPassword())) {
            return user;
        }
        return null;
    }

    private Map<String, User> initializeUsers() {
        Map<String, User> userMap = new HashMap<>();

        userMap.put("user", User.createAccount(
                "user",
                passwordEncoder.encode("user123"),
                List.of("ROLE_USER"),
                "일반 사용자",
                "user@sdw98.com"
        ));

        userMap.put("admin", User.createAccount(
                "admin",
                passwordEncoder.encode("admin123"),
                List.of("ROLE_USER", "ROLE_ADMIN"),
                "시스템 관리자",
                "admin@sdw98.com"
        ));

        userMap.put("manager", User.createAccount(
                "manager",
                passwordEncoder.encode("manager123"),
                List.of("ROLE_USER", "ROLE_MANAGER"),
                "부서 관리자",
                "manager@sdw98.com"
        ));

        return userMap;
    }
}