package com.evenster.controller;

import com.evenster.security.JwtUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    public AuthController(AuthenticationManager authenticationManager, JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String,String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");
        if (username == null || password == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "missing credentials"));
        }
        try {
            var auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            if (auth.isAuthenticated()) {
                String token = jwtUtils.generateToken(username);
                return ResponseEntity.ok(Map.of("token", token, "userId", username));
            }
            return ResponseEntity.status(401).body(Map.of("error","invalid credentials"));
        } catch (Exception ex) {
            return ResponseEntity.status(401).body(Map.of("error","invalid credentials"));
        }
    }
}