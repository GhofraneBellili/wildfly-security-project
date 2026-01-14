package com.evenster.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service utilisateur simple en mémoire pour prototype.
 * Remplacez par Spring Data JPA + base réelle en production.
 */
@Service
public class UserService implements UserDetailsService {

    private final Map<String, org.springframework.security.core.userdetails.UserDetails> users = new ConcurrentHashMap<>();
    private final PasswordEncoder encoder;

    public UserService(PasswordEncoder encoder) {
        this.encoder = encoder;
        // seed user: username "alice", password "password"
        var alice = User.withUsername("alice")
                .password(encoder.encode("password"))
                .roles("USER")
                .build();
        users.put("alice", alice);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var u = users.get(username);
        if (u == null) throw new UsernameNotFoundException("User not found");
        return u;
    }

    public void createUser(String username, String rawPassword) {
        var u = User.withUsername(username)
                .password(encoder.encode(rawPassword))
                .roles("USER")
                .build();
        users.put(username, u);
    }
}