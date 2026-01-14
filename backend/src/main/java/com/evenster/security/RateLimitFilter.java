package com.evenster.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Deque;
import java.util.LinkedList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Filtre simple: limite le nombre de requêtes sur /api/auth/login par IP.
 * Production: remplacer par solution robuste (redis + token bucket).
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private final Map<String, Deque<Instant>> attempts = new ConcurrentHashMap<>();
    private final int maxRequests;
    private final int windowSeconds;

    public RateLimitFilter(int maxRequests, int windowSeconds) {
        this.maxRequests = maxRequests;
        this.windowSeconds = windowSeconds;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        if ("/api/auth/login".equals(path)) {
            String ip = request.getRemoteAddr();
            var deque = attempts.computeIfAbsent(ip, k -> new LinkedList<>());
            Instant now = Instant.now();
            while (!deque.isEmpty() && deque.peekFirst().isBefore(now.minusSeconds(windowSeconds))) {
                deque.pollFirst();
            }
            if (deque.size() >= maxRequests) {
                response.setStatus(429);
                response.getWriter().write("Too many requests");
                return;
            }
            deque.addLast(now);
        }
        filterChain.doFilter(request, response);
    }
}