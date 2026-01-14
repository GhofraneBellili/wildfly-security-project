package com.evenster.security;

import com.evenster.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtUtils jwtUtils;
    private final UserService userService;
    private final String frontendOrigin;

    public SecurityConfig(JwtUtils jwtUtils, UserService userService,
                          @Value("${frontend.allowed-origin}") String frontendOrigin) {
        this.jwtUtils = jwtUtils;
        this.userService = userService;
        this.frontendOrigin = frontendOrigin;
    }

    // Expose JwtAuthenticationFilter as a bean (créé avec JwtUtils et UserService)
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtUtils, userService);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthenticationFilter jwtFilter) throws Exception {
        // Filtre de rate-limit pour /api/auth/login (prototype)
        RateLimitFilter rateLimitFilter = new RateLimitFilter(5, 60); // 5 reqs / 60s

        http
            .cors(cors -> cors.configurationSource(request -> {
                var config = new org.springframework.web.cors.CorsConfiguration();
                config.setAllowedOrigins(java.util.List.of(frontendOrigin));
                config.setAllowedMethods(java.util.List.of("GET","POST","PUT","DELETE","OPTIONS"));
                config.setAllowedHeaders(java.util.List.of("*"));
                config.setAllowCredentials(true);
                return config;
            }))
            .csrf(csrf -> csrf.disable()) // JWT stateless API; si cookie httpOnly alors réactiver CSRF
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/events").permitAll()
                .requestMatchers("/api/events/**").permitAll()
                .requestMatchers(org.springframework.http.HttpMethod.POST, "/api/events").authenticated()
                .requestMatchers(org.springframework.http.HttpMethod.POST, "/api/events/*/register").authenticated()
                .anyRequest().authenticated()
            )
            .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .headers(headers -> headers
                    .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
                    .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).preload(true))
                    .frameOptions(frame -> frame.sameOrigin())
                    .referrerPolicy(ref -> ref.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
            )
            .httpBasic(Customizer.withDefaults()); // utile pour debug, désactiver en prod

        return http.build();
    }

    // AuthenticationManager nécessaire pour l'endpoint /api/auth/login
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}