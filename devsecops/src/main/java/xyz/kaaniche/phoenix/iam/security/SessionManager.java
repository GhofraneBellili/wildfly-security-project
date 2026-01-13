package xyz.kaaniche.phoenix.iam.security;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import xyz.kaaniche.phoenix.iam.controllers.AuditLogRepository;
import xyz.kaaniche.phoenix.iam.entities.AuditLog;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@ApplicationScoped
public class SessionManager {

    @Inject
    AuditLogRepository auditLogRepository;

    // In-memory session store (use Redis in production)
    private final ConcurrentHashMap<String, SessionInfo> activeSessions = new ConcurrentHashMap<>();

    public String createSession(String username, String ipAddress, boolean isSensitive) {
        String sessionId = UUID.randomUUID().toString();
        Instant expiresAt = isSensitive ?
            Instant.now().plus(15, ChronoUnit.MINUTES) : // Short session for sensitive actions
            Instant.now().plus(8, ChronoUnit.HOURS);     // Normal session

        SessionInfo session = new SessionInfo(username, ipAddress, expiresAt, isSensitive);
        activeSessions.put(sessionId, session);

        auditLogRepository.save(new AuditLog(username, "SESSION_CREATED",
            "Session created for " + (isSensitive ? "sensitive" : "normal") + " access",
            ipAddress));

        return sessionId;
    }

    public boolean validateSession(String sessionId, String username, String ipAddress) {
        SessionInfo session = activeSessions.get(sessionId);
        if (session == null) {
            return false;
        }

        // Check if session expired
        if (Instant.now().isAfter(session.expiresAt)) {
            activeSessions.remove(sessionId);
            auditLogRepository.save(new AuditLog(username, "SESSION_EXPIRED",
                "Session expired", ipAddress));
            return false;
        }

        // Check IP consistency for security
        if (!session.ipAddress.equals(ipAddress)) {
            invalidateSession(sessionId, "IP address changed", username);
            return false;
        }

        return true;
    }

    public void invalidateSession(String sessionId, String reason, String username) {
        SessionInfo session = activeSessions.remove(sessionId);
        if (session != null) {
            auditLogRepository.save(new AuditLog(username, "SESSION_INVALIDATED",
                "Session invalidated: " + reason, session.ipAddress));
        }
    }

    public void extendSession(String sessionId, boolean isSensitive) {
        SessionInfo session = activeSessions.get(sessionId);
        if (session != null) {
            // Only extend non-sensitive sessions
            if (!session.isSensitive) {
                session.expiresAt = Instant.now().plus(8, ChronoUnit.HOURS);
            }
        }
    }

    public boolean isSensitiveSession(String sessionId) {
        SessionInfo session = activeSessions.get(sessionId);
        return session != null && session.isSensitive;
    }

    private static class SessionInfo {
        final String username;
        final String ipAddress;
        Instant expiresAt;
        final boolean isSensitive;

        SessionInfo(String username, String ipAddress, Instant expiresAt, boolean isSensitive) {
            this.username = username;
            this.ipAddress = ipAddress;
            this.expiresAt = expiresAt;
            this.isSensitive = isSensitive;
        }
    }
}
