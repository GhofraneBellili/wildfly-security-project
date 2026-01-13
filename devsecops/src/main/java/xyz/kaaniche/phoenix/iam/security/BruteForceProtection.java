package xyz.kaaniche.phoenix.iam.security;

import jakarta.annotation.PostConstruct;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import xyz.kaaniche.phoenix.iam.controllers.AuditLogRepository;
import xyz.kaaniche.phoenix.iam.entities.AuditLog;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Startup
@Singleton
public class BruteForceProtection {
    private final Config config = ConfigProvider.getConfig();

    // Configuration values
    private final int maxLoginAttempts = config.getValue("brute.force.max.attempts", Integer.class);
    private final int lockoutDurationMinutes = config.getValue("brute.force.lockout.duration", Integer.class);
    private final int monitoringWindowMinutes = config.getValue("brute.force.monitoring.window", Integer.class);

    // Thread-safe storage for tracking login attempts
    private final ConcurrentHashMap<String, LoginAttemptTracker> loginAttempts = new ConcurrentHashMap<>();

    @Inject
    private AuditLogRepository auditLogRepository;

    @PostConstruct
    public void init() {
        // Clean up expired entries periodically
        Thread cleanupThread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(60000); // Clean up every minute
                    cleanupExpiredEntries();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
        cleanupThread.setDaemon(true);
        cleanupThread.start();
    }

    public boolean isBlocked(String ipAddress) {
        LoginAttemptTracker tracker = loginAttempts.get(ipAddress);
        if (tracker == null) {
            return false;
        }

        // Check if currently locked out
        if (tracker.isLockedOut()) {
            auditLogRepository.save(new AuditLog("system", "BRUTE_FORCE_BLOCK",
                "IP address " + ipAddress + " is currently blocked due to excessive login attempts", ipAddress));
            return true;
        }

        return false;
    }

    public void recordFailedAttempt(String ipAddress, String username) {
        LoginAttemptTracker tracker = loginAttempts.computeIfAbsent(ipAddress,
            k -> new LoginAttemptTracker());

        tracker.recordFailedAttempt();

        // Log suspicious activity
        if (tracker.getFailedAttempts() >= maxLoginAttempts / 2) {
            auditLogRepository.save(new AuditLog(username != null ? username : "unknown",
                "SUSPICIOUS_ACTIVITY",
                "Multiple failed login attempts from IP: " + ipAddress + ", attempts: " + tracker.getFailedAttempts(),
                ipAddress));
        }

        // Check if threshold exceeded
        if (tracker.getFailedAttempts() >= maxLoginAttempts) {
            tracker.lock();
            auditLogRepository.save(new AuditLog(username != null ? username : "unknown",
                "ACCOUNT_LOCKED",
                "Account locked due to excessive failed login attempts from IP: " + ipAddress,
                ipAddress));
        }
    }

    public void recordSuccessfulLogin(String ipAddress, String username) {
        LoginAttemptTracker tracker = loginAttempts.get(ipAddress);
        if (tracker != null) {
            // Reset failed attempts on successful login
            tracker.reset();
            auditLogRepository.save(new AuditLog(username, "LOGIN_SUCCESS_RESET",
                "Login successful, resetting brute force protection counter for IP: " + ipAddress,
                ipAddress));
        }
    }

    private void cleanupExpiredEntries() {
        LocalDateTime now = LocalDateTime.now();
        loginAttempts.entrySet().removeIf(entry -> {
            LoginAttemptTracker tracker = entry.getValue();
            return tracker.getLastAttemptTime().plusMinutes(monitoringWindowMinutes).isBefore(now) &&
                   !tracker.isLockedOut();
        });
    }

    // Inner class to track login attempts for each IP
    private static class LoginAttemptTracker {
        private final AtomicInteger failedAttempts = new AtomicInteger(0);
        private volatile LocalDateTime lastAttemptTime = LocalDateTime.now();
        private volatile LocalDateTime lockoutUntil = null;

        public void recordFailedAttempt() {
            failedAttempts.incrementAndGet();
            lastAttemptTime = LocalDateTime.now();
        }

        public void reset() {
            failedAttempts.set(0);
            lockoutUntil = null;
            lastAttemptTime = LocalDateTime.now();
        }

        public void lock() {
            lockoutUntil = LocalDateTime.now().plusMinutes(30); // Default 30 minutes lockout
        }

        public boolean isLockedOut() {
            return lockoutUntil != null && LocalDateTime.now().isBefore(lockoutUntil);
        }

        public int getFailedAttempts() {
            return failedAttempts.get();
        }

        public LocalDateTime getLastAttemptTime() {
            return lastAttemptTime;
        }
    }
}
