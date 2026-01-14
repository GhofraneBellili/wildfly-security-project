package xyz.kaaniche.phoenix.iam.security;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import xyz.kaaniche.phoenix.iam.controllers.AuditLogRepository;
import xyz.kaaniche.phoenix.iam.entities.AuditLog;

import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
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

    // Scheduled executor for cleanup
    private ScheduledExecutorService cleanupExecutor;

    @Inject
    private AuditLogRepository auditLogRepository;

    @PostConstruct
    public void init() {
        // Use ScheduledExecutorService instead of manual thread
        cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "BruteForceProtection-Cleanup");
            t.setDaemon(true);
            return t;
        });
        
        // Schedule cleanup every minute
        cleanupExecutor.scheduleAtFixedRate(
            this::cleanupExpiredEntries,
            1, // Initial delay
            1, // Period
            TimeUnit.MINUTES
        );
    }

    @PreDestroy
    public void shutdown() {
        if (cleanupExecutor != null) {
            cleanupExecutor.shutdown();
            try {
                if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    cleanupExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                cleanupExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
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
            k -> new LoginAttemptTracker(lockoutDurationMinutes));

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
                "Account locked due to excessive failed login attempts from IP: " + ipAddress + 
                " for " + lockoutDurationMinutes + " minutes",
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

    public int getRemainingAttempts(String ipAddress) {
        LoginAttemptTracker tracker = loginAttempts.get(ipAddress);
        if (tracker == null) {
            return maxLoginAttempts;
        }
        return Math.max(0, maxLoginAttempts - tracker.getFailedAttempts());
    }

    public LocalDateTime getLockoutExpiry(String ipAddress) {
        LoginAttemptTracker tracker = loginAttempts.get(ipAddress);
        if (tracker != null && tracker.isLockedOut()) {
            return tracker.getLockoutUntil();
        }
        return null;
    }

    private void cleanupExpiredEntries() {
        try {
            LocalDateTime now = LocalDateTime.now();
            int removedCount = 0;
            
            var iterator = loginAttempts.entrySet().iterator();
            while (iterator.hasNext()) {
                var entry = iterator.next();
                LoginAttemptTracker tracker = entry.getValue();
                
                // Remove if monitoring window expired and not locked out
                if (tracker.getLastAttemptTime().plusMinutes(monitoringWindowMinutes).isBefore(now) &&
                    !tracker.isLockedOut()) {
                    iterator.remove();
                    removedCount++;
                }
            }
            
            if (removedCount > 0) {
                auditLogRepository.save(new AuditLog("system", "CLEANUP",
                    "Cleaned up " + removedCount + " expired brute force tracking entries", null));
            }
        } catch (Exception e) {
            // Log but don't fail - cleanup will retry
            auditLogRepository.save(new AuditLog("system", "CLEANUP_ERROR",
                "Error during cleanup: " + e.getMessage(), null));
        }
    }

    // Inner class to track login attempts for each IP
    private static class LoginAttemptTracker {
        private final AtomicInteger failedAttempts = new AtomicInteger(0);
        private volatile LocalDateTime lastAttemptTime = LocalDateTime.now();
        private volatile LocalDateTime lockoutUntil = null;
        private final int lockoutDurationMinutes;

        public LoginAttemptTracker(int lockoutDurationMinutes) {
            this.lockoutDurationMinutes = lockoutDurationMinutes;
        }

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
            // FIXED: Use configured lockout duration instead of hardcoded 30 minutes
            lockoutUntil = LocalDateTime.now().plusMinutes(lockoutDurationMinutes);
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

        public LocalDateTime getLockoutUntil() {
            return lockoutUntil;
        }
    }
}