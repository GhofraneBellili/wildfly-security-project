package xyz.kaaniche.phoenix.iam.boundaries;

import jakarta.ejb.EJB;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.servlet.http.HttpServletRequest;
import xyz.kaaniche.phoenix.iam.controllers.AuditLogRepository;
import xyz.kaaniche.phoenix.iam.entities.AuditLog;
import xyz.kaaniche.phoenix.iam.security.JwtManager;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Path("jwk")
@ApplicationScoped
public class JWKEndpoint {

    @EJB
    private JwtManager jwtManager;

    @Inject
    private AuditLogRepository auditLogRepository;

    // Simple in-memory rate limiter (per IP, max 10 requests per minute)
    private final Map<String, RequestInfo> requestTracker = new ConcurrentHashMap<>();
    private static final int MAX_REQUESTS_PER_MINUTE = 10;

    @GET
    public Response getPublicVerificationKey(@QueryParam("kid") String kid,
                                             @Context HttpServletRequest request) {

        String ipAddress = getClientIpAddress(request);

        // Rate limiting
        if (!allowRequest(ipAddress)) {
            return Response.status(Response.Status.TOO_MANY_REQUESTS)
                    .entity("Too many requests, please try again later").build();
        }

        // Sanitize input before logging
        String sanitizedKid = kid == null ? "null" : kid.replaceAll("[\\n\\r]", "_");

        try {
            // Audit log (sanitized)
            auditLogRepository.save(new AuditLog("anonymous", "JWK_REQUEST",
                    "Public key requested for kid: " + sanitizedKid, ipAddress));

            String publicKeyJson = jwtManager.getPublicValidationKey(kid).toJSONString();

            return Response.ok(publicKeyJson)
                    .type(MediaType.APPLICATION_JSON)
                    .build();

        } catch (Exception e) {
            // Log full details internally
            auditLogRepository.save(new AuditLog("anonymous", "JWK_REQUEST_FAILED",
                    "Failed to get public key for kid: " + sanitizedKid + ", error: " + e.getMessage(),
                    ipAddress));

            // Return generic error to client
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Unable to retrieve the requested key").build();
        }
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");

        // Only trust X-Forwarded-For if behind a trusted proxy
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }

    private boolean allowRequest(String ip) {
        Instant now = Instant.now();
        RequestInfo info = requestTracker.getOrDefault(ip, new RequestInfo(0, now));

        // Reset counter if more than 1 minute has passed
        if (now.isAfter(info.timestamp.plusSeconds(60))) {
            info.count = 1;
            info.timestamp = now;
        } else {
            info.count += 1;
        }

        requestTracker.put(ip, info);

        return info.count <= MAX_REQUESTS_PER_MINUTE;
    }

    private static class RequestInfo {
        int count;
        Instant timestamp;

        RequestInfo(int count, Instant timestamp) {
            this.count = count;
            this.timestamp = timestamp;
        }
    }
}
