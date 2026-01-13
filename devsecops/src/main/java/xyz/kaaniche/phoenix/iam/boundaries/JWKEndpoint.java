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

@Path("jwk")
@ApplicationScoped
public class JWKEndpoint {
    @EJB
    private JwtManager jwtManager;

    @Inject
    private AuditLogRepository auditLogRepository;

    @GET
    public Response getPublicVerificationKey(@QueryParam ("kid") String kid, @Context HttpServletRequest request) throws Exception {
        String ipAddress = getClientIpAddress(request);
        try {
            auditLogRepository.save(new AuditLog("anonymous", "JWK_REQUEST", "Public key requested for kid: " + kid, ipAddress));
            return Response.ok(jwtManager.getPublicValidationKey(kid).toJSONString()).type(MediaType.APPLICATION_JSON).build();
        }catch (Throwable t){
            auditLogRepository.save(new AuditLog("anonymous", "JWK_REQUEST_FAILED", "Failed to get public key for kid: " + kid + ", error: " + t.getMessage(), ipAddress));
            return Response.status(Response.Status.BAD_REQUEST).entity(t.getMessage()).build();
        }
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
