package xyz.kaaniche.phoenix.iam.boundaries;

import jakarta.ejb.EJB;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import jakarta.servlet.http.HttpServletRequest;
import org.eclipse.microprofile.config.ConfigProvider;
import xyz.kaaniche.phoenix.iam.controllers.AuditLogRepository;
import xyz.kaaniche.phoenix.iam.controllers.PhoenixIAMRepository;
import xyz.kaaniche.phoenix.iam.entities.AuditLog;
import xyz.kaaniche.phoenix.iam.security.AuthorizationCode;
import xyz.kaaniche.phoenix.iam.security.JwtManager;

import java.security.GeneralSecurityException;
import java.util.Optional;
import java.util.Set;

@Path("/oauth/token")
@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
@Produces(MediaType.APPLICATION_JSON)
public class TokenEndpoint {

    private static final Set<String> SUPPORTED_GRANTS =
            Set.of("authorization_code", "refresh_token");

    @Inject
    private PhoenixIAMRepository iamRepository;

    @Inject
    private AuditLogRepository auditLogRepository;

    @EJB
    private JwtManager jwtManager;

    @POST
    public Response token(@FormParam("grant_type") String grantType,
                          @FormParam("code") String code,
                          @FormParam("code_verifier") String codeVerifier,
                          @FormParam("refresh_token") String refreshToken,
                          @Context HttpServletRequest request) {

        if (grantType == null || !SUPPORTED_GRANTS.contains(grantType)) {
            return error("unsupported_grant_type", "Unsupported grant type", Response.Status.BAD_REQUEST);
        }

        try {
            if ("authorization_code".equals(grantType)) {
                return handleAuthorizationCode(code, codeVerifier, request);
            }

            if ("refresh_token".equals(grantType)) {
                return handleRefreshToken(refreshToken, request);
            }

            return error("invalid_request", "Invalid OAuth request", Response.Status.BAD_REQUEST);

        } catch (Exception e) {
            auditLogRepository.save(new AuditLog(
                    "SYSTEM",
                    "TOKEN_ERROR",
                    "Token endpoint internal error",
                    getClientIp(request)
            ));
            return error("server_error", "Unable to issue token", Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    /* ========================= AUTHORIZATION CODE FLOW ========================= */

    private Response handleAuthorizationCode(String code,
                                             String codeVerifier,
                                             HttpServletRequest request)
            throws GeneralSecurityException {

        if (code == null || codeVerifier == null) {
            return error("invalid_request", "Missing authorization code or verifier", Response.Status.BAD_REQUEST);
        }

        AuthorizationCode decoded = AuthorizationCode.decode(code, codeVerifier);
        if (decoded == null) {
            return error("invalid_grant", "Invalid authorization code", Response.Status.UNAUTHORIZED);
        }

        String username = decoded.identityUsername();
        String tenant = decoded.tenantName();
        String scopes = decoded.approvedScopes();

        var roles = iamRepository.getRoles(username);

        String accessToken = jwtManager.generateAccessToken(tenant, username, scopes, roles);
        String refreshToken = jwtManager.generateRefreshToken(tenant, username, scopes);

        auditLogRepository.save(new AuditLog(
                username,
                "TOKEN_ISSUED",
                "Access token issued via authorization code",
                getClientIp(request)
        ));

        return tokenResponse(accessToken, refreshToken, scopes);
    }

    /* ========================= REFRESH TOKEN FLOW ========================= */

    private Response handleRefreshToken(String refreshToken,
                                        HttpServletRequest request) {

        if (refreshToken == null) {
            return error("invalid_request", "refresh_token is required", Response.Status.BAD_REQUEST);
        }

        Optional<?> validated = jwtManager.validateJWT(refreshToken);
        if (validated.isEmpty()) {
            return error("invalid_grant", "Invalid refresh token", Response.Status.UNAUTHORIZED);
        }

        try {
            var claims = validated.get().getJWTClaimsSet();

            if (!jwtManager.isRefreshToken(claims)) {
                return error("invalid_grant", "Token is not a refresh token", Response.Status.UNAUTHORIZED);
            }

            String tenant = claims.getStringClaim("tenant_id");
            String subject = claims.getSubject();
            String scopes = claims.getStringClaim("scope");

            var roles = iamRepository.getRoles(subject);

            // 🔐 Refresh token rotation
            jwtManager.revokeToken(claims.getJWTID());

            String newAccessToken = jwtManager.generateAccessToken(tenant, subject, scopes, roles);
            String newRefreshToken = jwtManager.generateRefreshToken(tenant, subject, scopes);

            auditLogRepository.save(new AuditLog(
                    subject,
                    "TOKEN_REFRESHED",
                    "Access token refreshed",
                    getClientIp(request)
            ));

            return tokenResponse(newAccessToken, newRefreshToken, scopes);

        } catch (Exception e) {
            return error("invalid_grant", "Refresh token processing failed", Response.Status.UNAUTHORIZED);
        }
    }

    /* ========================= HELPERS ========================= */

    private Response tokenResponse(String accessToken,
                                   String refreshToken,
                                   String scopes) {

        JsonObject body = Json.createObjectBuilder()
                .add("token_type", "Bearer")
                .add("access_token", accessToken)
                .add("expires_in",
                        ConfigProvider.getConfig()
                                .getValue("jwt.lifetime.duration", Integer.class))
                .add("scope", scopes)
                .add("refresh_token", refreshToken)
                .build();

        return Response.ok(body)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .build();
    }

    private Response error(String error, String description, Response.Status status) {
        return Response.status(status)
                .entity(Json.createObjectBuilder()
                        .add("error", error)
                        .add("error_description", description)
                        .build())
                .build();
    }

    private String getClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        return (forwarded != null && !forwarded.isEmpty())
                ? forwarded.split(",")[0].trim()
                : request.getRemoteAddr();
    }
}
