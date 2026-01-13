package xyz.kaaniche.phoenix.iam.boundaries;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.StreamingOutput;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import xyz.kaaniche.phoenix.iam.controllers.AuditLogRepository;
import xyz.kaaniche.phoenix.iam.controllers.PhoenixIAMRepository;
import xyz.kaaniche.phoenix.iam.entities.AuditLog;
import xyz.kaaniche.phoenix.iam.entities.Grant;
import xyz.kaaniche.phoenix.iam.entities.Identity;
import xyz.kaaniche.phoenix.iam.entities.Tenant;
import xyz.kaaniche.phoenix.iam.security.Argon2Utility;
import xyz.kaaniche.phoenix.iam.security.AuthorizationCode;
import xyz.kaaniche.phoenix.iam.security.MfaUtility;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.core.Context;

import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Path("/")
@RequestScoped
public class AuthenticationEndpoint {
    public static final String CHALLENGE_RESPONSE_COOKIE_ID = "signInId";
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationEndpoint.class);

    @Inject
    PhoenixIAMRepository phoenixIAMRepository;

    @Inject
    AuditLogRepository auditLogRepository;

    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/authorize")
    public Response authorize(@Context UriInfo uriInfo) {
        MultivaluedMap<String, String> params = uriInfo.getQueryParameters();
        //1. Check tenant
        String clientId = params.getFirst("client_id");
        if (clientId == null || clientId.isEmpty()) {
            return informUserAboutError("Invalid client_id :" + clientId);
        }
        Tenant tenant = phoenixIAMRepository.findTenantByName(clientId);
        if (tenant == null) {
            return informUserAboutError("Invalid client_id :" + clientId);
        }
        //2. Client Authorized Grant Type
        if (tenant.getSupportedGrantTypes() != null && !tenant.getSupportedGrantTypes().contains("authorization_code")) {
            return informUserAboutError("Authorization Grant type, authorization_code, is not allowed for this tenant :" + clientId);
        }
        //3. redirectUri
        String redirectUri = params.getFirst("redirect_uri");
        if (tenant.getRedirectUri() != null && !tenant.getRedirectUri().isEmpty()) {
            if (redirectUri != null && !redirectUri.isEmpty() && !tenant.getRedirectUri().equals(redirectUri)) {
                //sould be in the client.redirectUri
                return informUserAboutError("redirect_uri is pre-registred and should match");
            }
            redirectUri = tenant.getRedirectUri();
        } else {
            if (redirectUri == null || redirectUri.isEmpty()) {
                return informUserAboutError("redirect_uri is not pre-registred and should be provided");
            }
        }

        //4. response_type
        String responseType = params.getFirst("response_type");
        if (!"code".equals(responseType) && !"token".equals(responseType)) {
            String error = "invalid_grant :" + responseType + ", response_type params should be code or token:";
            return informUserAboutError(error);
        }

        //5. check scope
        String requestedScope = params.getFirst("scope");
        if (requestedScope == null || requestedScope.isEmpty()) {
            requestedScope = tenant.getRequiredScopes();
        }
        //6. code_challenge_method must be S256
        String codeChallengeMethod = params.getFirst("code_challenge_method");
        if(codeChallengeMethod==null || !codeChallengeMethod.equals("S256")){
            String error = "invalid_grant :" + codeChallengeMethod + ", code_challenge_method must be 'S256'";
            return informUserAboutError(error);
        }
        StreamingOutput stream = output -> {
            try (InputStream is = Objects.requireNonNull(getClass().getResource("/login.html")).openStream()){
                output.write(is.readAllBytes());
            }
        };
        return Response.ok(stream).location(uriInfo.getBaseUri().resolve("/login/authorization"))
                .cookie(new NewCookie.Builder(CHALLENGE_RESPONSE_COOKIE_ID)
                .httpOnly(true).secure(true).sameSite(NewCookie.SameSite.STRICT).value(tenant.getName()+"#"+requestedScope+"$"+redirectUri).build()).build();
    }

    @POST
    @Path("/login/authorization")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response login(@CookieParam(CHALLENGE_RESPONSE_COOKIE_ID) Cookie cookie,
                          @FormParam("username")String username,
                          @FormParam("password")String password,
                          @Context UriInfo uriInfo,
                          @Context HttpServletRequest request) throws Exception {
        String ipAddress = getClientIpAddress(request);
        Identity identity = phoenixIAMRepository.findIdentityByUsername(username);
        if (identity != null && Argon2Utility.check(identity.getPassword(), password.toCharArray())) {
            logger.info("Password authentication successful for user: {}", username);
            auditLogRepository.save(new AuditLog(username, "LOGIN_SUCCESS", "Password authentication successful", ipAddress));

            // Check if MFA is enabled
            if (identity.getMfaSecret() != null && !identity.getMfaSecret().isEmpty()) {
                // Redirect to MFA verification page
                StreamingOutput stream = output -> {
                    try (InputStream is = Objects.requireNonNull(getClass().getResource("/mfa.html")).openStream()) {
                        output.write(is.readAllBytes());
                    }
                };
                return Response.ok(stream)
                        .cookie(new NewCookie.Builder("mfa_user").value(username).httpOnly(true).secure(true).build())
                        .build();
            } else {
                // Proceed with normal flow
                return proceedAfterAuthentication(cookie, username, uriInfo);
            }
        } else {
            logger.warn("Password authentication failed for user: {}", username);
            auditLogRepository.save(new AuditLog(username != null ? username : "unknown", "LOGIN_FAILURE", "Invalid password", ipAddress));
            URI location = UriBuilder.fromUri(cookie.getValue().split("\\$")[1])
                    .queryParam("error", "Invalid credentials")
                    .queryParam("error_description", "Invalid username or password")
                    .build();
            return Response.seeOther(location).build();
        }
    }

    @POST
    @Path("/mfa/verify")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response verifyMfa(@CookieParam("mfa_user") Cookie mfaUserCookie,
                              @FormParam("code") String code,
                              @CookieParam(CHALLENGE_RESPONSE_COOKIE_ID) Cookie cookie,
                              @Context UriInfo uriInfo,
                              @Context HttpServletRequest request) throws Exception {
        if (mfaUserCookie == null || code == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid MFA request").build();
        }

        String username = mfaUserCookie.getValue();
        String ipAddress = getClientIpAddress(request);
        Identity identity = phoenixIAMRepository.findIdentityByUsername(username);

        if (identity != null && MfaUtility.verifyCode(identity.getMfaSecret(), code)) {
            logger.info("MFA verification successful for user: {}", username);
            auditLogRepository.save(new AuditLog(username, "MFA_SUCCESS", "MFA verification successful", ipAddress));
            return proceedAfterAuthentication(cookie, username, uriInfo);
        } else {
            logger.warn("MFA verification failed for user: {}", username);
            auditLogRepository.save(new AuditLog(username, "MFA_FAILURE", "Invalid MFA code", ipAddress));
            StreamingOutput stream = output -> {
                try (InputStream is = Objects.requireNonNull(getClass().getResource("/mfa.html")).openStream()) {
                    output.write(is.readAllBytes());
                }
            };
            return Response.ok(stream).entity("Invalid MFA code. Please try again.").build();
        }
    }

    private Response proceedAfterAuthentication(Cookie cookie, String username, UriInfo uriInfo) throws Exception {
        MultivaluedMap<String, String> params = uriInfo.getQueryParameters();
        Optional<Grant> grant = phoenixIAMRepository.findGrant(cookie.getValue().split("#")[0], phoenixIAMRepository.findIdentityByUsername(username).getId());
        if (grant.isPresent()) {
            String redirectURI = buildActualRedirectURI(
                    cookie.getValue().split("\\$")[1], params.getFirst("response_type"),
                    cookie.getValue().split("#")[0],
                    username,
                    checkUserScopes(grant.get().getApprovedScopes(), cookie.getValue().split("#")[1].split("\\$")[0]),
                    params.getFirst("code_challenge"), params.getFirst("state")
            );
            return Response.seeOther(UriBuilder.fromUri(redirectURI).build()).build();
        } else {
            StreamingOutput stream = output -> {
                try (InputStream is = Objects.requireNonNull(getClass().getResource("/consent.html")).openStream()) {
                    output.write(is.readAllBytes());
                }
            };
            return Response.ok(stream).build();
        }
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    @GET
    @Path("/mfa/setup")
    @Produces(MediaType.APPLICATION_JSON)
    public Response setupMfa(@Context HttpServletRequest request) {
        // This would typically require authentication, but for simplicity assuming user is authenticated
        String username = "current_user"; // In real implementation, get from session/auth
        String secret = MfaUtility.generateSecret();
        byte[] qrCode = MfaUtility.generateQrCode(secret, username, "Phoenix IAM");

        // Store secret temporarily or return it for client to save
        return Response.ok()
                .entity("{\"secret\":\"" + secret + "\", \"qrCode\":\"" + Base64.getEncoder().encodeToString(qrCode) + "\"}")
                .build();
    }

    @POST
    @Path("/mfa/enable")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response enableMfa(String body, @Context HttpServletRequest request) {
        // Parse JSON body for secret and verification code
        // In real implementation, parse JSON properly
        String username = "current_user"; // Get from auth
        String secret = ""; // Extract from body
        String code = ""; // Extract from body

        if (MfaUtility.verifyCode(secret, code)) {
            // Save secret to user
            Identity identity = phoenixIAMRepository.findIdentityByUsername(username);
            if (identity != null) {
                identity.setMfaSecret(secret);
                phoenixIAMRepository.save(identity);
                auditLogRepository.save(new AuditLog(username, "MFA_ENABLED", "MFA enabled successfully", getClientIpAddress(request)));
                return Response.ok().entity("{\"success\":true}").build();
            }
        }
        return Response.status(Response.Status.BAD_REQUEST).entity("{\"success\":false}").build();
    }

    @POST
    @Path("/api/login")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response apiLogin(String body, @Context HttpServletRequest request) {
        // Parse JSON: {"username": "...", "password": "..."}
        String username = extractJsonValue(body, "username");
        String password = extractJsonValue(body, "password");
        String ipAddress = getClientIpAddress(request);

        Identity identity = phoenixIAMRepository.findIdentityByUsername(username);
        if (identity != null && Argon2Utility.check(identity.getPassword(), password.toCharArray())) {
            logger.info("Password authentication successful for user: {}", username);
            auditLogRepository.save(new AuditLog(username, "LOGIN_SUCCESS", "Password authentication successful", ipAddress));

            if (identity.getMfaSecret() != null && !identity.getMfaSecret().isEmpty()) {
                return Response.ok().entity("{\"success\":true, \"mfaRequired\":true}").build();
            } else {
                return Response.ok().entity("{\"success\":true, \"mfaRequired\":false}").build();
            }
        } else {
            logger.warn("Password authentication failed for user: {}", username);
            auditLogRepository.save(new AuditLog(username != null ? username : "unknown", "LOGIN_FAILURE", "Invalid password", ipAddress));
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"success\":false, \"error\":\"Invalid credentials\"}").build();
        }
    }

    @POST
    @Path("/api/mfa/verify")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response apiVerifyMfa(String body, @Context HttpServletRequest request) {
        String username = extractJsonValue(body, "username");
        String code = extractJsonValue(body, "code");
        String ipAddress = getClientIpAddress(request);

        Identity identity = phoenixIAMRepository.findIdentityByUsername(username);
        if (identity != null && MfaUtility.verifyCode(identity.getMfaSecret(), code)) {
            logger.info("MFA verification successful for user: {}", username);
            auditLogRepository.save(new AuditLog(username, "MFA_SUCCESS", "MFA verification successful", ipAddress));
            return Response.ok().entity("{\"success\":true}").build();
        } else {
            logger.warn("MFA verification failed for user: {}", username);
            auditLogRepository.save(new AuditLog(username, "MFA_FAILURE", "Invalid MFA code", ipAddress));
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"success\":false, \"error\":\"Invalid MFA code\"}").build();
        }
    }

    @GET
    @Path("/api/mfa/setup")
    @Produces(MediaType.APPLICATION_JSON)
    public Response apiSetupMfa(@Context HttpServletRequest request) {
        String username = "current_user"; // In real implementation, get from session/auth
        String secret = MfaUtility.generateSecret();
        byte[] qrCode = MfaUtility.generateQrCode(secret, username, "Phoenix IAM");

        return Response.ok()
                .entity("{\"secret\":\"" + secret + "\", \"qrCode\":\"" + Base64.getEncoder().encodeToString(qrCode) + "\"}")
                .build();
    }

    @POST
    @Path("/api/mfa/enable")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response apiEnableMfa(String body, @Context HttpServletRequest request) {
        String username = "current_user"; // Get from auth
        String secret = extractJsonValue(body, "secret");
        String code = extractJsonValue(body, "code");

        if (MfaUtility.verifyCode(secret, code)) {
            Identity identity = phoenixIAMRepository.findIdentityByUsername(username);
            if (identity != null) {
                identity.setMfaSecret(secret);
                phoenixIAMRepository.save(identity);
                auditLogRepository.save(new AuditLog(username, "MFA_ENABLED", "MFA enabled successfully", getClientIpAddress(request)));
                return Response.ok().entity("{\"success\":true}").build();
            }
        }
        return Response.status(Response.Status.BAD_REQUEST).entity("{\"success\":false}").build();
    }

    @GET
    @Path("/api/audit/logs")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuditLogs(@Context HttpServletRequest request) {
        // In real implementation, get current user from auth
        String username = "current_user";
        List<AuditLog> logs = auditLogRepository.findByUserId(username);
        // Convert to JSON
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < logs.size(); i++) {
            AuditLog log = logs.get(i);
            json.append("{\"id\":").append(log.getId())
                .append(",\"action\":\"").append(log.getAction())
                .append("\",\"details\":\"").append(log.getDetails())
                .append("\",\"timestamp\":\"").append(log.getTimestamp()).append("\"}");
            if (i < logs.size() - 1) json.append(",");
        }
        json.append("]");
        return Response.ok().entity(json.toString()).build();
    }

    private String extractJsonValue(String json, String key) {
        // Simple JSON parser for demo
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start == -1) return "";
        start += search.length();
        int end = json.indexOf("\"", start);
        return end == -1 ? "" : json.substring(start, end);
    }

    @PATCH
    @Path("/login/authorization")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response grantConsent(@CookieParam(CHALLENGE_RESPONSE_COOKIE_ID) Cookie cookie,
                                 @FormParam("approved_scope") String scope,
                                 @FormParam("approval_status") String approvalStatus,
                                 @FormParam("username") String username){
        if ("NO".equals(approvalStatus)) {
            URI location = UriBuilder.fromUri(cookie.getValue().split("\\$")[1])
                    .queryParam("error", "User doesn't approved the request.")
                    .queryParam("error_description", "User doesn't approved the request.")
                    .build();
            return Response.seeOther(location).build();
        }
        //==> YES
        List<String> approvedScopes = Arrays.stream(scope.split(" ")).toList();
        if (approvedScopes.isEmpty()) {
            URI location = UriBuilder.fromUri(cookie.getValue().split("\\$")[1])
                    .queryParam("error", "User doesn't approved the request.")
                    .queryParam("error_description", "User doesn't approved the request.")
                    .build();
            return Response.seeOther(location).build();
        }
        try {
            return Response.seeOther(UriBuilder.fromUri(buildActualRedirectURI(
                    cookie.getValue().split("\\$")[1],null,
                    cookie.getValue().split("#")[0],username, String.join(" ", approvedScopes), null,null
            )).build()).build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String buildActualRedirectURI(String redirectUri,String responseType,String clientId,String userId,String approvedScopes,String codeChallenge,String state) throws Exception {
        StringBuilder sb = new StringBuilder(redirectUri);
        if ("code".equals(responseType)) {
            AuthorizationCode authorizationCode = new AuthorizationCode(clientId,userId,
                    approvedScopes, Instant.now().plus(2, ChronoUnit.MINUTES).getEpochSecond(),redirectUri);
            sb.append("?code=").append(URLEncoder.encode(authorizationCode.getCode(codeChallenge), StandardCharsets.UTF_8));
        } else {
            //Implicit: responseType=token : Not Supported
            return null;
        }
        if (state != null) {
            sb.append("&state=").append(state);
        }
        return sb.toString();
    }

    private String checkUserScopes(String userScopes, String requestedScope) {
        Set<String> allowedScopes = new LinkedHashSet<>();
        Set<String> rScopes = new HashSet<>(Arrays.asList(requestedScope.split(" ")));
        Set<String> uScopes = new HashSet<>(Arrays.asList(userScopes.split(" ")));
        for (String scope : uScopes) {
            if (rScopes.contains(scope)) allowedScopes.add(scope);
        }
        return String.join( " ", allowedScopes);
    }

    private Response informUserAboutError(String error) {
        return Response.status(Response.Status.BAD_REQUEST).entity("""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8"/>
                    <title>Error</title>
                </head>
                <body>
                <aside class="container">
                    <p>%s</p>
                </aside>
                </body>
                </html>
                """.formatted(error)).build();
    }
}
