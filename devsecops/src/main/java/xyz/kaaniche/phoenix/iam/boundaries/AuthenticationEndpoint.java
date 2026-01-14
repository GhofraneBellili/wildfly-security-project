package xyz.kaaniche.phoenix.iam.boundaries;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

import xyz.kaaniche.phoenix.iam.controllers.AuditLogRepository;
import xyz.kaaniche.phoenix.iam.controllers.PhoenixIAMRepository;
import xyz.kaaniche.phoenix.iam.entities.*;
import xyz.kaaniche.phoenix.iam.security.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

@Path("/oauth")
@RequestScoped
public class AuthenticationEndpoint {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationEndpoint.class);
    private static final String AUTH_REQUEST_COOKIE = "AUTH_REQUEST_ID";

    @Inject PhoenixIAMRepository iamRepository;
    @Inject AuditLogRepository auditLogRepository;
    @Inject BruteForceProtection bruteForceProtection;
    @Inject SessionManager sessionManager;

    @Context HttpServletRequest request;

    /* =========================================================
       AUTHORIZE (OAuth 2.1 + PKCE)
       ========================================================= */

    @GET
    @Path("/authorize")
    @Produces(MediaType.TEXT_HTML)
    public Response authorize(@Context UriInfo uriInfo) {

        String clientId = uriInfo.getQueryParameters().getFirst("client_id");
        String redirectUri = uriInfo.getQueryParameters().getFirst("redirect_uri");
        String responseType = uriInfo.getQueryParameters().getFirst("response_type");
        String codeChallenge = uriInfo.getQueryParameters().getFirst("code_challenge");
        String challengeMethod = uriInfo.getQueryParameters().getFirst("code_challenge_method");
        String state = uriInfo.getQueryParameters().getFirst("state");

        if (!"code".equals(responseType)) {
            return error("Only authorization code flow is supported");
        }

        if (codeChallenge == null || !"S256".equals(challengeMethod)) {
            return error("PKCE with S256 is required");
        }

        Tenant tenant = iamRepository.findTenantByName(clientId);
        if (tenant == null || !tenant.getRedirectUri().equals(redirectUri)) {
            return error("Invalid OAuth client");
        }

        String authRequestId = sessionManager.storeAuthorizationRequest(
                clientId,
                redirectUri,
                codeChallenge,
                state,
                Instant.now().plus(5, ChronoUnit.MINUTES)
        );

        return Response.ok(loadHtml("/login.html"))
                .cookie(new NewCookie(
                        AUTH_REQUEST_COOKIE,
                        authRequestId,
                        "/",
                        null,
                        null,
                        300,
                        true,
                        true
                ))
                .build();
    }

    /* =========================================================
       LOGIN
       ========================================================= */

    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response login(@CookieParam(AUTH_REQUEST_COOKIE) Cookie authCookie,
                          @FormParam("username") String username,
                          @FormParam("password") String password) {

        String ip = request.getRemoteAddr();

        if (authCookie == null) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        if (bruteForceProtection.isBlocked(username, ip)) {
            return Response.status(429).entity("Too many attempts").build();
        }

        Identity identity = iamRepository.findIdentityByUsername(username);
        if (identity == null || !Argon2Utility.check(identity.getPassword(), password.toCharArray())) {
            bruteForceProtection.registerFailure(username, ip);
            auditLogRepository.save(new AuditLog(username, "LOGIN_FAILURE", "Invalid credentials", ip));
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        bruteForceProtection.registerSuccess(username, ip);
        auditLogRepository.save(new AuditLog(username, "LOGIN_SUCCESS", "Password verified", ip));

        sessionManager.authenticate(identity);

        if (Boolean.TRUE.equals(identity.getRequiresMfa())) {
            return Response.ok(loadHtml("/mfa.html")).build();
        }

        return issueAuthorizationCode(authCookie.getValue(), identity);
    }

    /* =========================================================
       MFA VERIFY
       ========================================================= */

    @POST
    @Path("/mfa/verify")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response verifyMfa(@FormParam("code") String code,
                              @CookieParam(AUTH_REQUEST_COOKIE) Cookie authCookie) {

        Identity identity = sessionManager.getAuthenticatedUser();
        if (identity == null || authCookie == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        if (!MfaUtility.verifyCode(identity.getMfaSecret(), code)) {
            auditLogRepository.save(new AuditLog(identity.getUsername(),
                    "MFA_FAILURE", "Invalid MFA code", request.getRemoteAddr()));
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        auditLogRepository.save(new AuditLog(identity.getUsername(),
                "MFA_SUCCESS", "MFA verified", request.getRemoteAddr()));

        return issueAuthorizationCode(authCookie.getValue(), identity);
    }

    /* =========================================================
       ISSUE AUTHORIZATION CODE
       ========================================================= */

    private Response issueAuthorizationCode(String authRequestId, Identity identity) {

        AuthorizationRequest authRequest =
                sessionManager.getAuthorizationRequest(authRequestId);

        if (authRequest == null || authRequest.isExpired()) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        AuthorizationCode code = new AuthorizationCode(
                authRequest.clientId(),
                identity.getId(),
                authRequest.scopes(),
                Instant.now().plus(2, ChronoUnit.MINUTES).getEpochSecond(),
                authRequest.redirectUri()
        );

        URI redirect = UriBuilder.fromUri(authRequest.redirectUri())
                .queryParam("code", code.getCode(authRequest.codeChallenge()))
                .queryParam("state", authRequest.state())
                .build();

        sessionManager.clearAuthorizationRequest(authRequestId);

        return Response.seeOther(redirect).build();
    }

    /* =========================================================
       UTILS
       ========================================================= */

    private StreamingOutput loadHtml(String file) {
        return output -> {
            try (InputStream is = Objects.requireNonNull(
                    getClass().getResource(file)).openStream()) {
                output.write(is.readAllBytes());
            }
        };
    }

    private Response error(String message) {
        return Response.status(Response.Status.BAD_REQUEST)
                .entity(message)
                .build();
    }
}
