package xyz.kaaniche.phoenix.iam.security;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.ext.Provider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Method;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Provider
@RequiresScopes("") // This filter applies to all endpoints with @RequiresScopes
@Priority(Priorities.AUTHORIZATION + 1) // Run after AuthorizationFilter
public class ScopeFilter implements ContainerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(ScopeFilter.class);

    @Context
    private ResourceInfo resourceInfo;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        Method method = resourceInfo.getResourceMethod();

        // Check if method has @RequiresScopes annotation
        RequiresScopes requiresScopes = method.getAnnotation(RequiresScopes.class);
        if (requiresScopes == null) {
            // Check class-level annotation
            requiresScopes = resourceInfo.getResourceClass().getAnnotation(RequiresScopes.class);
        }

        if (requiresScopes != null && requiresScopes.value().length > 0) {
            SecurityContext securityContext = requestContext.getSecurityContext();

            if (!hasRequiredScopes(requestContext, requiresScopes.value())) {
                logger.warn("Access denied due to insufficient scopes for user: {}",
                    securityContext.getUserPrincipal() != null ? securityContext.getUserPrincipal().getName() : "unknown");

                requestContext.abortWith(
                    Response.status(Response.Status.FORBIDDEN)
                        .entity("{\"error\":\"insufficient_scope\",\"error_description\":\"The access token does not contain the required scopes\"}")
                        .header(HttpHeaders.CONTENT_TYPE, "application/json")
                        .build());
            }
        }
    }

    private boolean hasRequiredScopes(ContainerRequestContext requestContext, String[] requiredScopes) {
        // Extract JWT token from Authorization header
        String authorizationHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return false;
        }

        String token = authorizationHeader.substring("Bearer ".length());

        try {
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();

            // Get scope claim
            String scopeClaim = claimsSet.getStringClaim("scope");
            if (scopeClaim == null || scopeClaim.isEmpty()) {
                return false;
            }

            Set<String> userScopes = Arrays.stream(scopeClaim.split("\\s+"))
                    .collect(Collectors.toSet());

            // Check if user has all required scopes
            for (String requiredScope : requiredScopes) {
                if (!userScopes.contains(requiredScope)) {
                    return false;
                }
            }

            return true;

        } catch (ParseException e) {
            logger.error("Failed to parse JWT token", e);
            return false;
        }
    }
}
