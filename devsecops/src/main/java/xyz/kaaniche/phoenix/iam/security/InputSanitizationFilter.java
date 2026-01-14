package xyz.kaaniche.phoenix.iam.security;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Improved input sanitization filter
 * Uses proper encoding and validation instead of regex removal
 */
@Provider
@PreMatching
public class InputSanitizationFilter implements ContainerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(InputSanitizationFilter.class);

    // More comprehensive XSS pattern detection (for logging only)
    private static final Pattern[] SUSPICIOUS_PATTERNS = {
        Pattern.compile("<script[^>]*>", Pattern.CASE_INSENSITIVE),
        Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("onerror\\s*=", Pattern.CASE_INSENSITIVE),
        Pattern.compile("onload\\s*=", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<iframe", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<object", Pattern.CASE_INSENSITIVE),
        Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("data:text/html", Pattern.CASE_INSENSITIVE)
    };

    // Maximum length for input parameters
    private static final int MAX_PARAM_LENGTH = 10000;
    
    // SQL injection patterns for detection
    private static final Pattern[] SQL_PATTERNS = {
        Pattern.compile("(union.*select|insert.*into|delete.*from|drop.*table|update.*set)", 
                       Pattern.CASE_INSENSITIVE),
        Pattern.compile("(--|;|/\\*|\\*/|xp_|sp_)", Pattern.CASE_INSENSITIVE)
    };

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        // Validate query parameters
        MultivaluedMap<String, String> queryParams = requestContext.getUriInfo().getQueryParameters();
        if (!validateParameters(queryParams, "query parameter")) {
            abortRequest(requestContext, "Invalid query parameter detected");
            return;
        }

        // Validate headers (limited validation - most headers are safe)
        MultivaluedMap<String, String> headers = requestContext.getHeaders();
        if (!validateHeaders(headers)) {
            abortRequest(requestContext, "Invalid header detected");
            return;
        }
    }

    private boolean validateParameters(MultivaluedMap<String, String> parameters, String paramType) {
        for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
            String paramName = entry.getKey();
            List<String> values = entry.getValue();
            
            for (String value : values) {
                if (value == null) continue;
                
                // Check length
                if (value.length() > MAX_PARAM_LENGTH) {
                    logger.warn("Parameter '{}' exceeds maximum length: {} characters", 
                               paramName, value.length());
                    return false;
                }
                
                // Check for suspicious patterns
                if (containsSuspiciousContent(value)) {
                    logger.warn("Potentially malicious {} detected: {}", paramType, paramName);
                    return false;
                }
                
                // Check for SQL injection patterns
                if (containsSQLInjection(value)) {
                    logger.warn("Potential SQL injection in {}: {}", paramType, paramName);
                    return false;
                }
            }
        }
        return true;
    }

    private boolean validateHeaders(MultivaluedMap<String, String> headers) {
        // Only validate specific headers that could be dangerous
        String[] headersToCheck = {"User-Agent", "Referer", "X-Forwarded-For"};
        
        for (String headerName : headersToCheck) {
            List<String> values = headers.get(headerName);
            if (values != null) {
                for (String value : values) {
                    if (value != null && value.length() > MAX_PARAM_LENGTH) {
                        logger.warn("Header '{}' exceeds maximum length", headerName);
                        return false;
                    }
                }
            }
        }
        return true;
    }

    private boolean containsSuspiciousContent(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        
        for (Pattern pattern : SUSPICIOUS_PATTERNS) {
            if (pattern.matcher(input).find()) {
                return true;
            }
        }
        return false;
    }

    private boolean containsSQLInjection(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        
        for (Pattern pattern : SQL_PATTERNS) {
            if (pattern.matcher(input).find()) {
                return true;
            }
        }
        return false;
    }

    private void abortRequest(ContainerRequestContext requestContext, String message) {
        logger.error("Request blocked: {}, URI: {}, IP: {}", 
                    message,
                    requestContext.getUriInfo().getRequestUri(),
                    requestContext.getHeaderString("X-Forwarded-For"));
        
        requestContext.abortWith(
            Response.status(Response.Status.BAD_REQUEST)
                .entity("{\"error\":\"invalid_request\",\"error_description\":\"Request contains invalid data\"}")
                .build()
        );
    }

    /**
     * Encode HTML entities for safe output (use when displaying user input)
     * This should be used in your presentation layer, not here
     */
    public static String encodeForHTML(String input) {
        if (input == null) return null;
        
        return input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;")
            .replace("/", "&#x2F;");
    }
}