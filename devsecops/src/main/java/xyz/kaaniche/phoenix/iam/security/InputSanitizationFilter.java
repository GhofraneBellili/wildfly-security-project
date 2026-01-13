package xyz.kaaniche.phoenix.iam.security;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.ext.Provider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Provider
@PreMatching
public class InputSanitizationFilter implements ContainerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(InputSanitizationFilter.class);

    // Basic XSS patterns to sanitize
    private static final String[] XSS_PATTERNS = {
        "<script[^>]*>.*?</script>",
        "<iframe[^>]*>.*?</iframe>",
        "<object[^>]*>.*?</object>",
        "<embed[^>]*>.*?</embed>",
        "javascript:",
        "vbscript:",
        "onload=",
        "onerror=",
        "onclick=",
        "onmouseover="
    };

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        // Sanitize query parameters
        MultivaluedMap<String, String> queryParams = requestContext.getUriInfo().getQueryParameters();
        sanitizeParameters(queryParams);

        // Sanitize headers (basic sanitization)
        MultivaluedMap<String, String> headers = requestContext.getHeaders();
        sanitizeParameters(headers);

        // Note: For POST/PUT body sanitization, would need a custom MessageBodyReader
        // This is a basic implementation focusing on query params and headers
    }

    private void sanitizeParameters(MultivaluedMap<String, String> parameters) {
        for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
            List<String> values = entry.getValue();
            for (int i = 0; i < values.size(); i++) {
                String originalValue = values.get(i);
                String sanitizedValue = sanitizeInput(originalValue);
                if (!originalValue.equals(sanitizedValue)) {
                    logger.warn("Potentially malicious input detected and sanitized in parameter: {}", entry.getKey());
                    values.set(i, sanitizedValue);
                }
            }
        }
    }

    private String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }

        String sanitized = input;

        // Remove or escape potentially dangerous patterns
        for (String pattern : XSS_PATTERNS) {
            sanitized = sanitized.replaceAll("(?i)" + pattern, "");
        }

        // Basic HTML entity encoding for common characters
        sanitized = sanitized.replace("&", "&amp;")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                            .replace("\"", "&quot;")
                            .replace("'", "&#x27;")
                            .replace("/", "&#x2F;");

        return sanitized;
    }
}
