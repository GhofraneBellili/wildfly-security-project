package xyz.kaaniche.phoenix.security.utils;

import org.apache.commons.codec.binary.Base64;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * PKCE (Proof Key for Code Exchange) utility for OAuth 2.0
 */
public class PKCEUtil {
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64 base64 = new Base64(true); // URL-safe

    /**
     * Generate a random code verifier
     * @return Base64 URL-encoded random string
     */
    public static String generateCodeVerifier() {
        byte[] codeVerifier = new byte[32];
        secureRandom.nextBytes(codeVerifier);
        return base64.encodeAsString(codeVerifier)
                .replace("=", "")
                .replace("+", "-")
                .replace("/", "_");
    }

    /**
     * Generate code challenge from verifier using S256 method
     * @param codeVerifier The code verifier
     * @return Base64 URL-encoded SHA-256 hash of the verifier
     */
    public static String generateCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return base64.encodeAsString(hash)
                    .replace("=", "")
                    .replace("+", "-")
                    .replace("/", "_");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
