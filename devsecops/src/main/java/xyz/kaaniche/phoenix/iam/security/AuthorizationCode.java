package xyz.kaaniche.phoenix.iam.security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public record AuthorizationCode(String tenantName, String identityUsername,
                                String approvedScopes, Long expirationDate,
                                String redirectUri){
    
    private static final Logger logger = LoggerFactory.getLogger(AuthorizationCode.class);
    private static final String codePrefix = "urn:phoenix:code:";

    public String getCode(String codeChallenge) throws Exception {
        String code = UUID.randomUUID().toString();
        String payload = Base64.getEncoder().withoutPadding().encodeToString(
            (tenantName + ":" + identityUsername + ":" + approvedScopes + ":" + 
             expirationDate + ":" + redirectUri).getBytes(StandardCharsets.UTF_8)
        );
        
        String fullCode = codePrefix + code + ":" + payload;
        
        // Get key from secure storage
        SecretKey key = SecureKeyManager.getAuthorizationCodeKey();
        
        // Encrypt the code challenge
        byte[] encryptedChallenge = ChaCha20Poly1305.encrypt(
            codeChallenge.getBytes(StandardCharsets.UTF_8), 
            key
        );
        
        return fullCode + ":" + Base64.getEncoder().withoutPadding().encodeToString(encryptedChallenge);
    }

    public static AuthorizationCode decode(String authorizationCode, String codeVerifier) throws Exception {
        try {
            int pos = authorizationCode.lastIndexOf(':');
            if (pos == -1) {
                logger.warn("Invalid authorization code format: missing separator");
                return null;
            }
            
            String code = authorizationCode.substring(0, pos);
            String cipherCodeChallenge = authorizationCode.substring(pos + 1);
            
            // Get key from secure storage
            SecretKey key = SecureKeyManager.getAuthorizationCodeKey();
            
            // Hash the code verifier
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(codeVerifier.getBytes(StandardCharsets.UTF_8));
            byte[] expectedHash = digest.digest();
            String expected = Base64.getEncoder().withoutPadding().encodeToString(expectedHash);
            
            // Decrypt the stored code challenge
            byte[] decryptedBytes = ChaCha20Poly1305.decrypt(
                Base64.getDecoder().decode(cipherCodeChallenge), 
                key
            );
            String decryptedChallenge = new String(decryptedBytes, StandardCharsets.UTF_8);
            
            // CRITICAL: Use constant-time comparison to prevent timing attacks
            if (!constantTimeEquals(expected, decryptedChallenge)) {
                // DO NOT log the actual values - security risk
                logger.warn("Code challenge verification failed");
                return null;
            }
            
            // Parse the code
            code = code.substring(codePrefix.length());
            pos = code.lastIndexOf(':');
            if (pos == -1) {
                logger.warn("Invalid code format after prefix");
                return null;
            }
            
            code = new String(Base64.getDecoder().decode(code.substring(pos + 1)), StandardCharsets.UTF_8);
            String[] attributes = code.split(":");
            
            if (attributes.length < 6) {
                logger.warn("Invalid number of attributes in code");
                return null;
            }
            
            return new AuthorizationCode(
                attributes[0],
                attributes[1],
                attributes[2],
                Long.parseLong(attributes[3]),
                attributes[4] + ":" + attributes[5]
            );
        } catch (Exception e) {
            logger.error("Error decoding authorization code", e);
            return null;
        }
    }
    
    /**
     * Constant-time string comparison to prevent timing attacks
     */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        
        return MessageDigest.isEqual(aBytes, bBytes);
    }

    private static class ChaCha20Poly1305 {
        private static final String ENCRYPT_ALGO = "ChaCha20-Poly1305";
        private static final int NONCE_LEN = 12; // 96 bits, 12 bytes

        public static byte[] encrypt(byte[] pText, SecretKey key) throws Exception {
            return encrypt(pText, key, getNonce());
        }

        public static byte[] encrypt(byte[] pText, SecretKey key, byte[] nonce) throws Exception {
            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
            IvParameterSpec iv = new IvParameterSpec(nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encryptedText = cipher.doFinal(pText);

            // Append nonce to the encrypted text
            return ByteBuffer.allocate(encryptedText.length + NONCE_LEN)
                    .put(encryptedText)
                    .put(nonce)
                    .array();
        }

        public static byte[] decrypt(byte[] cText, SecretKey key) throws Exception {
            ByteBuffer bb = ByteBuffer.wrap(cText);

            // Split cText to get the appended nonce
            byte[] encryptedText = new byte[cText.length - NONCE_LEN];
            byte[] nonce = new byte[NONCE_LEN];
            bb.get(encryptedText);
            bb.get(nonce);

            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
            IvParameterSpec iv = new IvParameterSpec(nonce);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);

            return cipher.doFinal(encryptedText);
        }

        private static byte[] getNonce() {
            byte[] newNonce = new byte[NONCE_LEN];
            new SecureRandom().nextBytes(newNonce);
            return newNonce;
        }
    }
}