package xyz.kaaniche.phoenix.iam.security;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;

public record AuthorizationCode(String tenantName, String identityUsername,
                                String approvedScopes, Long expirationDate,
                                String redirectUri){
    private static final SecretKey key;

    private static final String codePrefix = "urn:phoenix:code:";

    static {
        try {
            Config config = ConfigProvider.getConfig();
            try {
                String base64Key = config.getOptionalValue("authorization.code.key", String.class).orElse(null);
                if (base64Key != null && !base64Key.isEmpty()) {
                    byte[] decoded = Base64.getDecoder().decode(base64Key);
                    key = new SecretKeySpec(decoded, "ChaCha20");
                } else {
                    // fallback to generated key (not ideal for multi-instance deployments)
                    key = KeyGenerator.getInstance("CHACHA20").generateKey();
                }
            } catch (Exception ex) {
                // if config lookup fails, generate a key to keep backward compatibility
                key = KeyGenerator.getInstance("CHACHA20").generateKey();
            }
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public String getCode(String codeChallenge) throws Exception {
        String code = UUID.randomUUID().toString();
        String payload = String.join(":",
                tenantName,
                identityUsername,
                approvedScopes,
                Long.toString(expirationDate),
                redirectUri,
                codeChallenge
        );
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = (codePrefix + code).getBytes(StandardCharsets.UTF_8);
        byte[] cipher = ChaCha20Poly1305.encrypt(payloadBytes, key, ChaCha20Poly1305.getNonce(), associatedData);
        return codePrefix + code + ":" + Base64.getUrlEncoder().withoutPadding().encodeToString(cipher);
    }

    public static AuthorizationCode decode(String authorizationCode, String codeVerifier) throws Exception {
        int pos = authorizationCode.lastIndexOf(':');
        if (pos < 0) return null;
        String codePart = authorizationCode.substring(0, pos);
        String cipherB64 = authorizationCode.substring(pos + 1);
        byte[] cipher = Base64.getUrlDecoder().decode(cipherB64);
        byte[] associatedData = codePart.getBytes(StandardCharsets.UTF_8);
        byte[] plain = ChaCha20Poly1305.decrypt(cipher, key, associatedData);
        String payload = new String(plain, StandardCharsets.UTF_8);
        String[] attributes = payload.split(":", 6);
        if (attributes.length < 6) return null;

        // verify PKCE S256: stored challenge is attributes[5]
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] computed = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
        String computedB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(computed);
        byte[] storedBytes = attributes[5].getBytes(StandardCharsets.UTF_8);
        byte[] computedBytes = computedB64.getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(storedBytes, computedBytes)) {
            return null;
        }
        return new AuthorizationCode(attributes[0], attributes[1], attributes[2],
                Long.parseLong(attributes[3]), attributes[4]);
    }
    private static class ChaCha20Poly1305 {

        private static final String ENCRYPT_ALGO = "ChaCha20-Poly1305";
        private static final int NONCE_LEN = 12; // 96 bits, 12 bytes

        // if no nonce, generate a random 12 bytes nonce
        public static byte[] encrypt(byte[] pText, SecretKey key, byte[] nonce, byte[] associatedData) throws Exception {
            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
            IvParameterSpec iv = new IvParameterSpec(nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            if (associatedData != null) cipher.updateAAD(associatedData);
            byte[] encryptedText = cipher.doFinal(pText);
            // append nonce to the encrypted text
            byte[] output = ByteBuffer.allocate(encryptedText.length + NONCE_LEN)
                    .put(encryptedText)
                    .put(nonce)
                    .array();
            return output;
        }

        // helper variant used in getCode
        public static byte[] encrypt(byte[] pText, SecretKey key, byte[] nonce) throws Exception {
            return encrypt(pText, key, nonce, null);
        }

        public static byte[] decrypt(byte[] cText, SecretKey key, byte[] associatedData) throws Exception {
            ByteBuffer bb = ByteBuffer.wrap(cText);
            byte[] encryptedText = new byte[cText.length - NONCE_LEN];
            byte[] nonce = new byte[NONCE_LEN];
            bb.get(encryptedText);
            bb.get(nonce);
            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
            IvParameterSpec iv = new IvParameterSpec(nonce);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            if (associatedData != null) cipher.updateAAD(associatedData);
            byte[] output = cipher.doFinal(encryptedText);
            return output;
        }

        // helper variant used in decode
        public static byte[] decrypt(byte[] cText, SecretKey key) throws Exception {
            return decrypt(cText, key, null);
        }

        // 96-bit nonce (12 bytes)
        public static byte[] getNonce() {
            byte[] newNonce = new byte[12];
            new SecureRandom().nextBytes(newNonce);
            return newNonce;
        }

    }

}