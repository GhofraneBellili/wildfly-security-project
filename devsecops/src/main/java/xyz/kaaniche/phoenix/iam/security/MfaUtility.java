package xyz.kaaniche.phoenix.iam.security;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

public class MfaUtility {

    private static final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private static final TimeProvider timeProvider = new SystemTimeProvider();
    private static final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    private static final CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

    public static String generateSecret() {
        return secretGenerator.generate();
    }

    public static boolean verifyCode(String secret, String code) {
        return verifier.isValidCode(secret, code);
    }

    public static byte[] generateQrCode(String secret, String username, String issuer) {
        QrData data = new QrData.Builder()
                .label(username)
                .secret(secret)
                .issuer(issuer)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

        QrGenerator generator = new ZxingPngQrGenerator();
        try {
            return generator.generate(data);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate QR code", e);
        }
    }
}
