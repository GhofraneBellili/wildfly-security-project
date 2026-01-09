package xyz.kaaniche.phoenix.iam.security;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import jakarta.security.enterprise.identitystore.PasswordHash;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Utilitaire de hachage de mots de passe avec Argon2
 * Version sécurisée avec validation de la force des mots de passe
 */
public class Argon2Utility implements PasswordHash {
    private static final Logger logger = Logger.getLogger(Argon2Utility.class.getName());
    private static final Config config = ConfigProvider.getConfig();

    // Configuration Argon2
    private static final int saltLength = config.getValue("argon2.saltLength", Integer.class);
    private static final int hashLength = config.getValue("argon2.hashLength", Integer.class);
    private static final Argon2 argon2 = Argon2Factory.create(
            Argon2Factory.Argon2Types.ARGON2id,
            saltLength,
            hashLength
    );
    private static final int iterations = config.getValue("argon2.iterations", Integer.class);
    private static final int memory = config.getValue("argon2.memory", Integer.class);
    private static final int threads = config.getValue("argon2.threads", Integer.class);

    // Politique de mots de passe
    private static final int MIN_PASSWORD_LENGTH = config.getOptionalValue("password.minLength", Integer.class).orElse(12);
    private static final int MAX_PASSWORD_LENGTH = config.getOptionalValue("password.maxLength", Integer.class).orElse(128);
    private static final boolean REQUIRE_UPPERCASE = config.getOptionalValue("password.requireUppercase", Boolean.class).orElse(true);
    private static final boolean REQUIRE_LOWERCASE = config.getOptionalValue("password.requireLowercase", Boolean.class).orElse(true);
    private static final boolean REQUIRE_DIGIT = config.getOptionalValue("password.requireDigit", Boolean.class).orElse(true);
    private static final boolean REQUIRE_SPECIAL = config.getOptionalValue("password.requireSpecial", Boolean.class).orElse(true);

    // Patterns de validation
    private static final Pattern UPPERCASE_PATTERN = Pattern.compile("[A-Z]");
    private static final Pattern LOWERCASE_PATTERN = Pattern.compile("[a-z]");
    private static final Pattern DIGIT_PATTERN = Pattern.compile("[0-9]");
    private static final Pattern SPECIAL_PATTERN = Pattern.compile("[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]");

    /**
     * Hache un mot de passe après validation de sa force
     * @param clientHash Le mot de passe en clair
     * @return Le hash du mot de passe
     * @throws IllegalArgumentException si le mot de passe ne respecte pas la politique
     */
    public static String hash(char[] clientHash) {
        validatePasswordStrength(clientHash);
        try {
            String hashedPassword = argon2.hash(iterations, memory, threads, clientHash);
            logger.info("Password successfully hashed");
            return hashedPassword;
        } catch (Exception e) {
            logger.severe("Error during password hashing: " + e.getMessage());
            throw new RuntimeException("Failed to hash password", e);
        } finally {
            argon2.wipeArray(clientHash);
        }
    }

    /**
     * Vérifie un mot de passe contre son hash
     * @param serverHash Le hash stocké
     * @param clientHash Le mot de passe à vérifier
     * @return true si le mot de passe correspond
     */
    public static boolean check(String serverHash, char[] clientHash) {
        if (serverHash == null || serverHash.trim().isEmpty()) {
            logger.warning("Attempted to verify against null or empty hash");
            return false;
        }

        if (clientHash == null || clientHash.length == 0) {
            logger.warning("Attempted to verify null or empty password");
            return false;
        }

        try {
            boolean isValid = argon2.verify(serverHash, clientHash);
            if (!isValid) {
                logger.warning("Password verification failed");
            }
            return isValid;
        } catch (Exception e) {
            logger.severe("Error during password verification: " + e.getMessage());
            return false;
        } finally {
            argon2.wipeArray(clientHash);
        }
    }

    /**
     * Valide la force du mot de passe selon la politique définie
     * @param password Le mot de passe à valider
     * @throws IllegalArgumentException si le mot de passe ne respecte pas la politique
     */
    private static void validatePasswordStrength(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }

        if (password.length < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("Password must be at least %d characters long", MIN_PASSWORD_LENGTH)
            );
        }

        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("Password must not exceed %d characters", MAX_PASSWORD_LENGTH)
            );
        }

        String passwordStr = new String(password);

        if (REQUIRE_UPPERCASE && !UPPERCASE_PATTERN.matcher(passwordStr).find()) {
            throw new IllegalArgumentException("Password must contain at least one uppercase letter");
        }

        if (REQUIRE_LOWERCASE && !LOWERCASE_PATTERN.matcher(passwordStr).find()) {
            throw new IllegalArgumentException("Password must contain at least one lowercase letter");
        }

        if (REQUIRE_DIGIT && !DIGIT_PATTERN.matcher(passwordStr).find()) {
            throw new IllegalArgumentException("Password must contain at least one digit");
        }

        if (REQUIRE_SPECIAL && !SPECIAL_PATTERN.matcher(passwordStr).find()) {
            throw new IllegalArgumentException("Password must contain at least one special character");
        }

        // Vérifier les mots de passe communs (liste simple pour l'exemple)
        if (isCommonPassword(passwordStr)) {
            throw new IllegalArgumentException("Password is too common. Please choose a stronger password");
        }
    }

    /**
     * Vérifie si le mot de passe fait partie des mots de passe couramment utilisés
     * @param password Le mot de passe à vérifier
     * @return true si le mot de passe est trop commun
     */
    private static boolean isCommonPassword(String password) {
        String lowerPassword = password.toLowerCase();
        String[] commonPasswords = {
            "password", "123456", "12345678", "qwerty", "abc123",
            "monkey", "letmein", "trustno1", "dragon", "baseball",
            "iloveyou", "master", "sunshine", "ashley", "bailey"
        };

        for (String common : commonPasswords) {
            if (lowerPassword.contains(common)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String generate(char[] password) {
        return hash(password);
    }

    @Override
    public boolean verify(char[] password, String hashedPassword) {
        return check(hashedPassword, password);
    }
}