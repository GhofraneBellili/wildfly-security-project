package xyz.kaaniche.phoenix.iam;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.Dependent;
import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.inject.Disposes;
import jakarta.enterprise.inject.Produces;
import jakarta.enterprise.inject.spi.InjectionPoint;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.util.logging.Logger;

/**
 * Configuration principale de l'application IAM
 * Version sécurisée avec injection correcte des dépendances
 */
@ApplicationPath("/rest-iam")
public class IamApplication extends Application {

    /**
     * Classe de configuration CDI sécurisée
     */
    @ApplicationScoped
    public static final class CDIConfigurator {

        @PersistenceContext(unitName = "default")
        private EntityManager entityManager;

        @Inject
        @ConfigProperty(name = "jwt.realm")
        private String realm;

        @Inject
        @ConfigProperty(name = "jwt.secret")
        private String jwtSecret;

        @Inject
        @ConfigProperty(name = "jwt.issuer")
        private String jwtIssuer;

        @Inject
        @ConfigProperty(name = "jwt.expiration.hours", defaultValue = "24")
        private Integer jwtExpirationHours;

        @Inject
        @ConfigProperty(name = "security.audit.enabled", defaultValue = "true")
        private Boolean auditEnabled;

        @Inject
        @ConfigProperty(name = "security.mfa.enabled", defaultValue = "false")
        private Boolean mfaEnabled;

        /**
         * Produit un EntityManager thread-safe par requête
         * CORRECTION: Utilisation de RequestScoped au lieu de ApplicationScoped
         */
        @Produces
        @RequestScoped
        public EntityManager getEntityManager() {
            if (entityManager == null || !entityManager.isOpen()) {
                throw new IllegalStateException("EntityManager is not available");
            }
            return entityManager;
        }

        /**
         * Produit le realm JWT
         */
        @Produces
        @Named(value = "realm")
        @ApplicationScoped
        public String getRealm() {
            validateConfiguration(realm, "jwt.realm");
            return realm;
        }

        /**
         * Produit le secret JWT (à ne jamais logger!)
         */
        @Produces
        @Named(value = "jwtSecret")
        @ApplicationScoped
        public String getJwtSecret() {
            validateConfiguration(jwtSecret, "jwt.secret");

            // Vérifier la force du secret
            if (jwtSecret.length() < 32) {
                throw new IllegalStateException(
                        "JWT secret must be at least 32 characters long for security"
                );
            }

            return jwtSecret;
        }

        /**
         * Produit l'issuer JWT
         */
        @Produces
        @Named(value = "jwtIssuer")
        @ApplicationScoped
        public String getJwtIssuer() {
            validateConfiguration(jwtIssuer, "jwt.issuer");
            return jwtIssuer;
        }

        /**
         * Produit la durée d'expiration des tokens JWT
         */
        @Produces
        @Named(value = "jwtExpirationHours")
        @ApplicationScoped
        public Integer getJwtExpirationHours() {
            if (jwtExpirationHours == null || jwtExpirationHours < 1 || jwtExpirationHours > 168) {
                throw new IllegalStateException(
                        "JWT expiration hours must be between 1 and 168 (1 week)"
                );
            }
            return jwtExpirationHours;
        }

        /**
         * Produit le flag d'activation de l'audit
         */
        @Produces
        @Named(value = "auditEnabled")
        @ApplicationScoped
        public Boolean getAuditEnabled() {
            return auditEnabled;
        }

        /**
         * Produit le flag d'activation de MFA
         */
        @Produces
        @Named(value = "mfaEnabled")
        @ApplicationScoped
        public Boolean getMfaEnabled() {
            return mfaEnabled;
        }

        /**
         * Produit un Logger contextualisé par classe
         */
        @Produces
        @Dependent
        public Logger getLogger(InjectionPoint injectionPoint) {
            if (injectionPoint == null || injectionPoint.getBean() == null) {
                return Logger.getLogger(IamApplication.class.getName());
            }

            Class<?> clazz = injectionPoint.getBean().getBeanClass();
            Logger logger = Logger.getLogger(clazz.getName());

            // Configuration du niveau de log
            configureLoggerLevel(logger);

            return logger;
        }

        /**
         * Dispose un Logger correctement
         */
        public void disposeLogger(@Disposes Logger logger) {
            if (logger != null) {
                logger.fine("Logger disposed for: " + logger.getName());
            }
        }

        /**
         * Valide qu'une propriété de configuration n'est pas vide
         */
        private void validateConfiguration(String value, String propertyName) {
            if (value == null || value.trim().isEmpty()) {
                throw new IllegalStateException(
                        String.format("Configuration property '%s' must be set", propertyName)
                );
            }
        }

        /**
         * Configure le niveau de log en fonction de l'environnement
         */
        private void configureLoggerLevel(Logger logger) {
            // En production, on veut des logs plus restrictifs
            String env = System.getProperty("app.environment", "development");

            if ("production".equalsIgnoreCase(env)) {
                logger.setLevel(java.util.logging.Level.INFO);
            } else {
                logger.setLevel(java.util.logging.Level.FINE);
            }
        }
    }

    /**
     * Configuration de sécurité supplémentaire
     */
    @ApplicationScoped
    public static class SecurityConfiguration {

        @Inject
        private Logger logger;

        /**
         * Initialise les paramètres de sécurité au démarrage
         */
        public void initializeSecurity() {
            logger.info("Initializing IAM security configuration...");

            // Vérifier les propriétés de sécurité critiques
            verifySecurityProperties();

            // Logger les paramètres de sécurité (sans les secrets!)
            logSecuritySettings();

            logger.info("IAM security configuration initialized successfully");
        }

        /**
         * Vérifie que toutes les propriétés de sécurité sont correctement configurées
         */
        private void verifySecurityProperties() {
            List<String> requiredProperties = Arrays.asList(
                "jwt.realm",
                "jwt.secret",
                "jwt.issuer",
                "argon2.saltLength",
                "argon2.hashLength",
                "argon2.iterations",
                "argon2.memory",
                "argon2.threads"
            );

            List<String> missingProperties = new ArrayList<>();

            for (String prop : requiredProperties) {
                try {
                    String value = ConfigProvider.getConfig().getValue(prop, String.class);
                    if (value == null || value.trim().isEmpty()) {
                        missingProperties.add(prop);
                    }
                } catch (Exception e) {
                    missingProperties.add(prop);
                }
            }

            if (!missingProperties.isEmpty()) {
                throw new IllegalStateException(
                        "Missing required security properties: " + String.join(", ", missingProperties)
                );
            }
        }

        /**
         * Log les paramètres de sécurité (sans révéler les secrets)
         */
        private void logSecuritySettings() {
            Config config = ConfigProvider.getConfig();

            logger.info("Security Settings:");
            logger.info("  - Argon2 iterations: " + config.getValue("argon2.iterations", String.class));
            logger.info("  - Argon2 memory: " + config.getValue("argon2.memory", String.class));
            logger.info("  - Argon2 threads: " + config.getValue("argon2.threads", String.class));
            logger.info("  - JWT expiration: " +
                    config.getOptionalValue("jwt.expiration.hours", String.class).orElse("24") + " hours");
            logger.info("  - Audit enabled: " +
                    config.getOptionalValue("security.audit.enabled", String.class).orElse("true"));
            logger.info("  - MFA enabled: " +
                    config.getOptionalValue("security.mfa.enabled", String.class).orElse("false"));

            // NE JAMAIS logger les secrets!
            logger.info("  - JWT secret: [REDACTED]");
        }
    }
}