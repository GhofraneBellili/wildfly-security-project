package xyz.kaaniche.phoenix.security.config;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * Configuration for security testing
 */
public class TestConfig {
    private static TestConfig instance;
    private Properties properties;

    private TestConfig() {
        properties = new Properties();
        loadDefaultConfig();
    }

    public static TestConfig getInstance() {
        if (instance == null) {
            instance = new TestConfig();
        }
        return instance;
    }

    private void loadDefaultConfig() {
        // Default configuration
        properties.setProperty("iam.base.url", "http://localhost:8080");
        properties.setProperty("test.client.id", "test-client");
        properties.setProperty("test.client.secret", "test-secret");
        properties.setProperty("test.redirect.uri", "http://localhost:3000/callback");
        properties.setProperty("test.username", "testuser");
        properties.setProperty("test.password", "Test@123456");
        properties.setProperty("test.admin.username", "admin");
        properties.setProperty("test.admin.password", "Admin@123456");
        properties.setProperty("test.email", "testuser@example.com");
        properties.setProperty("test.scope", "openid profile email");
        properties.setProperty("brute.force.test.attempts", "6");

        // Try to load from file if exists
        try (FileInputStream fis = new FileInputStream("security-test.properties")) {
            properties.load(fis);
        } catch (IOException e) {
            // Use defaults if file not found
            System.out.println("Using default configuration. Create security-test.properties to customize.");
        }
    }

    public String getBaseUrl() {
        return properties.getProperty("iam.base.url");
    }

    public String getClientId() {
        return properties.getProperty("test.client.id");
    }

    public String getClientSecret() {
        return properties.getProperty("test.client.secret");
    }

    public String getRedirectUri() {
        return properties.getProperty("test.redirect.uri");
    }

    public String getTestUsername() {
        return properties.getProperty("test.username");
    }

    public String getTestPassword() {
        return properties.getProperty("test.password");
    }

    public String getAdminUsername() {
        return properties.getProperty("test.admin.username");
    }

    public String getAdminPassword() {
        return properties.getProperty("test.admin.password");
    }

    public String getTestEmail() {
        return properties.getProperty("test.email");
    }

    public String getTestScope() {
        return properties.getProperty("test.scope");
    }

    public int getBruteForceTestAttempts() {
        return Integer.parseInt(properties.getProperty("brute.force.test.attempts", "6"));
    }

    public String getProperty(String key) {
        return properties.getProperty(key);
    }
}
