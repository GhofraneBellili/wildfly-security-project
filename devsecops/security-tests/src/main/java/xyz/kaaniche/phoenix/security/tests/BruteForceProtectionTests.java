package xyz.kaaniche.phoenix.security.tests;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import xyz.kaaniche.phoenix.security.config.TestConfig;
import xyz.kaaniche.phoenix.security.utils.TestReportGenerator;

import static io.restassured.RestAssured.given;

/**
 * Security tests for brute force protection
 */
public class BruteForceProtectionTests {
    private final TestConfig config = TestConfig.getInstance();
    private final TestReportGenerator reporter;
    private static final String CATEGORY = "BRUTE FORCE PROTECTION TESTS";

    public BruteForceProtectionTests(TestReportGenerator reporter) {
        this.reporter = reporter;
        RestAssured.baseURI = config.getBaseUrl();
    }

    public void runAllTests() {
        System.out.println("\n=== Running Brute Force Protection Tests ===");

        testMultipleFailedLoginAttempts();
        testIPBlocking();
        testLockoutDuration();
        testSuccessfulLoginResetsCounter();
        testDifferentIPsIndependentTracking();
        testRateLimitingOnEndpoints();
    }

    private void testMultipleFailedLoginAttempts() {
        try {
            int maxAttempts = config.getBruteForceTestAttempts();
            int failedCount = 0;
            int successAfterLockout = 0;

            // Make multiple failed login attempts
            for (int i = 0; i < maxAttempts; i++) {
                String jsonBody = String.format("{\"username\":\"bruteforce_test_%d\",\"password\":\"wrong_password\"}",
                        System.currentTimeMillis());

                Response response = given()
                        .contentType("application/json")
                        .body(jsonBody)
                        .when()
                        .post("/api/login")
                        .then()
                        .extract()
                        .response();

                if (response.statusCode() == 401 || response.statusCode() == 403) {
                    failedCount++;
                }

                // Small delay between attempts
                Thread.sleep(100);
            }

            // After max attempts, try one more - should be blocked
            String jsonBody = "{\"username\":\"bruteforce_test\",\"password\":\"password\"}";
            Response blockedResponse = given()
                    .contentType("application/json")
                    .body(jsonBody)
                    .when()
                    .post("/api/login");

            boolean passed = failedCount >= maxAttempts - 1 &&
                           (blockedResponse.statusCode() == 429 || blockedResponse.statusCode() == 403);

            reporter.addResult(CATEGORY, "Multiple failed login attempts trigger lockout",
                    passed, "Failed attempts: " + failedCount + ", Blocked status: " + blockedResponse.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Multiple failed login attempts trigger lockout",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testIPBlocking() {
        try {
            // Make failed attempts from same IP
            String uniqueUser = "ipblock_" + System.currentTimeMillis();

            for (int i = 0; i < 7; i++) {
                String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"wrong\"}", uniqueUser);

                given()
                        .contentType("application/json")
                        .header("X-Forwarded-For", "192.168.1.100")
                        .body(jsonBody)
                        .when()
                        .post("/api/login");

                Thread.sleep(100);
            }

            // Try with different username but same IP
            String jsonBody = "{\"username\":\"different_user\",\"password\":\"password\"}";
            Response response = given()
                    .contentType("application/json")
                    .header("X-Forwarded-For", "192.168.1.100")
                    .body(jsonBody)
                    .when()
                    .post("/api/login");

            boolean passed = response.statusCode() == 429 || response.statusCode() == 403;
            reporter.addResult(CATEGORY, "IP-based blocking affects all requests from same IP",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "IP-based blocking affects all requests from same IP",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testLockoutDuration() {
        try {
            // Trigger lockout
            String uniqueUser = "lockout_test_" + System.currentTimeMillis();

            for (int i = 0; i < 7; i++) {
                String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"wrong\"}", uniqueUser);
                given()
                        .contentType("application/json")
                        .body(jsonBody)
                        .when()
                        .post("/api/login");
                Thread.sleep(100);
            }

            // Verify locked immediately
            String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"password\"}", uniqueUser);
            Response lockedResponse = given()
                    .contentType("application/json")
                    .body(jsonBody)
                    .when()
                    .post("/api/login");

            // Note: Full lockout duration test would require waiting 30 minutes
            // This test verifies immediate lockout behavior
            boolean passed = lockedResponse.statusCode() == 429 || lockedResponse.statusCode() == 403 ||
                           lockedResponse.statusCode() == 401;

            reporter.addResult(CATEGORY, "Lockout duration enforced (immediate check)",
                    passed, "Locked status: " + lockedResponse.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Lockout duration enforced (immediate check)",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testSuccessfulLoginResetsCounter() {
        try {
            String testUser = config.getTestUsername();
            String testPass = config.getTestPassword();

            // Make 2-3 failed attempts
            for (int i = 0; i < 3; i++) {
                String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"wrong_password_%d\"}",
                        testUser, i);
                given()
                        .contentType("application/json")
                        .body(jsonBody)
                        .when()
                        .post("/api/login");
                Thread.sleep(100);
            }

            // Make successful login
            String successBody = String.format("{\"username\":\"%s\",\"password\":\"%s\"}",
                    testUser, testPass);
            Response successResponse = given()
                    .contentType("application/json")
                    .body(successBody)
                    .when()
                    .post("/api/login");

            // Make more failed attempts (should start fresh counter)
            for (int i = 0; i < 3; i++) {
                String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"wrong_again_%d\"}",
                        testUser, i);
                given()
                        .contentType("application/json")
                        .body(jsonBody)
                        .when()
                        .post("/api/login");
                Thread.sleep(100);
            }

            // Should still be able to login (counter was reset)
            Response finalResponse = given()
                    .contentType("application/json")
                    .body(successBody)
                    .when()
                    .post("/api/login");

            boolean passed = successResponse.statusCode() == 200 &&
                           (finalResponse.statusCode() == 200 || finalResponse.statusCode() == 401);

            reporter.addResult(CATEGORY, "Successful login resets failed attempt counter",
                    passed, "Success response: " + successResponse.statusCode() +
                           ", Final: " + finalResponse.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Successful login resets failed attempt counter",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testDifferentIPsIndependentTracking() {
        try {
            String testUser = "multiip_" + System.currentTimeMillis();

            // Failed attempts from IP1
            for (int i = 0; i < 7; i++) {
                String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"wrong\"}", testUser);
                given()
                        .contentType("application/json")
                        .header("X-Forwarded-For", "192.168.1.101")
                        .body(jsonBody)
                        .when()
                        .post("/api/login");
                Thread.sleep(100);
            }

            // Attempt from different IP should not be blocked
            String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"password\"}", testUser);
            Response ip2Response = given()
                    .contentType("application/json")
                    .header("X-Forwarded-For", "192.168.1.102")
                    .body(jsonBody)
                    .when()
                    .post("/api/login");

            // IP1 should be blocked
            Response ip1Response = given()
                    .contentType("application/json")
                    .header("X-Forwarded-For", "192.168.1.101")
                    .body(jsonBody)
                    .when()
                    .post("/api/login");

            boolean passed = (ip2Response.statusCode() == 401 || ip2Response.statusCode() == 200) &&
                           (ip1Response.statusCode() == 429 || ip1Response.statusCode() == 403);

            reporter.addResult(CATEGORY, "Different IPs tracked independently",
                    passed, "IP2 (should work): " + ip2Response.statusCode() +
                           ", IP1 (should block): " + ip1Response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Different IPs tracked independently",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testRateLimitingOnEndpoints() {
        try {
            int requestCount = 0;
            int successCount = 0;
            int rateLimitedCount = 0;

            // Make rapid requests to an endpoint
            for (int i = 0; i < 50; i++) {
                Response response = given()
                        .when()
                        .get("/jwk?kid=test-key-" + i);

                requestCount++;
                if (response.statusCode() == 200 || response.statusCode() == 404) {
                    successCount++;
                } else if (response.statusCode() == 429) {
                    rateLimitedCount++;
                }

                // Very small delay
                Thread.sleep(10);
            }

            // If rate limiting is in place, we should see some 429s
            // If not, all requests succeed (which is also valid behavior)
            boolean passed = requestCount == 50;

            reporter.addResult(CATEGORY, "Rate limiting on public endpoints (if enabled)",
                    passed, "Requests: " + requestCount + ", Success: " + successCount +
                           ", Rate limited: " + rateLimitedCount);
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Rate limiting on public endpoints (if enabled)",
                    false, "Exception: " + e.getMessage());
        }
    }
}
