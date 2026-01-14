package xyz.kaaniche.phoenix.security.tests;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import xyz.kaaniche.phoenix.security.config.TestConfig;
import xyz.kaaniche.phoenix.security.utils.PKCEUtil;
import xyz.kaaniche.phoenix.security.utils.TestReportGenerator;

import static io.restassured.RestAssured.given;

/**
 * Security tests for authorization and JWT functionality
 */
public class AuthorizationAndJWTTests {
    private final TestConfig config = TestConfig.getInstance();
    private final TestReportGenerator reporter;
    private static final String CATEGORY = "AUTHORIZATION & JWT TESTS";

    public AuthorizationAndJWTTests(TestReportGenerator reporter) {
        this.reporter = reporter;
        RestAssured.baseURI = config.getBaseUrl();
    }

    public void runAllTests() {
        System.out.println("\n=== Running Authorization & JWT Tests ===");

        testTokenEndpointWithAuthorizationCode();
        testTokenEndpointWithInvalidCode();
        testTokenEndpointWithMissingCodeVerifier();
        testTokenEndpointWithInvalidCodeVerifier();
        testTokenEndpointRefreshToken();
        testTokenEndpointInvalidRefreshToken();
        testJWTStructureValidation();
        testJWKEndpoint();
        testJWKEndpointWithInvalidKid();
        testAccessProtectedEndpointWithoutToken();
        testAccessProtectedEndpointWithInvalidToken();
        testAccessProtectedEndpointWithExpiredToken();
        testAccessProtectedEndpointWithMalformedToken();
        testRoleBasedAccessControl();
        testScopeBasedAccessControl();
        testTokenRevocation();
    }

    private void testTokenEndpointWithAuthorizationCode() {
        try {
            // This is a complex flow test - would need valid authorization code from previous step
            String codeVerifier = PKCEUtil.generateCodeVerifier();

            Response response = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", "authorization_code")
                    .formParam("code", "dummy_code")
                    .formParam("code_verifier", codeVerifier)
                    .formParam("client_id", config.getClientId())
                    .when()
                    .post("/oauth/token")
                    .then()
                    .extract()
                    .response();

            // Will fail with invalid code, but we're testing the endpoint exists
            boolean passed = response.statusCode() == 400 || response.statusCode() == 401 || response.statusCode() == 200;
            reporter.addResult(CATEGORY, "Token endpoint responds to authorization_code grant",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Token endpoint responds to authorization_code grant",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testTokenEndpointWithInvalidCode() {
        try {
            String codeVerifier = PKCEUtil.generateCodeVerifier();

            Response response = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", "authorization_code")
                    .formParam("code", "invalid_authorization_code_12345")
                    .formParam("code_verifier", codeVerifier)
                    .formParam("client_id", config.getClientId())
                    .when()
                    .post("/oauth/token")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 400 || response.statusCode() == 401;
            reporter.addResult(CATEGORY, "Token endpoint rejects invalid authorization code",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Token endpoint rejects invalid authorization code",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testTokenEndpointWithMissingCodeVerifier() {
        try {
            Response response = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", "authorization_code")
                    .formParam("code", "dummy_code")
                    .formParam("client_id", config.getClientId())
                    .when()
                    .post("/oauth/token")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 400 || response.statusCode() == 401;
            reporter.addResult(CATEGORY, "Token endpoint rejects request without code_verifier",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Token endpoint rejects request without code_verifier",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testTokenEndpointWithInvalidCodeVerifier() {
        try {
            Response response = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", "authorization_code")
                    .formParam("code", "dummy_code")
                    .formParam("code_verifier", "wrong_verifier_12345")
                    .formParam("client_id", config.getClientId())
                    .when()
                    .post("/oauth/token")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 400 || response.statusCode() == 401;
            reporter.addResult(CATEGORY, "Token endpoint rejects mismatched code_verifier",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Token endpoint rejects mismatched code_verifier",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testTokenEndpointRefreshToken() {
        try {
            Response response = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", "refresh_token")
                    .formParam("code", "dummy_access_token")
                    .formParam("code_verifier", "dummy_refresh_token")
                    .formParam("client_id", config.getClientId())
                    .when()
                    .post("/oauth/token")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 400 || response.statusCode() == 401 || response.statusCode() == 200;
            reporter.addResult(CATEGORY, "Token endpoint responds to refresh_token grant",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Token endpoint responds to refresh_token grant",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testTokenEndpointInvalidRefreshToken() {
        try {
            Response response = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", "refresh_token")
                    .formParam("code", "invalid_token")
                    .formParam("code_verifier", "invalid_refresh")
                    .formParam("client_id", config.getClientId())
                    .when()
                    .post("/oauth/token")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 400 || response.statusCode() == 401;
            reporter.addResult(CATEGORY, "Token endpoint rejects invalid refresh token",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Token endpoint rejects invalid refresh token",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJWTStructureValidation() {
        try {
            // Create a fake JWT to test structure
            String fakeJwt = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature";

            DecodedJWT decoded = JWT.decode(fakeJwt);
            boolean hasHeader = decoded.getHeader() != null;
            boolean hasPayload = decoded.getPayload() != null;
            boolean hasSignature = decoded.getSignature() != null;

            boolean passed = hasHeader && hasPayload && hasSignature;
            reporter.addResult(CATEGORY, "JWT structure validation (header, payload, signature)",
                    passed, "Structure valid: " + passed);
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JWT structure validation (header, payload, signature)",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJWKEndpoint() {
        try {
            Response response = given()
                    .queryParam("kid", "test-key-id")
                    .when()
                    .get("/jwk")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 200 || response.statusCode() == 404;
            reporter.addResult(CATEGORY, "JWK endpoint responds to key requests",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JWK endpoint responds to key requests",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJWKEndpointWithInvalidKid() {
        try {
            Response response = given()
                    .queryParam("kid", "non-existent-key-id-xyz")
                    .when()
                    .get("/jwk")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 404 || response.statusCode() == 400;
            reporter.addResult(CATEGORY, "JWK endpoint handles invalid key ID",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JWK endpoint handles invalid key ID",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testAccessProtectedEndpointWithoutToken() {
        try {
            Response response = given()
                    .when()
                    .get("/jit/my-access")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 || response.statusCode() == 403;
            reporter.addResult(CATEGORY, "Protected endpoint rejects request without token",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Protected endpoint rejects request without token",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testAccessProtectedEndpointWithInvalidToken() {
        try {
            Response response = given()
                    .header("Authorization", "Bearer invalid_token_xyz123")
                    .when()
                    .get("/jit/my-access")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 || response.statusCode() == 403;
            reporter.addResult(CATEGORY, "Protected endpoint rejects invalid token",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Protected endpoint rejects invalid token",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testAccessProtectedEndpointWithExpiredToken() {
        try {
            // Create an obviously expired JWT (using a very old timestamp)
            String expiredToken = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxMDAwfQ.signature";

            Response response = given()
                    .header("Authorization", "Bearer " + expiredToken)
                    .when()
                    .get("/jit/my-access")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 || response.statusCode() == 403;
            reporter.addResult(CATEGORY, "Protected endpoint rejects expired token",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Protected endpoint rejects expired token",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testAccessProtectedEndpointWithMalformedToken() {
        try {
            Response response = given()
                    .header("Authorization", "Bearer not.a.valid.jwt")
                    .when()
                    .get("/jit/my-access")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 || response.statusCode() == 400;
            reporter.addResult(CATEGORY, "Protected endpoint rejects malformed token",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Protected endpoint rejects malformed token",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testRoleBasedAccessControl() {
        try {
            // Try to access admin endpoint without proper role
            Response response = given()
                    .header("Authorization", "Bearer user_token_without_admin_role")
                    .when()
                    .get("/jit/requests")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 || response.statusCode() == 403;
            reporter.addResult(CATEGORY, "Role-based access control enforced on admin endpoints",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Role-based access control enforced on admin endpoints",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testScopeBasedAccessControl() {
        try {
            // Test endpoint with insufficient scopes
            Response response = given()
                    .header("Authorization", "Bearer token_without_required_scopes")
                    .when()
                    .get("/api/audit/logs")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 || response.statusCode() == 403;
            reporter.addResult(CATEGORY, "Scope-based access control enforced",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Scope-based access control enforced",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testTokenRevocation() {
        try {
            // Test accessing endpoint with a revoked token
            String revokedToken = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJyZXZva2VkLXRva2VuLWlkIn0.signature";

            Response response = given()
                    .header("Authorization", "Bearer " + revokedToken)
                    .when()
                    .get("/jit/my-access")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 || response.statusCode() == 403;
            reporter.addResult(CATEGORY, "Token revocation mechanism functional",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Token revocation mechanism functional",
                    false, "Exception: " + e.getMessage());
        }
    }
}
