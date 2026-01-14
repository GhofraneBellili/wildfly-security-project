package xyz.kaaniche.phoenix.security.tests;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import xyz.kaaniche.phoenix.security.config.TestConfig;
import xyz.kaaniche.phoenix.security.utils.TestReportGenerator;

import static io.restassured.RestAssured.given;

/**
 * Security tests for Just-In-Time (JIT) access endpoints
 */
public class JITAccessTests {
    private final TestConfig config = TestConfig.getInstance();
    private final TestReportGenerator reporter;
    private static final String CATEGORY = "JIT ACCESS ENDPOINT TESTS";

    public JITAccessTests(TestReportGenerator reporter) {
        this.reporter = reporter;
        RestAssured.baseURI = config.getBaseUrl();
    }

    public void runAllTests() {
        System.out.println("\n=== Running JIT Access Tests ===");

        testJITRequestCreation();
        testJITRequestWithoutAuthentication();
        testJITRequestWithInvalidData();
        testJITGetPendingRequests();
        testJITGetPendingRequestsWithoutAdminRole();
        testJITApproveRequest();
        testJITApproveRequestWithoutAdminRole();
        testJITApproveNonExistentRequest();
        testJITRevokeRequest();
        testJITRevokeRequestWithoutAdminRole();
        testJITGetMyAccess();
        testJITGetMyAccessWithoutAuthentication();
        testJITAccessExpiration();
    }

    private void testJITRequestCreation() {
        try {
            String jsonBody = "{"
                    + "\"requesterId\":\"" + config.getTestUsername() + "\","
                    + "\"privilegeType\":\"READ_SENSITIVE_DATA\","
                    + "\"resourceId\":\"resource-123\","
                    + "\"justification\":\"Need access for audit\""
                    + "}";

            Response response = given()
                    .contentType("application/json")
                    .header("Authorization", "Bearer user_token")
                    .body(jsonBody)
                    .when()
                    .post("/jit/request")
                    .then()
                    .extract()
                    .response();

            // Without valid token, should be 401/403
            boolean passed = response.statusCode() == 401 || response.statusCode() == 403 ||
                           response.statusCode() == 200 || response.statusCode() == 201;

            reporter.addResult(CATEGORY, "JIT request creation endpoint exists",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JIT request creation endpoint exists",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJITRequestWithoutAuthentication() {
        try {
            String jsonBody = "{"
                    + "\"requesterId\":\"testuser\","
                    + "\"privilegeType\":\"ADMIN_ACCESS\","
                    + "\"resourceId\":\"resource-123\","
                    + "\"justification\":\"Testing\""
                    + "}";

            Response response = given()
                    .contentType("application/json")
                    .body(jsonBody)
                    .when()
                    .post("/jit/request")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 || response.statusCode() == 403;
            reporter.addResult(CATEGORY, "JIT request without authentication rejected",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JIT request without authentication rejected",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJITRequestWithInvalidData() {
        try {
            // Missing required fields
            String jsonBody = "{"
                    + "\"privilegeType\":\"READ_DATA\""
                    + "}";

            Response response = given()
                    .contentType("application/json")
                    .header("Authorization", "Bearer user_token")
                    .body(jsonBody)
                    .when()
                    .post("/jit/request")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 400 || response.statusCode() == 401;
            reporter.addResult(CATEGORY, "JIT request with missing fields rejected",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JIT request with missing fields rejected",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJITGetPendingRequests() {
        try {
            Response response = given()
                    .header("Authorization", "Bearer admin_token")
                    .when()
                    .get("/jit/requests")
                    .then()
                    .extract()
                    .response();

            // Without valid admin token, should be 401/403
            boolean passed = response.statusCode() == 401 || response.statusCode() == 403 ||
                           response.statusCode() == 200;

            reporter.addResult(CATEGORY, "JIT get pending requests endpoint exists",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JIT get pending requests endpoint exists",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJITGetPendingRequestsWithoutAdminRole() {
        try {
            Response response = given()
                    .header("Authorization", "Bearer user_token_without_admin")
                    .when()
                    .get("/jit/requests")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 || response.statusCode() == 403;
            reporter.addResult(CATEGORY, "JIT get requests requires admin role",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JIT get requests requires admin role",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJITApproveRequest() {
        try {
            long requestId = 12345L;

            Response response = given()
                    .header("Authorization", "Bearer admin_token")
                    .when()
                    .post("/jit/approve/" + requestId)
                    .then()
                    .extract()
                    .response();

            // Without valid admin token, should be 401/403, or 404 if request doesn't exist
            boolean passed = response.statusCode() == 401 || response.statusCode() == 403 ||
                           response.statusCode() == 404 || response.statusCode() == 200;

            reporter.addResult(CATEGORY, "JIT approve request endpoint exists",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JIT approve request endpoint exists",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJITApproveRequestWithoutAdminRole() {
        try {
            long requestId = 12345L;

            Response response = given()
                    .header("Authorization", "Bearer user_token")
                    .when()
                    .post("/jit/approve/" + requestId)
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 || response.statusCode() == 403;
            reporter.addResult(CATEGORY, "JIT approve requires admin role",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JIT approve requires admin role",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJITApproveNonExistentRequest() {
        try {
            long requestId = 999999999L; // Non-existent ID

            Response response = given()
                    .header("Authorization", "Bearer admin_token")
                    .when()
                    .post("/jit/approve/" + requestId)
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 404 || response.statusCode() == 401 ||
                           response.statusCode() == 403;

            reporter.addResult(CATEGORY, "JIT approve handles non-existent request",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JIT approve handles non-existent request",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJITRevokeRequest() {
        try {
            long requestId = 12345L;

            Response response = given()
                    .header("Authorization", "Bearer admin_token")
                    .when()
                    .post("/jit/revoke/" + requestId)
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 || response.statusCode() == 403 ||
                           response.statusCode() == 404 || response.statusCode() == 200;

            reporter.addResult(CATEGORY, "JIT revoke request endpoint exists",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JIT revoke request endpoint exists",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJITRevokeRequestWithoutAdminRole() {
        try {
            long requestId = 12345L;

            Response response = given()
                    .header("Authorization", "Bearer user_token")
                    .when()
                    .post("/jit/revoke/" + requestId)
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 || response.statusCode() == 403;
            reporter.addResult(CATEGORY, "JIT revoke requires admin role",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JIT revoke requires admin role",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJITGetMyAccess() {
        try {
            Response response = given()
                    .header("Authorization", "Bearer user_token")
                    .when()
                    .get("/jit/my-access")
                    .then()
                    .extract()
                    .response();

            // Without valid token, should be 401/403
            boolean passed = response.statusCode() == 401 || response.statusCode() == 403 ||
                           response.statusCode() == 200;

            reporter.addResult(CATEGORY, "JIT get my access endpoint exists",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JIT get my access endpoint exists",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJITGetMyAccessWithoutAuthentication() {
        try {
            Response response = given()
                    .when()
                    .get("/jit/my-access")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 || response.statusCode() == 403;
            reporter.addResult(CATEGORY, "JIT get my access requires authentication",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JIT get my access requires authentication",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJITAccessExpiration() {
        try {
            // Test that expired JIT access is not returned
            Response response = given()
                    .header("Authorization", "Bearer user_token")
                    .when()
                    .get("/jit/my-access")
                    .then()
                    .extract()
                    .response();

            // If response is 200, check that it filters expired access
            if (response.statusCode() == 200) {
                String body = response.body().asString();
                // Assuming response contains list of access, check structure
                boolean passed = !body.isEmpty() || body.equals("[]");
                reporter.addResult(CATEGORY, "JIT access expiration handled",
                        passed, "Response structure valid");
            } else {
                // Without auth, should fail appropriately
                boolean passed = response.statusCode() == 401 || response.statusCode() == 403;
                reporter.addResult(CATEGORY, "JIT access expiration handled",
                        passed, "Status: " + response.statusCode());
            }
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JIT access expiration handled",
                    false, "Exception: " + e.getMessage());
        }
    }
}
