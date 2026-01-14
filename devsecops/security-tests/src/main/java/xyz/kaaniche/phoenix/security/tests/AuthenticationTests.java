package xyz.kaaniche.phoenix.security.tests;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import xyz.kaaniche.phoenix.security.config.TestConfig;
import xyz.kaaniche.phoenix.security.utils.PKCEUtil;
import xyz.kaaniche.phoenix.security.utils.TestReportGenerator;

import static io.restassured.RestAssured.given;

/**
 * Security tests for authentication endpoints
 */
public class AuthenticationTests {
    private final TestConfig config = TestConfig.getInstance();
    private final TestReportGenerator reporter;
    private static final String CATEGORY = "AUTHENTICATION ENDPOINT TESTS";

    public AuthenticationTests(TestReportGenerator reporter) {
        this.reporter = reporter;
        RestAssured.baseURI = config.getBaseUrl();
    }

    public void runAllTests() {
        System.out.println("\n=== Running Authentication Tests ===");

        testOAuthAuthorizeEndpoint();
        testOAuthAuthorizeWithInvalidClientId();
        testOAuthAuthorizeWithMissingCodeChallenge();
        testOAuthAuthorizeWithInvalidChallengeMethod();
        testLoginWithValidCredentials();
        testLoginWithInvalidCredentials();
        testLoginWithMissingCredentials();
        testLoginWithSQLInjection();
        testLoginWithXSSPayload();
        testAPILoginValidCredentials();
        testAPILoginInvalidCredentials();
        testAPILoginMissingFields();
        testUserRegistration();
        testUserRegistrationDuplicateUsername();
        testUserRegistrationDuplicateEmail();
        testUserRegistrationInvalidEmail();
        testUserRegistrationXSSInFields();
    }

    private void testOAuthAuthorizeEndpoint() {
        try {
            String codeVerifier = PKCEUtil.generateCodeVerifier();
            String codeChallenge = PKCEUtil.generateCodeChallenge(codeVerifier);

            Response response = given()
                    .queryParam("client_id", config.getClientId())
                    .queryParam("redirect_uri", config.getRedirectUri())
                    .queryParam("response_type", "code")
                    .queryParam("scope", config.getTestScope())
                    .queryParam("code_challenge", codeChallenge)
                    .queryParam("code_challenge_method", "S256")
                    .queryParam("grant_type", "authorization_code")
                    .when()
                    .get("/authorize")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 200 && response.contentType().contains("text/html");
            reporter.addResult(CATEGORY, "OAuth authorize endpoint with valid parameters",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "OAuth authorize endpoint with valid parameters",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testOAuthAuthorizeWithInvalidClientId() {
        try {
            String codeVerifier = PKCEUtil.generateCodeVerifier();
            String codeChallenge = PKCEUtil.generateCodeChallenge(codeVerifier);

            Response response = given()
                    .queryParam("client_id", "invalid-client-id")
                    .queryParam("redirect_uri", config.getRedirectUri())
                    .queryParam("response_type", "code")
                    .queryParam("scope", config.getTestScope())
                    .queryParam("code_challenge", codeChallenge)
                    .queryParam("code_challenge_method", "S256")
                    .queryParam("grant_type", "authorization_code")
                    .when()
                    .get("/authorize")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 400 || response.statusCode() == 401;
            reporter.addResult(CATEGORY, "OAuth authorize with invalid client_id (should reject)",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "OAuth authorize with invalid client_id (should reject)",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testOAuthAuthorizeWithMissingCodeChallenge() {
        try {
            Response response = given()
                    .queryParam("client_id", config.getClientId())
                    .queryParam("redirect_uri", config.getRedirectUri())
                    .queryParam("response_type", "code")
                    .queryParam("scope", config.getTestScope())
                    .queryParam("grant_type", "authorization_code")
                    .when()
                    .get("/authorize")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 400 || response.statusCode() == 401;
            reporter.addResult(CATEGORY, "OAuth authorize without code_challenge (should reject)",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "OAuth authorize without code_challenge (should reject)",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testOAuthAuthorizeWithInvalidChallengeMethod() {
        try {
            String codeVerifier = PKCEUtil.generateCodeVerifier();
            String codeChallenge = PKCEUtil.generateCodeChallenge(codeVerifier);

            Response response = given()
                    .queryParam("client_id", config.getClientId())
                    .queryParam("redirect_uri", config.getRedirectUri())
                    .queryParam("response_type", "code")
                    .queryParam("scope", config.getTestScope())
                    .queryParam("code_challenge", codeChallenge)
                    .queryParam("code_challenge_method", "plain")
                    .queryParam("grant_type", "authorization_code")
                    .when()
                    .get("/authorize")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 400 || response.statusCode() == 401;
            reporter.addResult(CATEGORY, "OAuth authorize with invalid challenge_method (should reject)",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "OAuth authorize with invalid challenge_method (should reject)",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testLoginWithValidCredentials() {
        try {
            // This test requires a session cookie from authorize endpoint
            String codeVerifier = PKCEUtil.generateCodeVerifier();
            String codeChallenge = PKCEUtil.generateCodeChallenge(codeVerifier);

            // First get the authorize page to get cookie
            Response authResponse = given()
                    .queryParam("client_id", config.getClientId())
                    .queryParam("redirect_uri", config.getRedirectUri())
                    .queryParam("response_type", "code")
                    .queryParam("scope", config.getTestScope())
                    .queryParam("code_challenge", codeChallenge)
                    .queryParam("code_challenge_method", "S256")
                    .queryParam("grant_type", "authorization_code")
                    .when()
                    .get("/authorize");

            String cookie = authResponse.getCookie("CHALLENGE_RESPONSE_COOKIE_ID");

            Response response = given()
                    .cookie("CHALLENGE_RESPONSE_COOKIE_ID", cookie)
                    .formParam("username", config.getTestUsername())
                    .formParam("password", config.getTestPassword())
                    .when()
                    .post("/login/authorization")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 200 || response.statusCode() == 302;
            reporter.addResult(CATEGORY, "Login with valid credentials",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Login with valid credentials",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testLoginWithInvalidCredentials() {
        try {
            Response response = given()
                    .formParam("username", "invalid_user")
                    .formParam("password", "wrong_password")
                    .when()
                    .post("/login/authorization")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 || response.statusCode() == 403;
            reporter.addResult(CATEGORY, "Login with invalid credentials (should reject)",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Login with invalid credentials (should reject)",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testLoginWithMissingCredentials() {
        try {
            Response response = given()
                    .formParam("username", "testuser")
                    .when()
                    .post("/login/authorization")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 400 || response.statusCode() == 401;
            reporter.addResult(CATEGORY, "Login with missing password (should reject)",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Login with missing password (should reject)",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testLoginWithSQLInjection() {
        try {
            Response response = given()
                    .formParam("username", "admin' OR '1'='1")
                    .formParam("password", "' OR '1'='1")
                    .when()
                    .post("/login/authorization")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 || response.statusCode() == 400;
            reporter.addResult(CATEGORY, "Login with SQL injection attempt (should reject)",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Login with SQL injection attempt (should reject)",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testLoginWithXSSPayload() {
        try {
            Response response = given()
                    .formParam("username", "<script>alert('XSS')</script>")
                    .formParam("password", "password")
                    .when()
                    .post("/login/authorization")
                    .then()
                    .extract()
                    .response();

            String body = response.body().asString();
            boolean containsUnsafeScript = body.contains("<script>") && body.contains("alert");
            boolean passed = !containsUnsafeScript;

            reporter.addResult(CATEGORY, "Login with XSS payload (should sanitize)",
                    passed, "XSS found in response: " + containsUnsafeScript);
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Login with XSS payload (should sanitize)",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testAPILoginValidCredentials() {
        try {
            String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"%s\"}",
                    config.getTestUsername(), config.getTestPassword());

            Response response = given()
                    .contentType("application/json")
                    .body(jsonBody)
                    .when()
                    .post("/api/login")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 200;
            reporter.addResult(CATEGORY, "API login with valid credentials",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "API login with valid credentials",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testAPILoginInvalidCredentials() {
        try {
            String jsonBody = "{\"username\":\"invalid\",\"password\":\"wrong\"}";

            Response response = given()
                    .contentType("application/json")
                    .body(jsonBody)
                    .when()
                    .post("/api/login")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 401 ||
                           (response.statusCode() == 200 && response.body().asString().contains("\"success\":false"));
            reporter.addResult(CATEGORY, "API login with invalid credentials (should reject)",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "API login with invalid credentials (should reject)",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testAPILoginMissingFields() {
        try {
            String jsonBody = "{\"username\":\"testuser\"}";

            Response response = given()
                    .contentType("application/json")
                    .body(jsonBody)
                    .when()
                    .post("/api/login")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 400 || response.statusCode() == 401;
            reporter.addResult(CATEGORY, "API login with missing password (should reject)",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "API login with missing password (should reject)",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testUserRegistration() {
        try {
            String uniqueUsername = "testuser_" + System.currentTimeMillis();
            String uniqueEmail = "test_" + System.currentTimeMillis() + "@example.com";
            String jsonBody = String.format(
                    "{\"username\":\"%s\",\"email\":\"%s\",\"password\":\"Test@123456\",\"role\":\"USER\"}",
                    uniqueUsername, uniqueEmail);

            Response response = given()
                    .contentType("application/json")
                    .body(jsonBody)
                    .when()
                    .post("/api/register")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 200 || response.statusCode() == 201;
            reporter.addResult(CATEGORY, "User registration with valid data",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "User registration with valid data",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testUserRegistrationDuplicateUsername() {
        try {
            String jsonBody = String.format(
                    "{\"username\":\"%s\",\"email\":\"new@example.com\",\"password\":\"Test@123456\",\"role\":\"USER\"}",
                    config.getTestUsername());

            Response response = given()
                    .contentType("application/json")
                    .body(jsonBody)
                    .when()
                    .post("/api/register")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 400 || response.statusCode() == 409;
            reporter.addResult(CATEGORY, "Registration with duplicate username (should reject)",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Registration with duplicate username (should reject)",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testUserRegistrationDuplicateEmail() {
        try {
            String jsonBody = String.format(
                    "{\"username\":\"newuser123\",\"email\":\"%s\",\"password\":\"Test@123456\",\"role\":\"USER\"}",
                    config.getTestEmail());

            Response response = given()
                    .contentType("application/json")
                    .body(jsonBody)
                    .when()
                    .post("/api/register")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 400 || response.statusCode() == 409;
            reporter.addResult(CATEGORY, "Registration with duplicate email (should reject)",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Registration with duplicate email (should reject)",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testUserRegistrationInvalidEmail() {
        try {
            String jsonBody = "{\"username\":\"newuser\",\"email\":\"invalid-email\",\"password\":\"Test@123456\",\"role\":\"USER\"}";

            Response response = given()
                    .contentType("application/json")
                    .body(jsonBody)
                    .when()
                    .post("/api/register")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 400;
            reporter.addResult(CATEGORY, "Registration with invalid email format (should reject)",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Registration with invalid email format (should reject)",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testUserRegistrationXSSInFields() {
        try {
            String jsonBody = "{\"username\":\"<script>alert('XSS')</script>\",\"email\":\"test@example.com\",\"password\":\"Test@123456\",\"role\":\"USER\"}";

            Response response = given()
                    .contentType("application/json")
                    .body(jsonBody)
                    .when()
                    .post("/api/register")
                    .then()
                    .extract()
                    .response();

            boolean passed = response.statusCode() == 400 ||
                           !response.body().asString().contains("<script>");
            reporter.addResult(CATEGORY, "Registration with XSS in username (should sanitize/reject)",
                    passed, "Status: " + response.statusCode());
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Registration with XSS in username (should sanitize/reject)",
                    false, "Exception: " + e.getMessage());
        }
    }
}
