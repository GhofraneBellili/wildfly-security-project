package xyz.kaaniche.phoenix.security.tests;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import xyz.kaaniche.phoenix.security.config.TestConfig;
import xyz.kaaniche.phoenix.security.utils.PKCEUtil;
import xyz.kaaniche.phoenix.security.utils.TestReportGenerator;

import static io.restassured.RestAssured.given;

/**
 * Security tests for input sanitization and XSS prevention
 */
public class InputSanitizationTests {
    private final TestConfig config = TestConfig.getInstance();
    private final TestReportGenerator reporter;
    private static final String CATEGORY = "INPUT SANITIZATION & XSS TESTS";

    public InputSanitizationTests(TestReportGenerator reporter) {
        this.reporter = reporter;
        RestAssured.baseURI = config.getBaseUrl();
    }

    public void runAllTests() {
        System.out.println("\n=== Running Input Sanitization Tests ===");

        testXSSInQueryParameters();
        testXSSInRequestHeaders();
        testScriptTagSanitization();
        testIframeTagSanitization();
        testJavaScriptProtocolSanitization();
        testEventHandlerSanitization();
        testHTMLEntityEncoding();
        testSQLInjectionPrevention();
        testPathTraversalPrevention();
        testCommandInjectionPrevention();
        testXMLInjectionPrevention();
        testLDAPInjectionPrevention();
    }

    private void testXSSInQueryParameters() {
        try {
            String xssPayload = "<script>alert('XSS')</script>";
            String codeVerifier = PKCEUtil.generateCodeVerifier();
            String codeChallenge = PKCEUtil.generateCodeChallenge(codeVerifier);

            Response response = given()
                    .queryParam("client_id", config.getClientId())
                    .queryParam("redirect_uri", xssPayload)
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

            String body = response.body().asString();
            boolean containsUnsafeScript = body.contains("<script>alert");

            boolean passed = !containsUnsafeScript;
            reporter.addResult(CATEGORY, "XSS in query parameters sanitized",
                    passed, "Contains unsafe script: " + containsUnsafeScript);
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "XSS in query parameters sanitized",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testXSSInRequestHeaders() {
        try {
            String xssPayload = "<script>alert('XSS')</script>";

            Response response = given()
                    .header("User-Agent", xssPayload)
                    .header("X-Custom-Header", xssPayload)
                    .when()
                    .get("/jwk?kid=test")
                    .then()
                    .extract()
                    .response();

            String body = response.body().asString();
            boolean containsUnsafeScript = body.contains("<script>alert");

            boolean passed = !containsUnsafeScript;
            reporter.addResult(CATEGORY, "XSS in request headers sanitized",
                    passed, "Contains unsafe script: " + containsUnsafeScript);
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "XSS in request headers sanitized",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testScriptTagSanitization() {
        try {
            String[] scriptPayloads = {
                "<script>alert(1)</script>",
                "<SCRIPT>alert(1)</SCRIPT>",
                "<script src='http://evil.com/xss.js'></script>",
                "<script>document.cookie</script>"
            };

            int sanitizedCount = 0;
            for (String payload : scriptPayloads) {
                String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"test\"}", payload);

                Response response = given()
                        .contentType("application/json")
                        .body(jsonBody)
                        .when()
                        .post("/api/login");

                String body = response.body().asString();
                if (!body.contains("<script>") && !body.contains("<SCRIPT>")) {
                    sanitizedCount++;
                }
            }

            boolean passed = sanitizedCount == scriptPayloads.length;
            reporter.addResult(CATEGORY, "Script tag variants sanitized",
                    passed, sanitizedCount + "/" + scriptPayloads.length + " sanitized");
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Script tag variants sanitized",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testIframeTagSanitization() {
        try {
            String[] iframePayloads = {
                "<iframe src='http://evil.com'></iframe>",
                "<IFRAME src='javascript:alert(1)'></IFRAME>",
                "<iframe onload='alert(1)'></iframe>"
            };

            int sanitizedCount = 0;
            for (String payload : iframePayloads) {
                String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"test\"}", payload);

                Response response = given()
                        .contentType("application/json")
                        .body(jsonBody)
                        .when()
                        .post("/api/login");

                String body = response.body().asString();
                if (!body.contains("<iframe") && !body.contains("<IFRAME")) {
                    sanitizedCount++;
                }
            }

            boolean passed = sanitizedCount == iframePayloads.length;
            reporter.addResult(CATEGORY, "IFrame tag variants sanitized",
                    passed, sanitizedCount + "/" + iframePayloads.length + " sanitized");
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "IFrame tag variants sanitized",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testJavaScriptProtocolSanitization() {
        try {
            String[] jsProtocols = {
                "javascript:alert(1)",
                "JAVASCRIPT:alert(1)",
                "vbscript:msgbox(1)",
                "javascript:document.cookie"
            };

            int sanitizedCount = 0;
            for (String payload : jsProtocols) {
                String codeVerifier = PKCEUtil.generateCodeVerifier();
                String codeChallenge = PKCEUtil.generateCodeChallenge(codeVerifier);

                Response response = given()
                        .queryParam("client_id", config.getClientId())
                        .queryParam("redirect_uri", payload)
                        .queryParam("response_type", "code")
                        .queryParam("code_challenge", codeChallenge)
                        .queryParam("code_challenge_method", "S256")
                        .queryParam("grant_type", "authorization_code")
                        .when()
                        .get("/authorize");

                String body = response.body().asString();
                if (!body.contains("javascript:") && !body.contains("vbscript:")) {
                    sanitizedCount++;
                }
            }

            boolean passed = sanitizedCount == jsProtocols.length;
            reporter.addResult(CATEGORY, "JavaScript protocol handlers sanitized",
                    passed, sanitizedCount + "/" + jsProtocols.length + " sanitized");
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "JavaScript protocol handlers sanitized",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testEventHandlerSanitization() {
        try {
            String[] eventHandlers = {
                "<img src=x onerror='alert(1)'>",
                "<body onload='alert(1)'>",
                "<div onmouseover='alert(1)'>",
                "<input onclick='alert(1)'>"
            };

            int sanitizedCount = 0;
            for (String payload : eventHandlers) {
                String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"test\"}", payload);

                Response response = given()
                        .contentType("application/json")
                        .body(jsonBody)
                        .when()
                        .post("/api/login");

                String body = response.body().asString();
                if (!body.contains("onerror=") && !body.contains("onload=") &&
                    !body.contains("onmouseover=") && !body.contains("onclick=")) {
                    sanitizedCount++;
                }
            }

            boolean passed = sanitizedCount == eventHandlers.length;
            reporter.addResult(CATEGORY, "Event handler attributes sanitized",
                    passed, sanitizedCount + "/" + eventHandlers.length + " sanitized");
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Event handler attributes sanitized",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testHTMLEntityEncoding() {
        try {
            String[] specialChars = {
                "<test>",
                "\"test\"",
                "'test'",
                "&test&",
                "/test/"
            };

            int encodedCount = 0;
            for (String payload : specialChars) {
                String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"test\"}", payload);

                Response response = given()
                        .contentType("application/json")
                        .body(jsonBody)
                        .when()
                        .post("/api/login");

                String body = response.body().asString();
                // Check if special characters are encoded
                if (body.contains("&lt;") || body.contains("&gt;") ||
                    body.contains("&quot;") || body.contains("&#x27;") ||
                    body.contains("&amp;") || body.contains("&#x2F;") ||
                    !body.contains(payload)) {
                    encodedCount++;
                }
            }

            boolean passed = encodedCount >= specialChars.length - 1; // Allow some flexibility
            reporter.addResult(CATEGORY, "HTML entities properly encoded",
                    passed, encodedCount + "/" + specialChars.length + " encoded/handled");
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "HTML entities properly encoded",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testSQLInjectionPrevention() {
        try {
            String[] sqlPayloads = {
                "admin' OR '1'='1",
                "'; DROP TABLE users--",
                "1' UNION SELECT * FROM users--",
                "admin'--",
                "' OR 1=1--"
            };

            int rejectedCount = 0;
            for (String payload : sqlPayloads) {
                String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"test\"}", payload);

                Response response = given()
                        .contentType("application/json")
                        .body(jsonBody)
                        .when()
                        .post("/api/login");

                // SQL injection should result in failed login, not unauthorized access
                if (response.statusCode() == 401 || response.statusCode() == 400) {
                    rejectedCount++;
                }
            }

            boolean passed = rejectedCount == sqlPayloads.length;
            reporter.addResult(CATEGORY, "SQL injection attempts prevented",
                    passed, rejectedCount + "/" + sqlPayloads.length + " rejected");
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "SQL injection attempts prevented",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testPathTraversalPrevention() {
        try {
            String[] pathPayloads = {
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            };

            int rejectedCount = 0;
            for (String payload : pathPayloads) {
                Response response = given()
                        .queryParam("kid", payload)
                        .when()
                        .get("/jwk");

                // Should not return sensitive file contents
                String body = response.body().asString();
                if (response.statusCode() == 400 || response.statusCode() == 404 ||
                    (!body.contains("root:") && !body.contains("Administrator"))) {
                    rejectedCount++;
                }
            }

            boolean passed = rejectedCount == pathPayloads.length;
            reporter.addResult(CATEGORY, "Path traversal attempts prevented",
                    passed, rejectedCount + "/" + pathPayloads.length + " rejected");
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Path traversal attempts prevented",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testCommandInjectionPrevention() {
        try {
            String[] cmdPayloads = {
                "; ls -la",
                "| cat /etc/passwd",
                "& whoami",
                "`whoami`",
                "$(whoami)"
            };

            int rejectedCount = 0;
            for (String payload : cmdPayloads) {
                String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"test\"}", payload);

                Response response = given()
                        .contentType("application/json")
                        .body(jsonBody)
                        .when()
                        .post("/api/login");

                // Should not execute commands or return command output
                String body = response.body().asString();
                if (!body.contains("bin/") && !body.contains("usr/") &&
                    !body.contains("root") && !body.contains("Administrator")) {
                    rejectedCount++;
                }
            }

            boolean passed = rejectedCount == cmdPayloads.length;
            reporter.addResult(CATEGORY, "Command injection attempts prevented",
                    passed, rejectedCount + "/" + cmdPayloads.length + " prevented");
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "Command injection attempts prevented",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testXMLInjectionPrevention() {
        try {
            String[] xmlPayloads = {
                "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
                "<![CDATA[<script>alert('XSS')</script>]]>",
                "<!--<script>alert('XSS')</script>-->"
            };

            int rejectedCount = 0;
            for (String payload : xmlPayloads) {
                String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"test\"}", payload);

                Response response = given()
                        .contentType("application/json")
                        .body(jsonBody)
                        .when()
                        .post("/api/login");

                String body = response.body().asString();
                if (!body.contains("<!ENTITY") && !body.contains("<!DOCTYPE") &&
                    !body.contains("<![CDATA[")) {
                    rejectedCount++;
                }
            }

            boolean passed = rejectedCount == xmlPayloads.length;
            reporter.addResult(CATEGORY, "XML injection attempts prevented",
                    passed, rejectedCount + "/" + xmlPayloads.length + " prevented");
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "XML injection attempts prevented",
                    false, "Exception: " + e.getMessage());
        }
    }

    private void testLDAPInjectionPrevention() {
        try {
            String[] ldapPayloads = {
                "*)(uid=*))(|(uid=*",
                "admin)(&(password=*))",
                "*)(objectClass=*",
                "*))(|(cn=*"
            };

            int rejectedCount = 0;
            for (String payload : ldapPayloads) {
                String jsonBody = String.format("{\"username\":\"%s\",\"password\":\"test\"}", payload);

                Response response = given()
                        .contentType("application/json")
                        .body(jsonBody)
                        .when()
                        .post("/api/login");

                // Should not bypass authentication
                if (response.statusCode() == 401 || response.statusCode() == 400) {
                    rejectedCount++;
                }
            }

            boolean passed = rejectedCount == ldapPayloads.length;
            reporter.addResult(CATEGORY, "LDAP injection attempts prevented",
                    passed, rejectedCount + "/" + ldapPayloads.length + " rejected");
        } catch (Exception e) {
            reporter.addResult(CATEGORY, "LDAP injection attempts prevented",
                    false, "Exception: " + e.getMessage());
        }
    }
}
