package xyz.kaaniche.phoenix.security;

import xyz.kaaniche.phoenix.security.config.TestConfig;
import xyz.kaaniche.phoenix.security.tests.*;
import xyz.kaaniche.phoenix.security.utils.TestReportGenerator;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Main test runner for IAM Security Tests
 */
public class IAMSecurityTestRunner {

    public static void main(String[] args) {
        System.out.println("=".repeat(80));
        System.out.println("          PHOENIX IAM SECURITY TESTING SUITE");
        System.out.println("=".repeat(80));
        System.out.println();

        TestConfig config = TestConfig.getInstance();
        System.out.println("Test Configuration:");
        System.out.println("  Base URL: " + config.getBaseUrl());
        System.out.println("  Client ID: " + config.getClientId());
        System.out.println("  Test Username: " + config.getTestUsername());
        System.out.println();

        LocalDateTime startTime = LocalDateTime.now();
        System.out.println("Test Started: " + startTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        System.out.println();

        TestReportGenerator reporter = new TestReportGenerator();

        try {
            // Run all test suites
            runTestSuite("Authentication Tests", new AuthenticationTests(reporter));
            runTestSuite("Authorization & JWT Tests", new AuthorizationAndJWTTests(reporter));
            runTestSuite("MFA & PKCE Tests", new MFAAndPKCETests(reporter));
            runTestSuite("Brute Force Protection Tests", new BruteForceProtectionTests(reporter));
            runTestSuite("Input Sanitization Tests", new InputSanitizationTests(reporter));
            runTestSuite("JIT Access Tests", new JITAccessTests(reporter));

            // Print summary
            System.out.println();
            System.out.println("=".repeat(80));
            LocalDateTime endTime = LocalDateTime.now();
            System.out.println("Test Completed: " + endTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            reporter.printSummary();

            // Generate detailed report
            String reportFilename = "security-test-report-" +
                    LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + ".txt";
            reporter.generateReport(reportFilename);
            System.out.println("\nDetailed report generated: " + reportFilename);

        } catch (Exception e) {
            System.err.println("\nFATAL ERROR: Test execution failed");
            e.printStackTrace();
            System.exit(1);
        }

        System.out.println("\n" + "=".repeat(80));
        System.out.println("          TEST EXECUTION COMPLETE");
        System.out.println("=".repeat(80));
    }

    private static void runTestSuite(String suiteName, Object testSuite) {
        try {
            System.out.println("\n" + "=".repeat(80));
            System.out.println("  " + suiteName);
            System.out.println("=".repeat(80));

            // Use reflection to call runAllTests method
            testSuite.getClass().getMethod("runAllTests").invoke(testSuite);

            System.out.println("\n[COMPLETED] " + suiteName);
        } catch (Exception e) {
            System.err.println("\n[FAILED] " + suiteName + ": " + e.getMessage());
            e.printStackTrace();
        }
    }
}
