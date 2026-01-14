package xyz.kaaniche.phoenix.security.utils;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Generate security test reports
 */
public class TestReportGenerator {
    private final List<TestResult> results = new ArrayList<>();
    private final LocalDateTime startTime;

    public TestReportGenerator() {
        this.startTime = LocalDateTime.now();
    }

    public void addResult(String category, String testName, boolean passed, String details) {
        results.add(new TestResult(category, testName, passed, details));
    }

    public void generateReport(String filename) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("=".repeat(80));
            writer.println("        PHOENIX IAM SECURITY TEST REPORT");
            writer.println("=".repeat(80));
            writer.println();
            writer.println("Test Start Time: " + startTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            writer.println("Test End Time:   " + LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            writer.println();

            // Summary statistics
            long passed = results.stream().filter(r -> r.passed).count();
            long failed = results.size() - passed;
            double passRate = results.isEmpty() ? 0 : (passed * 100.0) / results.size();

            writer.println("SUMMARY");
            writer.println("-".repeat(80));
            writer.printf("Total Tests:  %d%n", results.size());
            writer.printf("Passed:       %d (%.1f%%)%n", passed, passRate);
            writer.printf("Failed:       %d (%.1f%%)%n", failed, 100 - passRate);
            writer.println();

            // Group by category
            String currentCategory = "";
            for (TestResult result : results) {
                if (!result.category.equals(currentCategory)) {
                    currentCategory = result.category;
                    writer.println();
                    writer.println("=".repeat(80));
                    writer.println("  " + currentCategory);
                    writer.println("=".repeat(80));
                }

                String status = result.passed ? "[PASS]" : "[FAIL]";
                writer.printf("%-60s %s%n", result.testName, status);
                if (!result.details.isEmpty()) {
                    writer.println("    Details: " + result.details);
                }
            }

            writer.println();
            writer.println("=".repeat(80));
            writer.println("                    END OF REPORT");
            writer.println("=".repeat(80));
        } catch (IOException e) {
            System.err.println("Failed to generate report: " + e.getMessage());
        }
    }

    public void printSummary() {
        long passed = results.stream().filter(r -> r.passed).count();
        long failed = results.size() - passed;
        double passRate = results.isEmpty() ? 0 : (passed * 100.0) / results.size();

        System.out.println("\n=== TEST SUMMARY ===");
        System.out.printf("Total: %d | Passed: %d | Failed: %d | Pass Rate: %.1f%%%n",
                results.size(), passed, failed, passRate);
    }

    private static class TestResult {
        final String category;
        final String testName;
        final boolean passed;
        final String details;

        TestResult(String category, String testName, boolean passed, String details) {
            this.category = category;
            this.testName = testName;
            this.passed = passed;
            this.details = details;
        }
    }
}
