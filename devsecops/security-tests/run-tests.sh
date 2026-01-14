#!/bin/bash
# Phoenix IAM Security Test Runner for Linux/Mac

echo "================================================================================"
echo "          PHOENIX IAM SECURITY TESTING SUITE"
echo "================================================================================"
echo ""

# Check if Maven is installed
if ! command -v mvn &> /dev/null; then
    echo "ERROR: Maven is not installed or not in PATH"
    echo "Please install Maven from https://maven.apache.org/download.cgi"
    exit 1
fi

# Check if Java is installed
if ! command -v java &> /dev/null; then
    echo "ERROR: Java is not installed or not in PATH"
    echo "Please install Java 17 or higher"
    exit 1
fi

echo "Maven found:"
mvn -version | grep "Apache Maven"
echo ""
echo "Java found:"
java -version 2>&1 | grep "version"
echo ""

echo "================================================================================"
echo "Building project..."
echo "================================================================================"
mvn clean compile
if [ $? -ne 0 ]; then
    echo "ERROR: Build failed"
    exit 1
fi

echo ""
echo "================================================================================"
echo "Running security tests..."
echo "================================================================================"
mvn exec:java

echo ""
echo "================================================================================"
echo "Tests complete! Check the generated report file."
echo "================================================================================"
