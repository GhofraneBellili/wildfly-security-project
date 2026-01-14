@echo off
REM Phoenix IAM Security Test Runner for Windows

echo ================================================================================
echo          PHOENIX IAM SECURITY TESTING SUITE
echo ================================================================================
echo.

REM Check if Maven is installed
where mvn >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Maven is not installed or not in PATH
    echo Please install Maven from https://maven.apache.org/download.cgi
    exit /b 1
)

REM Check if Java is installed
where java >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Java is not installed or not in PATH
    echo Please install Java 17 or higher
    exit /b 1
)

echo Maven found:
call mvn -version | findstr "Apache Maven"
echo.
echo Java found:
call java -version 2>&1 | findstr "version"
echo.

echo ================================================================================
echo Building project...
echo ================================================================================
call mvn clean compile
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Build failed
    exit /b 1
)

echo.
echo ================================================================================
echo Running security tests...
echo ================================================================================
call mvn exec:java

echo.
echo ================================================================================
echo Tests complete! Check the generated report file.
echo ================================================================================
pause
