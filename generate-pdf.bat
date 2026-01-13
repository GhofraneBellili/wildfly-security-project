@echo off
REM Script to generate PDF from HTML report using Chrome

set HTML_FILE=%~dp0SECURITY-REPORT.html
set PDF_FILE=%~dp0SECURITY-REPORT.pdf

echo Generating PDF from HTML report...
echo.

REM Try Chrome first
if exist "C:\Program Files\Google\Chrome\Application\chrome.exe" (
    echo Using Google Chrome...
    "C:\Program Files\Google\Chrome\Application\chrome.exe" --headless --disable-gpu --print-to-pdf="%PDF_FILE%" "%HTML_FILE%"
    goto :success
)

REM Try Chrome (x86)
if exist "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" (
    echo Using Google Chrome...
    "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --headless --disable-gpu --print-to-pdf="%PDF_FILE%" "%HTML_FILE%"
    goto :success
)

REM Try Edge
if exist "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" (
    echo Using Microsoft Edge...
    "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless --disable-gpu --print-to-pdf="%PDF_FILE%" "%HTML_FILE%"
    goto :success
)

echo.
echo ERROR: Chrome or Edge not found!
echo Please open SECURITY-REPORT.html in your browser and print to PDF manually.
echo.
pause
exit /b 1

:success
echo.
echo SUCCESS! PDF generated: %PDF_FILE%
echo.
pause
