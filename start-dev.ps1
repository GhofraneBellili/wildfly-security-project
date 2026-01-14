<#
Start both backend (Spring Boot) and frontend (Vite) on Windows PowerShell.
Usage: PowerShell -NoProfile -ExecutionPolicy Bypass -File "C:\path\to\start-dev.ps1"
#>

# Prereqs check
if (-not (Get-Command mvn -ErrorAction SilentlyContinue)) {
    Write-Error "Maven (mvn) required but not found in PATH."
    exit 1
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Error "npm required but not found in PATH."
    exit 1
}
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    Write-Error "Java (JDK) required but not found in PATH."
    exit 1
}

# Ensure env vars
if (-not $env:SECURITY_JWT_SECRET -or $env:SECURITY_JWT_SECRET -eq "") {
    $env:SECURITY_JWT_SECRET = "dev-" + [guid]::NewGuid().ToString()
    Write-Host ("SECURITY_JWT_SECRET not set - using temporary: {0}" -f $env:SECURITY_JWT_SECRET)
}
if (-not $env:FRONTEND_ALLOWED_ORIGIN -or $env:FRONTEND_ALLOWED_ORIGIN -eq "") {
    $env:FRONTEND_ALLOWED_ORIGIN = "http://localhost:3000"
    Write-Host ("FRONTEND_ALLOWED_ORIGIN set to: {0}" -f $env:FRONTEND_ALLOWED_ORIGIN)
}

$Root = (Get-Location).Path
$BackendLog = Join-Path $Root "backend.log"
$FrontendLog = Join-Path $Root "frontend.log"

# Build backend
Write-Host "Building backend..."
Push-Location (Join-Path $Root "backend")
&mvn clean package
Pop-Location

# Start backend
Write-Host "Starting backend (Spring Boot)... (logs -> $BackendLog)"
Push-Location (Join-Path $Root "backend")
$backendProc = Start-Process -FilePath "mvn" -ArgumentList "spring-boot:run" -NoNewWindow -PassThru -RedirectStandardOutput $BackendLog -RedirectStandardError $BackendLog
Pop-Location

Start-Sleep -Seconds 2

# Start frontend
Write-Host "Installing frontend dependencies (if needed) and starting Vite dev server... (logs -> $FrontendLog)"
Push-Location (Join-Path $Root "frontend")
&npm ci
$frontendProc = Start-Process -FilePath "npm" -ArgumentList "run","dev" -NoNewWindow -PassThru -RedirectStandardOutput $FrontendLog -RedirectStandardError $FrontendLog
Pop-Location

Write-Host ""
Write-Host ("Backend PID: {0} (logs: {1})" -f $backendProc.Id, $BackendLog)
Write-Host ("Frontend PID: {0} (logs: {1})" -f $frontendProc.Id, $FrontendLog)
Write-Host "Backend: http://localhost:8080"
Write-Host "Frontend: http://localhost:3000"
Write-Host ""
Write-Host "Press Ctrl+C in this console to stop both processes."

try {
    Wait-Process -Id $backendProc.Id, $frontendProc.Id
}
finally {
    Write-Host ""
    Write-Host "Stopping backend and frontend..."
    Stop-Process -Id $backendProc.Id -ErrorAction SilentlyContinue
    Stop-Process -Id $frontendProc.Id -ErrorAction SilentlyContinue
    Write-Host "Stopped."
}