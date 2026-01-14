#!/usr/bin/env bash
# Start both backend (Spring Boot) and frontend (Vite) for local development.
# Usage: chmod +x start-dev.sh && ./start-dev.sh

set -euo pipefail

ROOT="$(pwd)"

# Check prerequisites
command -v mvn >/dev/null 2>&1 || { echo "mvn (Maven) is required but not found."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "npm is required but not found."; exit 1; }
command -v java >/dev/null 2>&1 || { echo "java (JDK) is required but not found."; exit 1; }

# Ensure env vars
if [ -z "${SECURITY_JWT_SECRET:-}" ]; then
  if command -v openssl >/dev/null 2>&1; then
    export SECURITY_JWT_SECRET="dev-$(openssl rand -hex 24)"
  else
    export SECURITY_JWT_SECRET="dev-$(date +%s)-$RANDOM"
  fi
  echo "SECURITY_JWT_SECRET not set — using temporary: ${SECURITY_JWT_SECRET}"
fi

export FRONTEND_ALLOWED_ORIGIN="${FRONTEND_ALLOWED_ORIGIN:-http://localhost:3000}"

# Logs
BACKEND_LOG="$ROOT/backend.log"
FRONTEND_LOG="$ROOT/frontend.log"

# Start backend
echo "Building backend..."
cd "$ROOT/backend"
mvn -q clean package

echo "Starting backend (Spring Boot) ..."
# run in background and capture PID
nohup mvn spring-boot:run > "$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!
cd "$ROOT"

# Give backend a few seconds to start (optional)
sleep 2

# Start frontend
echo "Installing frontend dependencies (if needed) and starting Vite dev server..."
cd "$ROOT/frontend"
npm ci --silent
# start dev server in background
nohup npm run dev > "$FRONTEND_LOG" 2>&1 &
FRONTEND_PID=$!
cd "$ROOT"

echo
echo "Backend PID: $BACKEND_PID (logs: $BACKEND_LOG)"
echo "Frontend PID: $FRONTEND_PID (logs: $FRONTEND_LOG)"
echo "Backend: http://localhost:8080"
echo "Frontend: http://localhost:3000"
echo
echo "Press Ctrl+C to stop both."

# Trap Ctrl+C / termination to stop children
trap 'echo -e "\nStopping backend and frontend..."; kill '"$BACKEND_PID"' '"$FRONTEND_PID"' 2>/dev/null || true; wait '"$BACKEND_PID"' 2>/dev/null || true; wait '"$FRONTEND_PID"' 2>/dev/null || true; exit 0' SIGINT SIGTERM

# Wait for processes (keeps script running so trap works)
wait "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true