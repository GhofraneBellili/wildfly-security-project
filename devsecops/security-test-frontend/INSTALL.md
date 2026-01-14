# Installation Guide

## Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js** 18.0 or higher ([Download](https://nodejs.org/))
- **npm** (comes with Node.js)
- **Git** (optional, for cloning)
- **Phoenix IAM Backend** running (default: http://localhost:8080)

## Verification

Check your installations:

```bash
# Check Node.js version
node --version
# Should show v18.0.0 or higher

# Check npm version
npm --version
# Should show 8.0.0 or higher
```

## Installation Steps

### Step 1: Navigate to Project Directory

```bash
cd c:\Users\boula\Downloads\devsecops\security-test-frontend
```

### Step 2: Install Dependencies

```bash
npm install
```

This will install:
- express (web server)
- axios (HTTP client)
- crypto (PKCE generation)
- totp-generator (MFA support)

### Step 3: Configure Environment (Optional)

Create a `.env` file or set environment variables:

**Windows:**
```cmd
set IAM_BASE_URL=http://localhost:8080
set PORT=3000
```

**Linux/Mac:**
```bash
export IAM_BASE_URL=http://localhost:8080
export PORT=3000
```

Or copy `.env.example` to `.env` and edit:
```bash
cp .env.example .env
# Edit .env file with your settings
```

### Step 4: Start the Application

```bash
npm start
```

You should see:
```
╔════════════════════════════════════════════════════════════╗
║  IAM Security Testing Frontend                             ║
╠════════════════════════════════════════════════════════════╣
║  Server running on: http://localhost:3000                  ║
║  IAM Backend URL:   http://localhost:8080                  ║
╚════════════════════════════════════════════════════════════╝
```

### Step 5: Open in Browser

Navigate to: **http://localhost:3000**

## Troubleshooting

### Issue: `npm install` fails

**Solution:**
```bash
# Clear npm cache
npm cache clean --force

# Delete node_modules and package-lock.json
rm -rf node_modules package-lock.json

# Reinstall
npm install
```

### Issue: Port 3000 already in use

**Solution:**
```bash
# Use a different port
set PORT=3001  # Windows
export PORT=3001  # Linux/Mac

npm start
```

Or find and kill the process using port 3000:

**Windows:**
```cmd
netstat -ano | findstr :3000
taskkill /PID <PID> /F
```

**Linux/Mac:**
```bash
lsof -i :3000
kill -9 <PID>
```

### Issue: Cannot connect to backend

**Solution:**
1. Verify IAM backend is running:
   ```bash
   curl http://localhost:8080/jwk
   ```

2. Check IAM_BASE_URL is correct:
   ```bash
   echo %IAM_BASE_URL%  # Windows
   echo $IAM_BASE_URL   # Linux/Mac
   ```

3. Update backend URL and restart:
   ```bash
   set IAM_BASE_URL=http://correct-url:8080
   npm start
   ```

### Issue: Tests all failing

**Checklist:**
- [ ] Backend is running
- [ ] Backend URL is correct
- [ ] Test credentials exist in backend database
- [ ] No firewall blocking connections
- [ ] Check browser console for errors (F12)

## Development Mode

For development with auto-restart on file changes:

```bash
# Install nodemon globally
npm install -g nodemon

# Or use the dev script
npm run dev
```

## Production Installation

### Using PM2 (Recommended)

```bash
# Install PM2 globally
npm install pm2 -g

# Start application
pm2 start server.js --name iam-security-test

# Save PM2 configuration
pm2 save

# Setup PM2 to start on boot
pm2 startup
```

Manage with PM2:
```bash
pm2 status              # Check status
pm2 logs iam-security-test  # View logs
pm2 restart iam-security-test  # Restart
pm2 stop iam-security-test     # Stop
```

### Using Docker

Create `Dockerfile`:
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
ENV IAM_BASE_URL=http://localhost:8080
CMD ["node", "server.js"]
```

Build and run:
```bash
# Build image
docker build -t iam-security-test .

# Run container
docker run -d \
  -p 3000:3000 \
  -e IAM_BASE_URL=http://backend:8080 \
  --name iam-security-test \
  iam-security-test

# View logs
docker logs iam-security-test

# Stop container
docker stop iam-security-test
```

## Reverse Proxy Setup (Nginx)

For production deployment behind Nginx:

```nginx
server {
    listen 80;
    server_name security-test.example.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## SSL/HTTPS Setup

### Using Let's Encrypt

```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d security-test.example.com

# Auto-renewal is configured automatically
```

## Firewall Configuration

### Allow port 3000

**Ubuntu/Debian:**
```bash
sudo ufw allow 3000
sudo ufw reload
```

**CentOS/RHEL:**
```bash
sudo firewall-cmd --permanent --add-port=3000/tcp
sudo firewall-cmd --reload
```

**Windows Firewall:**
```powershell
New-NetFirewallRule -DisplayName "IAM Security Test" -Direction Inbound -LocalPort 3000 -Protocol TCP -Action Allow
```

## Systemd Service (Linux)

Create `/etc/systemd/system/iam-security-test.service`:

```ini
[Unit]
Description=IAM Security Testing Frontend
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/security-test-frontend
Environment="IAM_BASE_URL=http://localhost:8080"
Environment="PORT=3000"
ExecStart=/usr/bin/node server.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable iam-security-test
sudo systemctl start iam-security-test
sudo systemctl status iam-security-test
```

## Updating

To update the application:

```bash
# Pull latest changes (if using git)
git pull

# Reinstall dependencies
npm install

# Restart application
npm start
# Or with PM2:
pm2 restart iam-security-test
```

## Uninstallation

To completely remove:

```bash
# Stop the application
pm2 stop iam-security-test
pm2 delete iam-security-test

# Or if running directly
# Press Ctrl+C to stop

# Remove directory
cd ..
rm -rf security-test-frontend
```

## Verification

After installation, verify everything works:

1. **Server starts:** Check console output for success message
2. **Browser opens:** Navigate to http://localhost:3000
3. **UI loads:** Dashboard appears with purple gradient
4. **Tests work:** Click a test button and see results
5. **Backend connects:** Tests should show status codes (not 500)

## Next Steps

After successful installation:

1. Read [QUICK_START.md](QUICK_START.md) for usage guide
2. Configure test credentials in the UI
3. Run your first tests
4. Export a test report
5. Review [README.md](README.md) for detailed documentation

## Support

If you encounter issues not covered here:

1. Check the [README.md](README.md) troubleshooting section
2. Review browser console (F12) for errors
3. Check server.js console output
4. Verify backend is accessible
5. Ensure all prerequisites are met

## Success Checklist

- [ ] Node.js 18+ installed
- [ ] Dependencies installed (`npm install`)
- [ ] Environment configured (optional)
- [ ] Server starts successfully
- [ ] Dashboard opens in browser
- [ ] Tests execute without errors
- [ ] Backend connection works

---

**Congratulations!** Your security testing frontend is now installed and ready to use!

Proceed to [QUICK_START.md](QUICK_START.md) to start testing.
