# Phoenix IAM - Production Deployment Guide

**Version:** 1.0
**Last Updated:** January 13, 2026
**Status:** Security Enhanced

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Security Setup (Critical)](#security-setup-critical)
3. [Database Configuration](#database-configuration)
4. [Application Build](#application-build)
5. [WildFly Configuration](#wildfly-configuration)
6. [HTTPS/SSL Setup](#httpsssl-setup)
7. [Rate Limiting Setup](#rate-limiting-setup)
8. [Monitoring & Logging](#monitoring--logging)
9. [Production Checklist](#production-checklist)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software

- **Java**: 17 or higher
- **Maven**: 3.8+
- **WildFly**: 27+ Application Server
- **Database**: PostgreSQL 13+ or MySQL 8+
- **OpenSSL**: For generating encryption keys
- **Reverse Proxy**: nginx or Apache (for rate limiting & SSL termination)

### System Requirements

**Minimum:**
- 2 CPU cores
- 4 GB RAM
- 20 GB disk space

**Recommended:**
- 4+ CPU cores
- 8+ GB RAM
- 50+ GB disk space (for logs)

---

## Security Setup (Critical)

⚠️ **These steps MUST be completed before deployment**

### Step 1: Generate Encryption Key

```bash
# Navigate to project directory
cd /path/to/phoenix-iam/src

# Generate AES-256 key for authorization codes
chmod +x generate-encryption-key.sh
./generate-encryption-key.sh

# Or on Windows
generate-encryption-key.bat
```

This creates `authorization_code.key` file. **DO NOT COMMIT THIS FILE!**

### Step 2: Store Secrets Securely

**Option A: Environment Variables (Simple)**

```bash
# Linux/Mac - Add to ~/.bashrc or /etc/environment
export AUTHORIZATION_CODE_KEY="your-base64-key-here"
export MQTT_USERNAME="your-mqtt-username"
export MQTT_PASSWORD="secure-mqtt-password"
export DB_PASSWORD="secure-database-password"

# Windows - System Properties > Environment Variables
# Or PowerShell:
[System.Environment]::SetEnvironmentVariable('AUTHORIZATION_CODE_KEY', 'your-base64-key-here', 'Machine')
```

**Option B: HashiCorp Vault (Recommended for Production)**

```bash
# Store in Vault
vault kv put secret/phoenix-iam \
  authorization_code_key="your-base64-key-here" \
  mqtt_username="your-mqtt-username" \
  mqtt_password="secure-mqtt-password" \
  db_password="secure-database-password"

# Retrieve in application startup
vault kv get -field=authorization_code_key secret/phoenix-iam
```

**Option C: Kubernetes Secrets**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: phoenix-iam-secrets
type: Opaque
data:
  authorization-code-key: <base64-encoded-key>
  mqtt-username: <base64-encoded-username>
  mqtt-password: <base64-encoded-password>
```

### Step 3: Update .gitignore

```bash
# Add to .gitignore
echo "authorization_code.key" >> .gitignore
echo "*.key" >> .gitignore
echo "*.pem" >> .gitignore
echo "*.jks" >> .gitignore
```

### Step 4: Delete Key File After Storage

```bash
# After storing key securely
rm authorization_code.key
```

---

## Database Configuration

### PostgreSQL Setup

```sql
-- Create database
CREATE DATABASE phoenix_iam;

-- Create user
CREATE USER phoenix_user WITH ENCRYPTED PASSWORD 'your-secure-password';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE phoenix_iam TO phoenix_user;

-- Connect to database
\c phoenix_iam

-- Grant schema privileges
GRANT ALL ON SCHEMA public TO phoenix_user;
```

### Update persistence.xml

Edit `src/main/resources/META-INF/persistence.xml`:

```xml
<property name="jakarta.persistence.jdbc.url"
          value="${DB_URL:jdbc:postgresql://localhost:5432/phoenix_iam}"/>
<property name="jakarta.persistence.jdbc.user"
          value="${DB_USER:phoenix_user}"/>
<property name="jakarta.persistence.jdbc.password"
          value="${DB_PASSWORD}"/>
```

### Database Connection Pool (WildFly)

Add to `standalone.xml`:

```xml
<datasource jndi-name="java:jboss/datasources/PhoenixIAM"
            pool-name="PhoenixIAMDS"
            enabled="true"
            use-java-context="true">
    <connection-url>jdbc:postgresql://localhost:5432/phoenix_iam</connection-url>
    <driver>postgresql</driver>
    <security>
        <user-name>phoenix_user</user-name>
        <password>${env.DB_PASSWORD}</password>
    </security>
    <pool>
        <min-pool-size>10</min-pool-size>
        <max-pool-size>50</max-pool-size>
    </pool>
</datasource>
```

---

## Application Build

### Development Build

```bash
cd /path/to/phoenix-iam
mvn clean package
```

### Production Build (Optimized)

```bash
# Build with production profile
mvn clean package -P production -DskipTests

# Output: src/target/iam-1.0.war
```

### Build with Tests

```bash
mvn clean install
```

---

## WildFly Configuration

### Install WildFly

```bash
# Download WildFly
wget https://github.com/wildfly/wildfly/releases/download/27.0.1.Final/wildfly-27.0.1.Final.tar.gz

# Extract
tar -xzf wildfly-27.0.1.Final.tar.gz
cd wildfly-27.0.1.Final

# Set WILDFLY_HOME
export WILDFLY_HOME=/path/to/wildfly-27.0.1.Final
```

### Configure WildFly for Production

Edit `$WILDFLY_HOME/standalone/configuration/standalone.xml`:

```xml
<!-- Set bind address to 0.0.0.0 for external access -->
<interface name="public">
    <inet-address value="0.0.0.0"/>
</interface>

<!-- Configure logging -->
<periodic-rotating-file-handler name="FILE" autoflush="true">
    <level name="INFO"/>
    <formatter>
        <named-formatter name="PATTERN"/>
    </formatter>
    <file relative-to="jboss.server.log.dir" path="server.log"/>
    <suffix value=".yyyy-MM-dd"/>
</periodic-rotating-file-handler>
```

### Deploy Application

**Option 1: Manual Deployment**

```bash
cp src/target/iam-1.0.war $WILDFLY_HOME/standalone/deployments/
```

**Option 2: CLI Deployment**

```bash
$WILDFLY_HOME/bin/jboss-cli.sh --connect
deploy /path/to/iam-1.0.war
```

**Option 3: Maven Plugin**

```bash
# Start WildFly first
$WILDFLY_HOME/bin/standalone.sh

# Deploy with Maven
mvn wildfly:deploy
```

### Start WildFly

```bash
# Foreground
$WILDFLY_HOME/bin/standalone.sh

# Background (Linux)
nohup $WILDFLY_HOME/bin/standalone.sh > wildfly.log 2>&1 &

# As systemd service
sudo systemctl start wildfly
```

---

## HTTPS/SSL Setup

### Option 1: Let's Encrypt (Recommended)

```bash
# Install Certbot
sudo apt-get install certbot

# Obtain certificate
sudo certbot certonly --standalone \
  -d iam.yourdomain.com \
  --email your-email@example.com

# Certificates will be in:
# /etc/letsencrypt/live/iam.yourdomain.com/
```

### Option 2: Self-Signed Certificate (Development Only)

```bash
# Generate keystore
keytool -genkeypair \
  -alias phoenix-iam \
  -keyalg RSA \
  -keysize 2048 \
  -validity 365 \
  -keystore keystore.jks \
  -storepass changeit \
  -dname "CN=localhost,OU=DevOps,O=Phoenix,L=City,ST=State,C=US"
```

### Configure WildFly SSL

Edit `standalone.xml`:

```xml
<security-realm name="SslRealm">
    <server-identities>
        <ssl>
            <keystore path="/path/to/keystore.jks"
                     keystore-password="${env.KEYSTORE_PASSWORD}"
                     alias="phoenix-iam"/>
        </ssl>
    </server-identities>
</security-realm>

<https-listener name="https"
                socket-binding="https"
                security-realm="SslRealm"
                enable-http2="true"/>
```

### Force HTTPS Redirect

Add to `web.xml`:

```xml
<security-constraint>
    <web-resource-collection>
        <web-resource-name>Entire Application</web-resource-name>
        <url-pattern>/*</url-pattern>
    </web-resource-collection>
    <user-data-constraint>
        <transport-guarantee>CONFIDENTIAL</transport-guarantee>
    </user-data-constraint>
</security-constraint>
```

---

## Rate Limiting Setup

### Option 1: nginx Reverse Proxy

```nginx
# /etc/nginx/nginx.conf

# Define rate limiting zones
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=token:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=general:10m rate=100r/m;

server {
    listen 443 ssl http2;
    server_name iam.yourdomain.com;

    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/iam.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/iam.yourdomain.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Rate limit login endpoint (5 requests per minute)
    location /iam-1.0/login/authorization {
        limit_req zone=login burst=2 nodelay;
        limit_req_status 429;
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Rate limit token endpoint (10 requests per minute)
    location /iam-1.0/oauth/token {
        limit_req zone=token burst=5 nodelay;
        limit_req_status 429;
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # General rate limit (100 requests per minute)
    location /iam-1.0/ {
        limit_req zone=general burst=20 nodelay;
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name iam.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

### Option 2: Apache Reverse Proxy

```apache
# /etc/apache2/sites-available/iam.conf

<VirtualHost *:443>
    ServerName iam.yourdomain.com

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/iam.yourdomain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/iam.yourdomain.com/privkey.pem

    # Rate limiting with mod_qos
    QS_SrvMaxConnPerIP 50
    QS_LocRequestLimitMatch /iam-1.0/login 5 60
    QS_LocRequestLimitMatch /iam-1.0/oauth/token 10 60

    ProxyPreserveHost On
    ProxyPass / http://localhost:8080/
    ProxyPassReverse / http://localhost:8080/

    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
</VirtualHost>
```

---

## Monitoring & Logging

### Application Logs

```bash
# View WildFly logs
tail -f $WILDFLY_HOME/standalone/log/server.log

# Filter security events
grep "Security\|Authentication\|Failed login" server.log

# Monitor account lockouts
grep "Account locked" server.log
```

### Prometheus Metrics (Optional)

Add to `pom.xml`:

```xml
<dependency>
    <groupId>org.wildfly.swarm</groupId>
    <artifactId>microprofile-metrics</artifactId>
</dependency>
```

Configure metrics endpoint:

```java
@GET
@Path("/metrics")
@Produces("application/json")
public Response getMetrics() {
    // Return application metrics
}
```

### Grafana Dashboard

Import pre-built dashboard for WildFly monitoring:
- Dashboard ID: 11159

Configure alerts for:
- Failed login attempts > 10/min
- Account lockouts
- High memory usage
- Slow response times

---

## Production Checklist

### Before Deployment

- [ ] Generated and stored authorization code encryption key
- [ ] Moved all secrets to environment variables/vault
- [ ] Updated database credentials
- [ ] Configured HTTPS with valid certificate
- [ ] Set up rate limiting at reverse proxy
- [ ] Enabled security headers
- [ ] Configured logging
- [ ] Set up monitoring
- [ ] Tested backup/restore procedures
- [ ] Reviewed all configuration files
- [ ] Removed all dummy/test credentials

### Security Verification

- [ ] Run security scan: `mvn dependency-check:check`
- [ ] Test account lockout mechanism
- [ ] Verify PKCE implementation
- [ ] Test JWT validation
- [ ] Check authorization code encryption
- [ ] Verify HTTPS enforcement
- [ ] Test rate limiting
- [ ] Review logs for security events

### Performance Testing

- [ ] Load test with 100 concurrent users
- [ ] Test token generation performance
- [ ] Verify database connection pooling
- [ ] Check memory usage under load
- [ ] Test failover scenarios

---

## Troubleshooting

### Common Issues

**Issue:** Application fails to start - "Authorization code key not found"

**Solution:**
```bash
export AUTHORIZATION_CODE_KEY="your-base64-key-here"
# Restart WildFly
```

**Issue:** Database connection refused

**Solution:**
1. Check PostgreSQL is running: `sudo systemctl status postgresql`
2. Verify connection string in persistence.xml
3. Test connection: `psql -h localhost -U phoenix_user -d phoenix_iam`

**Issue:** "Account locked" but user needs access

**Solution:**
```bash
# Access WildFly CLI
$WILDFLY_HOME/bin/jboss-cli.sh --connect

# Call unlock method (implementation needed in admin endpoint)
# Or restart application to clear in-memory lockouts
```

**Issue:** High memory usage

**Solution:**
```bash
# Increase WildFly heap size
export JAVA_OPTS="-Xms2g -Xmx4g"
```

### Log Locations

- **WildFly Logs:** `$WILDFLY_HOME/standalone/log/server.log`
- **nginx Logs:** `/var/log/nginx/access.log` and `/var/log/nginx/error.log`
- **Apache Logs:** `/var/log/apache2/access.log`

### Support

For issues:
1. Check logs first
2. Review [SECURITY-REPORT.md](SECURITY-REPORT.md)
3. Check [ARCHITECTURE.md](ARCHITECTURE.md)
4. Contact DevOps team

---

**Last Updated:** January 13, 2026
**Maintainer:** DevOps Team
**Status:** Production Ready ✅
