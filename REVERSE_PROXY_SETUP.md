# Reverse Proxy Setup Guide for Issuerr

## Overview

This guide covers setting up a reverse proxy (nginx or Traefik) to access Issuerr via HTTPS with a custom domain like `https://something.yourdomain.com`.

**Benefits of Reverse Proxy:**
- ✅ HTTPS/SSL encryption
- ✅ Custom domain access
- ✅ Centralized certificate management
- ✅ Additional security headers
- ✅ Hide internal ports

---

## 🎯 Important: Dual-Access Support

**Issuerr supports both HTTP and HTTPS access simultaneously!**

You can access your Issuerr instance via:
- 🏠 **Local HTTP:** `http://10.0.0.1:5000` (convenience)
- 🌐 **Domain HTTPS:** `https://something.yourdomain.com` (security)

**How it works:**
- Issuerr automatically detects if requests come through HTTPS reverse proxy
- Session cookies get the `Secure` flag **only** when accessed via HTTPS
- This provides maximum security for remote access while keeping local access working

**Key Requirement:**
Your reverse proxy **must** send the `X-Forwarded-Proto` header. All configurations in this guide include this header - just follow the instructions and it will work automatically!

---

## 🔧 Option 1: Nginx Reverse Proxy

### Prerequisites

```bash
# Install nginx
sudo apt update
sudo apt install nginx

# Install certbot for Let's Encrypt SSL
sudo apt install certbot python3-certbot-nginx
```

### Basic Configuration

Create nginx config file:
```bash
sudo nano /etc/nginx/sites-available/issuerr
```

**Configuration:**
```nginx
server {
    listen 80;
    server_name something.yourdomain.com;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name something.yourdomain.com;

    # SSL certificate paths (will be added by certbot)
    ssl_certificate /etc/letsencrypt/live/something.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/something.yourdomain.com/privkey.pem;

    # SSL security settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Proxy settings
    location / {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        
        # Forward real IP and protocol
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        
        # WebSocket support (if needed in future)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffering
        proxy_buffering off;
    }

    # Increase max upload size if needed
    client_max_body_size 10M;

    # Logging
    access_log /var/log/nginx/issuerr.access.log;
    error_log /var/log/nginx/issuerr.error.log;
}
```

### Enable the Site

```bash
# Enable the site
sudo ln -s /etc/nginx/sites-available/issuerr /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Restart nginx
sudo systemctl restart nginx
```

### Get SSL Certificate

```bash
# Obtain Let's Encrypt certificate
sudo certbot --nginx -d something.yourdomain.com

# Follow the prompts
# Certbot will automatically update your nginx config with SSL settings
```

### Auto-Renewal Setup

```bash
# Test renewal
sudo certbot renew --dry-run

# Certbot automatically sets up a cron job/systemd timer for renewal
# Verify it's scheduled:
sudo systemctl status certbot.timer
```

---

## 🐳 Option 2: Traefik (Docker-based)

### Prerequisites

You should already have Docker and docker-compose installed.

### Directory Structure

```bash
mkdir -p ~/traefik
cd ~/traefik
```

### Create Traefik Configuration

**traefik.yml:**
```yaml
# Static configuration
api:
  dashboard: true
  insecure: false

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"

certificatesResolvers:
  letsencrypt:
    acme:
      email: your-email@example.com  # Change this
      storage: /letsencrypt/acme.json
      httpChallenge:
        entryPoint: web

providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
    network: media
```

### Create docker-compose.yml for Traefik

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    container_name: traefik
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik.yml:/traefik.yml:ro
      - ./letsencrypt:/letsencrypt
    networks:
      - media

networks:
  media:
    external: true
```

### Start Traefik

```bash
# Create acme.json with correct permissions
mkdir -p letsencrypt
touch letsencrypt/acme.json
chmod 600 letsencrypt/acme.json

# Start Traefik
docker-compose up -d
```

### Update Issuerr docker-compose.yml

Add Traefik labels to your Issuerr container:

```yaml
version: '3.8'

services:
  issuerr:
    build: .
    container_name: issuerr
    ports:
      - "5000:5000"  # Keep for local access
    volumes:
      - ./config:/config
    restart: unless-stopped
    environment:
      - TZ=America/New_York
      - PUID=1000
      - PGID=1000
    networks:
      - media
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETUID
      - SETGID
      - DAC_OVERRIDE
    labels:
      # Enable Traefik
      - "traefik.enable=true"
      
      # HTTP router (will redirect to HTTPS)
      - "traefik.http.routers.issuerr.rule=Host(`something.yourdomain.com`)"
      - "traefik.http.routers.issuerr.entrypoints=web"
      
      # HTTPS router
      - "traefik.http.routers.issuerr-secure.rule=Host(`something.yourdomain.com`)"
      - "traefik.http.routers.issuerr-secure.entrypoints=websecure"
      - "traefik.http.routers.issuerr-secure.tls=true"
      - "traefik.http.routers.issuerr-secure.tls.certresolver=letsencrypt"
      
      # Service
      - "traefik.http.services.issuerr.loadbalancer.server.port=5000"
      
      # Security headers
      - "traefik.http.middlewares.issuerr-headers.headers.sslredirect=true"
      - "traefik.http.middlewares.issuerr-headers.headers.stsSeconds=31536000"
      - "traefik.http.middlewares.issuerr-headers.headers.stsIncludeSubdomains=true"
      - "traefik.http.middlewares.issuerr-headers.headers.stsPreload=true"
      - "traefik.http.middlewares.issuerr-headers.headers.frameDeny=true"
      - "traefik.http.middlewares.issuerr-headers.headers.contentTypeNosniff=true"
      - "traefik.http.middlewares.issuerr-headers.headers.browserXssFilter=true"
      - "traefik.http.middlewares.issuerr-headers.headers.referrerPolicy=strict-origin-when-cross-origin"
      
      # Apply middleware
      - "traefik.http.routers.issuerr-secure.middlewares=issuerr-headers"

networks:
  media:
    external: true
```

### Restart Issuerr

```bash
cd ~/Issuerr
docker-compose down
docker-compose up -d
```

---

## 🌐 DNS Configuration

Before accessing via domain, configure DNS:

### Option 1: Public Domain
If using a public domain (like yourdomain.com):

1. Log into your domain registrar
2. Add an A record:
   ```
   Type: A
   Name: something.yourdomain.com
   Value: YOUR_PUBLIC_IP
   TTL: 3600
   ```

### Option 2: Local DNS (Internal Only)
If only accessing from local network:

1. Edit your router's DNS settings or local DNS server
2. Add local DNS entry:
   ```
   something.yourdomain.com → 10.0.0.1
   ```

### Option 3: Hosts File (Single Computer)
For testing or single-device access:

**Linux/Mac:**
```bash
sudo nano /etc/hosts
```

**Windows:**
```
notepad C:\Windows\System32\drivers\etc\hosts
```

Add:
```
10.0.0.1    something.yourdomain.com
```

---

## 🔒 Security Considerations

### 1. Firewall Configuration

**If using UFW (Ubuntu):**
```bash
# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Block direct access to Issuerr port (optional)
sudo ufw deny 5000/tcp

# Enable firewall
sudo ufw enable
```

**If using firewalld (CentOS/RHEL):**
```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

### 2. Session Cookie Security with HTTPS (Already Implemented!)

**Good news:** Issuerr automatically handles session cookie security dynamically!

**How it works:**
- When accessed via **HTTP** (local IP): Session cookies work normally
- When accessed via **HTTPS** (domain): Session cookies get the `Secure` flag automatically
- No configuration needed - it just works!

**Technical Details:**

Issuerr detects HTTPS by checking the `X-Forwarded-Proto` header sent by your reverse proxy:

```python
@app.before_request
def before_request():
    # Set Secure cookie flag dynamically based on request protocol
    if request.headers.get('X-Forwarded-Proto') == 'https':
        app.config['SESSION_COOKIE_SECURE'] = True  # Secure flag ON
    else:
        app.config['SESSION_COOKIE_SECURE'] = False  # Secure flag OFF
```

**This means:**
✅ Local access works: `http://10.0.0.1:5000` (no Secure flag)
✅ Domain access works: `https://something.yourdomain.com` (with Secure flag)
✅ Both work simultaneously with appropriate security!

**Important:** Your reverse proxy **must** send the `X-Forwarded-Proto` header. The nginx and Traefik configurations in this guide already include this:

**Nginx (line 77 above):**
```nginx
proxy_set_header X-Forwarded-Proto $scheme;  # ← Already included!
```

**Traefik:**
```
Automatically sets X-Forwarded-Proto ✅
```

**No additional configuration needed!**

### 3. Additional Nginx Security

Add to nginx config:
```nginx
# Rate limiting
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;

server {
    # ... existing config ...
    
    location /login {
        limit_req zone=login burst=3;
        proxy_pass http://localhost:5000;
        # ... other proxy settings ...
    }
    
    location / {
        limit_req zone=general burst=20;
        proxy_pass http://localhost:5000;
        # ... other proxy settings ...
    }
}
```

---

## 📊 Testing Your Setup

### 1. Test HTTP → HTTPS Redirect
```bash
curl -I http://something.yourdomain.com
# Should return: 301 Moved Permanently
# Location: https://something.yourdomain.com
```

### 2. Test HTTPS Access
```bash
curl -I https://something.yourdomain.com
# Should return: 200 OK
```

### 3. Test SSL Certificate
```bash
# Check certificate details
openssl s_client -connect something.yourdomain.com:443 -servername something.yourdomain.com

# Or use online tool:
# https://www.ssllabs.com/ssltest/
```

### 4. Test Security Headers
```bash
curl -I https://something.yourdomain.com | grep -i "strict-transport\|x-frame\|x-content"
```

Should show:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
```

### 5. Test Dual-Access Support (HTTP + HTTPS)

**Test that both local and domain access work:**

```bash
# Test 1: Local HTTP access works
curl -v http://10.0.0.1:5000/login 2>&1 | grep -i "< HTTP"
# Should return: HTTP/1.1 200 OK

# Test 2: Domain HTTPS access works
curl -v https://something.yourdomain.com/login 2>&1 | grep -i "< HTTP"
# Should return: HTTP/2 200

# Test 3: Login via local IP (HTTP)
curl -v -X POST http://10.0.0.1:5000/login \
  -d "username=admin&password=yourpassword" \
  -c cookies-local.txt 2>&1 | grep -i "set-cookie"
# Cookie should NOT have Secure flag

# Test 4: Login via domain (HTTPS)
curl -v -X POST https://something.yourdomain.com/login \
  -d "username=admin&password=yourpassword" \
  -c cookies-domain.txt 2>&1 | grep -i "set-cookie"
# Cookie SHOULD have Secure flag

# Verify cookies
cat cookies-local.txt | grep session
# Should see: session cookie WITHOUT "Secure"

cat cookies-domain.txt | grep session
# Should see: session cookie WITH "Secure"
```

**Expected Result:**
- ✅ Both HTTP (local) and HTTPS (domain) access work
- ✅ HTTP login cookies work for local access
- ✅ HTTPS login cookies have Secure flag
- ✅ No need to choose - both work simultaneously!

### 6. Test Application Functions
- ✅ Login works
- ✅ Configuration saves
- ✅ Webhooks received
- ✅ Password change works

---

## 🔧 Troubleshooting

### Issue: 502 Bad Gateway

**Cause:** Nginx can't reach Issuerr

**Solutions:**
```bash
# Check Issuerr is running
docker ps | grep issuerr

# Check Issuerr logs
docker logs issuerr

# Check Issuerr is accessible locally
curl http://localhost:5000/api/health

# Check nginx error logs
sudo tail -f /var/log/nginx/issuerr.error.log
```

### Issue: Certificate Not Valid

**Cause:** DNS not pointing to server or firewall blocking port 80

**Solutions:**
```bash
# Verify DNS resolves correctly
nslookup something.yourdomain.com

# Verify port 80 is open
sudo netstat -tulpn | grep :80

# Try obtaining cert manually
sudo certbot certonly --standalone -d something.yourdomain.com
```

### Issue: Login Fails via Domain but Works Locally

**Cause:** Session cookies not being set properly

**Check:**
- Browser dev tools → Application → Cookies
- Should see session cookie for your domain
- Check SameSite attribute

**Solution:**
Make sure nginx is forwarding headers correctly:
```nginx
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Proto $scheme;
```

### Issue: Traefik Can't Get Certificate

**Cause:** Port 80 not accessible or DNS not configured

**Solutions:**
```bash
# Check Traefik logs
docker logs traefik

# Verify port 80 is accessible from internet
# Use online tool: https://www.yougetsignal.com/tools/open-ports/

# Check acme.json permissions
ls -l letsencrypt/acme.json
# Should be: -rw------- (600)
```

---

## 📱 Access Patterns

After setup, you'll have multiple ways to access Issuerr:

### Local Network:
- `http://10.0.0.1:5000` ← Direct access
- `http://localhost:5000` ← On the server itself
- `https://something.yourdomain.com` ← Via reverse proxy (local DNS)

### Internet (if ports forwarded):
- `https://something.yourdomain.com` ← Secure public access

**Recommendation:** 
- Use domain for regular access (HTTPS, secure)
- Keep local IP access for emergency/troubleshooting

---

## 🔐 Production Checklist

Before going live:

- [ ] SSL certificate obtained and valid
- [ ] HTTPS redirect working (HTTP → HTTPS)
- [ ] Security headers present
- [ ] DNS configured correctly
- [ ] Firewall rules set
- [ ] Rate limiting configured (nginx or in-app)
- [ ] Tested login via domain
- [ ] Tested webhook reception
- [ ] Logs monitored for errors
- [ ] Certificate auto-renewal tested
- [ ] Backup of nginx/traefik configs

---

## 📚 Additional Resources

**Let's Encrypt:**
- https://letsencrypt.org/docs/

**Nginx:**
- https://nginx.org/en/docs/

**Traefik:**
- https://doc.traefik.io/traefik/

**SSL Labs Test:**
- https://www.ssllabs.com/ssltest/

**Security Headers:**
- https://securityheaders.com/

---

## Summary

✅ **HTTPS encryption** protects your credentials in transit  
✅ **Custom domain** provides professional access  
✅ **Security headers** add multiple layers of protection  
✅ **Rate limiting** prevents brute force at proxy level  
✅ **Centralized certs** simplifies SSL management  

**Next:** Monitor your setup and keep certificates renewed automatically!
