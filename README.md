# AFNSec-Nginx-Reputation

Enterprise-grade NGINX + Lua reputation enforcement module for AFNSec.

## File structure

| Path | Purpose |
|------|----------|
| `lua/reputation.lua` | Core Lua logic |
| `lua/util.lua` | Utility functions |
| `conf/afnsec-reputation.conf` | Global http{} loader (init + cache) |
| `conf/afnsec-reputation-site.conf` | Example TLS site |
| `html/block.html` | Minimal white block page |
| `/etc/afnsec-reputation/reputation.conf` | **Not committed** – contains API key and policy |

## Deployment

AFNSec-Nginx-Reputation

Enterprise-grade IP reputation enforcement for NGINX powered by the AFNSec Intel API.
This module queries the AFNSec reputation service in real time to block known malicious or suspicious IPs before they reach your app.

⚙️ Overview

AFNSec-Nginx-Reputation runs entirely inside NGINX using Lua.
It performs lightweight lookups to https://api.afnsec.com/api/v1/ip/{ip} and caches results locally for rapid enforcement.

🧾 Compatibility Notice

This module requires NGINX compiled with the Lua module.

Build Source	Works	Notes
Ubuntu official nginx (apt install nginx libnginx-mod-http-lua)	✅ Supported	Recommended and simplest
OpenResty	✅ Supported	Lua built in by default
nginx.org repository builds (http://nginx.org/packages/ubuntu)	❌ Not supported	Those binaries do not include Lua
Custom-built nginx with ngx_http_lua_module	⚙️ Supported	Must compile lua-nginx-module + ndk manually

If you use nginx.org’s repo, you must switch to Ubuntu’s nginx packages or use OpenResty.

🧩 Requirements

Ubuntu 22.04 / 24.04 LTS

nginx with libnginx-mod-http-lua

lua-cjson and ca-certificates

AFNSec Intel API key

Optional: Cloudflare or similar proxy (for client IP forwarding)

🛠️ Installation (Ubuntu nginx build)
sudo apt update
sudo apt install -y nginx libnginx-mod-http-lua libnginx-mod-http-ndk lua-cjson ca-certificates
sudo update-ca-certificates


Verify Lua support:

nginx -V 2>&1 | grep http_lua_module


If you don’t see it, you’re on an incompatible nginx build.

🗂️ Directory layout
/usr/local/share/afnsec-reputation/   → Lua engine files (reputation.lua, util.lua)
/etc/afnsec-reputation/               → Runtime configuration (reputation.conf)
/etc/nginx/conf.d/                    → NGINX includes (afnsec-reputation.conf)
/var/www/afnsec/                      → Block page (block.html)
/var/log/nginx/afnsec-reputation.log  → Per-site log

⚙️ Setup Steps
1. Create directories
sudo mkdir -p /etc/afnsec-reputation /usr/local/share/afnsec-reputation /var/www/afnsec

2. Copy files

From this repo:

sudo cp lua/*.lua /usr/local/share/afnsec-reputation/
sudo cp conf/afnsec-reputation.conf /etc/nginx/conf.d/
sudo cp html/block.html /var/www/afnsec/

3. Create configuration
sudo tee /etc/afnsec-reputation/reputation.conf >/dev/null <<'EOF'
API_KEY=<your_api_key_here>
AFNSEC_VERDICT=malicious,suspicious
REQUEST_TIMEOUT=1500
EXCLUDE_LOCATION=/healthz,/status,/assets
AFNSEC_CACHE_EXPIRATION=600
AFNSEC_BLOCK_TEMPLATE_PATH=/var/www/afnsec/block.html
FAIL_MODE=open
RESPECT_XFF=on
LOG_LEVEL=info
EOF
sudo chmod 600 /etc/afnsec-reputation/reputation.conf

🧱 Add to NGINX
In /etc/nginx/nginx.conf → inside http {}
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
lua_ssl_verify_depth 3;
resolver 1.1.1.1 1.0.0.1 9.9.9.9 valid=300s ipv6=off;
resolver_timeout 2s;

In your server {} block
error_log /var/log/nginx/afnsec-reputation.log info;

# (Optional) Cloudflare trusted proxies
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
real_ip_header X-Forwarded-For;

# Reputation enforcement
access_by_lua_block {
  local rep = require("reputation")
  rep.enforce()
}

✅ Validate
sudo nginx -t
sudo systemctl reload nginx

🧪 Test
# Normal request (should be 200)
curl -I https://yourdomain.com

# Simulate malicious IP (from server)
curl -i -H 'X-Forwarded-For: 1.1.1.1' https://yourdomain.com


Expected:

HTTP/1.1 403 Forbidden


Check logs:

sudo tail -f /var/log/nginx/afnsec-reputation.log

🪪 Log meanings
Field	Description
live_block	New API call resulting in a block
cache_block	Reused cached verdict
live_allow	New allow decision (debug mode)
cache_allow	Cached allow decision
api_fail_allow	API timeout or network error; allowed (fail-open)
🔒 Security best practices

Protect your API key file:
/etc/afnsec-reputation/reputation.conf → chmod 600

Restrict origin access:
If behind Cloudflare, firewall your origin to CF IP ranges only.

Rotate logs:
Use logrotate for /var/log/nginx/afnsec-reputation.log.

🚫 Troubleshooting
Symptom	Cause	Fix
libnginx-mod-http-lua won’t install	Using nginx.org repo	Remove that repo or use OpenResty
module not found: resty.core	You installed OpenResty LuaRocks packages	Our code doesn’t use resty.*, remove them
api_fail_allow flood	DNS/TLS issue	Verify resolver + CA bundle in nginx.conf
🧰 Uninstall
sudo rm -rf /etc/afnsec-reputation /usr/local/share/afnsec-reputation /var/www/afnsec
sudo rm /etc/nginx/conf.d/afnsec-reputation.conf
sudo systemctl reload nginx

🧾 License

Copyright © AFNSec
Proprietary – for authorized AFNSec partners and enterprise clients only.
