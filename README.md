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

Enterprise IP reputation enforcement for NGINX powered by AFNSec Intel API

🔧 Overview

AFNSec-Nginx-Reputation adds real-time IP reputation checks directly to NGINX.
It uses Lua to query AFNSec Intel API, cache verdicts, and block or allow traffic before it reaches your app.

📁 Directory layout
Path	Purpose
/usr/local/share/afnsec-reputation/reputation.lua	Main Lua engine
/usr/local/share/afnsec-reputation/util.lua	Helper library
/etc/afnsec-reputation/reputation.conf	Runtime configuration (private)
/etc/nginx/conf.d/afnsec-reputation.conf	Global NGINX loader (init + cache)
/var/www/afnsec/block.html	Block page template
/var/log/nginx/afnsec-reputation.log	Per-site decision log (info level)
⚙️ Requirements

Ubuntu 22 / 24 LTS

nginx with libnginx-mod-http-lua

lua-cjson, ca-certificates

An AFNSec Intel API key

Optional: a proxy/CDN (e.g., Cloudflare)

🧩 1. Install dependencies
sudo apt update
sudo apt install -y nginx libnginx-mod-http-lua lua-cjson ca-certificates
sudo update-ca-certificates


Confirm Lua is available:

nginx -V 2>&1 | grep http_lua_module

🏗️ 2. Create directories
sudo mkdir -p /etc/afnsec-reputation
sudo mkdir -p /usr/local/share/afnsec-reputation
sudo mkdir -p /var/www/afnsec

📜 3. Deploy files

Copy files from this repository to their system paths:

sudo cp lua/*.lua /usr/local/share/afnsec-reputation/
sudo cp conf/afnsec-reputation.conf /etc/nginx/conf.d/
sudo cp html/block.html /var/www/afnsec/


Do not copy reputation.conf.example over your live configuration; instead create your real file in the next step.

🔐 4. Create configuration
sudo tee /etc/afnsec-reputation/reputation.conf >/dev/null <<'EOF'
# === AFNSec-Nginx-Reputation configuration ===
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


Keep this file private — never commit it to GitHub.

🌐 5. Update NGINX globals

Edit /etc/nginx/nginx.conf inside the http {} block and make sure these exist:

lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
lua_ssl_verify_depth 3;
resolver 1.1.1.1 1.0.0.1 9.9.9.9 valid=300s ipv6=off;
resolver_timeout 2s;

🧱 6. Protect your site

In each server {} block you want protected, add:

error_log /var/log/nginx/afnsec-reputation.log info;

# Real client IPs if behind Cloudflare
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

# AFNSec Reputation enforcement
access_by_lua_block {
  local rep = require("reputation")
  rep.enforce()
}


This runs the Lua module for every request before proxying or serving content.

🧪 7. Validate and reload
sudo nginx -t
sudo systemctl reload nginx

🔍 8. Verify operation

Normal traffic should pass as usual.

Known bad IP will get a 403 and your block page.

Logs:

sudo tail -f /var/log/nginx/afnsec-reputation.log


You’ll see entries like:

{"verdict":"suspicious","msg":"live_block","cache":"miss","ip":"1.1.1.1"}

📦 9. Safe rollback

To disable AFNSec enforcement:

sudo mv /etc/nginx/conf.d/afnsec-reputation.conf /etc/nginx/conf.d/afnsec-reputation.conf.disabled
sudo nginx -t && sudo systemctl reload nginx

🧰 10. Optional hardening
Option	Purpose
Firewall non-Cloudflare traffic	Allow only trusted proxy ranges on 443
Per-verdict TTLs	Already implemented: malicious = 1 h, suspicious = 15 min, unknown = 2 min
Fail-open mode	Keeps your site online if AFNSec API times out
Custom block page	Modify /var/www/afnsec/block.html – no reload needed
🪪 11. Logging quick reference
Type	Appears when	Meaning
live_block	New block after API lookup	AFNSec denied the IP
cache_block	Reused previous verdict	Fast cached block
live_allow	New allow (debug mode)	Clean IP
cache_allow	Reused clean verdict	From cache
api_fail_allow	API timeout/failure	Allowed (fail-open)
🧾 12. Security notes

Protect /etc/afnsec-reputation/reputation.conf (chmod 600).

Don’t log sensitive headers or cookies in your access logs.

Rotate /var/log/nginx/afnsec-reputation.log via logrotate if large.

✅ Quick summary
# One-liner overview
sudo apt install -y nginx libnginx-mod-http-lua lua-cjson ca-certificates && \
sudo mkdir -p /etc/afnsec-reputation /usr/local/share/afnsec-reputation /var/www/afnsec && \
sudo cp lua/*.lua /usr/local/share/afnsec-reputation/ && \
sudo cp conf/afnsec-reputation.conf /etc/nginx/conf.d/ && \
sudo cp html/block.html /var/www/afnsec/ && \
sudo nginx -t && sudo systemctl reload nginx



