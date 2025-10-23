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

This module integrates directly into NGINX using Lua to block malicious or suspicious IPs in real time — before traffic reaches your application.

🧩 Compatibility
Build Source	Works	Notes
Ubuntu nginx (apt install nginx libnginx-mod-http-lua)	✅	Recommended – includes dynamic Lua/NDK modules
OpenResty	✅	Lua built-in; works out of the box
nginx.org builds (nginx.org/packages)	❌	Not supported – lacks Lua module
Custom nginx build with Lua	⚙️	Supported only if you manually compile lua-nginx-module + ndk

🧩 Requirements

Ubuntu 22.04 / 24.04 LTS

nginx with libnginx-mod-http-lua

lua-cjson and ca-certificates

AFNSec Intel API key

Optional: Cloudflare or similar proxy (for client IP forwarding)


💡 If your nginx install came from nginx.org, remove that repo and use Ubuntu’s nginx or OpenResty.

📦 Directory Layout
afnsec-nginx-reputation/
├── lua/
│   ├── reputation.lua              # Core Lua logic
│   └── util.lua                    # Utility helpers
├── conf/
│   ├── afnsec-reputation.conf      # Global loader (http{} init + cache)
│   └── reputation.conf.example     # Sample config (no secrets)
└── html/
    └── block.html                  # Minimal white AFNSec block page

⚙️ Installation (Ubuntu 22/24 LTS)
1️⃣ Install Required Packages
sudo apt update
sudo apt install -y nginx libnginx-mod-http-lua libnginx-mod-http-ndk lua-cjson ca-certificates
sudo update-ca-certificates

2️⃣ Enable Dynamic Modules

Ubuntu’s nginx uses dynamic Lua modules, so ensure they load at startup:

# Create module loader snippets if missing
echo 'load_module /usr/lib/nginx/modules/ndk_http_module.so;'     | sudo tee /etc/nginx/modules-enabled/50-mod-http-ndk.conf
echo 'load_module /usr/lib/nginx/modules/ngx_http_lua_module.so;' | sudo tee /etc/nginx/modules-enabled/50-mod-http-lua.conf

# Ensure the directory is included near the top of nginx.conf
grep -q 'modules-enabled' /etc/nginx/nginx.conf || \
sudo sed -i '1 a include /etc/nginx/modules-enabled/*.conf;' /etc/nginx/nginx.conf


🔴 If you skip this step, NGINX will say:
unknown directive "access_by_lua_block"

3️⃣ Add Resolver and CA Trust (inside http {})

Open /etc/nginx/nginx.conf and make sure these lines exist inside the http block:

lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
lua_ssl_verify_depth 3;
resolver 1.1.1.1 1.0.0.1 9.9.9.9 valid=300s ipv6=off;
resolver_timeout 2s;

4️⃣ Deploy AFNSec Files
sudo mkdir -p /usr/local/share/afnsec-reputation /etc/afnsec-reputation /var/www/afnsec

sudo cp lua/*.lua /usr/local/share/afnsec-reputation/
sudo cp conf/afnsec-reputation.conf /etc/nginx/conf.d/
sudo cp html/block.html /var/www/afnsec/
sudo cp conf/reputation.conf.example /etc/afnsec-reputation/reputation.conf
sudo chmod 600 /etc/afnsec-reputation/reputation.conf


Edit /etc/afnsec-reputation/reputation.conf and set your API key:

sudo nano /etc/afnsec-reputation/reputation.conf

5️⃣ Add Enforcement to Your Site

Edit the nginx site you want protected (example: /etc/nginx/sites-available/default):

# Optional: dedicated AFNSec log
error_log /var/log/nginx/afnsec-reputation.log info;

# Cloudflare proxy IP ranges (if used)
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

6️⃣ Reload NGINX
sudo nginx -t
sudo systemctl reload nginx

🔍 Verify

Normal traffic:

curl -I https://yourdomain.com


Simulate a blocked IP:

curl -i -H 'X-Forwarded-For: 1.1.1.1' https://yourdomain.com


→ Should return 403 Forbidden with the AFNSec block page.

Tail logs:

sudo tail -f /var/log/nginx/afnsec-reputation.log


You’ll see entries like:

{"verdict":"suspicious","msg":"live_block","cache":"miss","ip":"1.1.1.1"}

🧾 Log meanings
Log key	Meaning
live_block	New block after AFNSec API lookup
cache_block	Cached verdict triggered a block
live_allow	New allow decision (debug only)
cache_allow	Cached clean result
api_fail_allow	API timeout/failure – allowed (fail-open mode)
🔒 Security Best Practices

Keep /etc/afnsec-reputation/reputation.conf at chmod 600.

Restrict origin access to Cloudflare IPs if you proxy through CF.

Logrotate /var/log/nginx/afnsec-reputation.log if large.

Fail-open mode (FAIL_MODE=open) prevents downtime during AFNSec API outages.

🧰 Troubleshooting

unknown directive "access_by_lua_block"
→ Add this line at the top of /etc/nginx/nginx.conf:

include /etc/nginx/modules-enabled/*.conf;


libnginx-mod-http-lua won’t install / dependency conflict
→ You’re using nginx.org packages. Remove that repo and reinstall Ubuntu’s nginx.

api_fail_allow flooding logs
→ Network or resolver issue. Verify your DNS and CA trust lines inside http {}.

🧾 License & Credits

© AFNSec. All rights reserved.
Enterprise use only.
For support: secops@afnsec.com
 | intel.afnsec.com
