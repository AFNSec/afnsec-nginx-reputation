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

🛡️ AFNSec-Nginx-Reputation

Enterprise IP reputation enforcement for NGINX powered by the AFNSec Intel API

AFNSec-Nginx-Reputation runs natively inside NGINX using Lua to block malicious or suspicious IPs before they reach your web applications.

⚙️ Compatibility
NGINX Build	Works	Notes
Ubuntu nginx (apt install nginx libnginx-mod-http-lua)	
✅ Supported	Recommended — includes dynamic Lua/NDK modules
OpenResty	✅ Supported	Lua built-in; no extra steps
nginx.org builds (nginx.org/packages)	❌ Not supported	Missing Lua module — will not work
Custom nginx + lua-nginx-module	⚙️ Advanced	Must compile Lua module manually and rebuild on updates

⚠️ If your system uses the nginx.org repo, remove it and install Ubuntu’s nginx or OpenResty.

Email AFNSec SOC for API KEY

🧩 Installation
For Ubuntu (Recommended)
Step 1 — Install Required Packages
```bash
sudo apt update
sudo apt install -y nginx libnginx-mod-http-lua libnginx-mod-http-ndk lua-cjson ca-certificates
sudo update-ca-certificates
```
Step 2 — Enable Dynamic Lua Modules

Ubuntu’s nginx uses dynamic modules.
Make sure they are loaded at startup:

```bash
# Create loader snippets if missing
echo 'load_module /usr/lib/nginx/modules/ndk_http_module.so;' | sudo tee /etc/nginx/modules-enabled/50-mod-http-ndk.conf
echo 'load_module /usr/lib/nginx/modules/ngx_http_lua_module.so;' | sudo tee /etc/nginx/modules-enabled/50-mod-http-lua.conf
```

# Ensure nginx loads them at startup
```bash
grep -q 'modules-enabled' /etc/nginx/nginx.conf || \
sudo sed -i '1 a include /etc/nginx/modules-enabled/*.conf;' /etc/nginx/nginx.conf
```

💡 If you skip this step, NGINX will show:
unknown directive "access_by_lua_block"

Step 3 — Add Resolver and CA Trust

Add these lines inside the http {} block in /etc/nginx/nginx.conf:

```nginx
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
lua_ssl_verify_depth 3;
resolver 1.1.1.1 1.0.0.1 9.9.9.9 valid=300s ipv6=off;
resolver_timeout 2s;
```

Step 4 — Deploy AFNSec Files

```bash
sudo mkdir -p /usr/local/share/afnsec-reputation /etc/afnsec-reputation /var/www/afnsec

sudo cp lua/*.lua /usr/local/share/afnsec-reputation/
sudo cp conf/afnsec-reputation.conf /etc/nginx/conf.d/
sudo cp html/block.html /var/www/afnsec/
sudo cp conf/reputation.conf.example /etc/afnsec-reputation/reputation.conf

sudo chmod 600 /etc/afnsec-reputation/reputation.conf

```

Edit /etc/afnsec-reputation/reputation.conf and set your API key:

```bash
sudo nano /etc/afnsec-reputation/reputation.conf
```
Step 5 — Add Enforcement to Your Site

In the nginx site you want to protect (for example, /etc/nginx/sites-available/default):

```nginx
error_log /var/log/nginx/afnsec-reputation.log info;

# (Optional) Cloudflare trusted proxy ranges
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

# AFNSec reputation enforcement
access_by_lua_block {
  local rep = require("reputation")
  rep.enforce()
}
```
Step 6 — Validate and Reload
```bash
sudo nginx -t
sudo systemctl reload nginx
```

🧪 Verification
✅ Normal Request

```bash
curl -I https://yourdomain.com
```

🚫 Simulate Block
```bash
curl -i -H 'X-Forwarded-For: 1.1.1.1' https://yourdomain.com
```


Expected:

HTTP/1.1 403 Forbidden

📜 View Logs

```bash
sudo tail -f /var/log/nginx/afnsec-reputation.log
```

🔍 Log Reference
Key	Meaning
live_block	New AFNSec lookup resulting in a block
cache_block	Cached block verdict reused
live_allow	New allow decision (debug mode)
cache_allow	Cached allow decision reused
api_fail_allow	AFNSec API timed out — request allowed (fail-open)
🔒 Security Recommendations

Restrict config file permissions:

```bash
chmod 600 /etc/afnsec-reputation/reputation.conf
```


Fail-open (FAIL_MODE=open) ensures uptime during API outages.

Rotate /var/log/nginx/afnsec-reputation.log with logrotate.

If behind Cloudflare, firewall your origin to only allow Cloudflare IPs.

🧰 Troubleshooting
❌ Unknown Directive access_by_lua_block

Add this line near the top of /etc/nginx/nginx.conf:

```bash
include /etc/nginx/modules-enabled/*.conf;
```
❌ Lua Package Install Conflict

You’re likely using the nginx.org repo.
Remove it and reinstall Ubuntu’s nginx:

```bash
sudo rm -f /etc/apt/sources.list.d/nginx.list
sudo apt update
sudo apt install nginx libnginx-mod-http-lua
```

⚠️ Frequent api_fail_allow

Indicates DNS or TLS issue.
Check your resolver and CA config in http {}.

📜 License

© 2025 AFNSec — All rights reserved
Enterprise use only.

Contact: secops@afnsec.com

Docs: intel.afnsec.com

⚡ Quick One-Line Install (Ubuntu nginx)

```bash
sudo apt install -y nginx libnginx-mod-http-lua libnginx-mod-http-ndk lua-cjson ca-certificates && \
sudo sed -i '1 a include /etc/nginx/modules-enabled/*.conf;' /etc/nginx/nginx.conf && \
sudo mkdir -p /usr/local/share/afnsec-reputation /etc/afnsec-reputation /var/www/afnsec && \
sudo cp lua/*.lua /usr/local/share/afnsec-reputation/ && \
sudo cp conf/afnsec-reputation.conf /etc/nginx/conf.d/ && \
sudo cp html/block.html /var/www/afnsec/ && \
sudo cp conf/reputation.conf.example /etc/afnsec-reputation/reputation.conf && \
sudo chmod 600 /etc/afnsec-reputation/reputation.conf && \
sudo nginx -t && sudo systemctl reload nginx
```

🧾 License & Credits

© AFNSec. All rights reserved.
Enterprise use only.
For support: secops@afnsec.com
 | intel.afnsec.com
