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
| `/etc/afnsec-reputation/reputation.conf` | contains API key and policy |

## This application intergration only supports Nginx compiled with Lua. Only ubuntu apt packages for nginx will work because it comes prepackaged with Lua support. Advanced users can properly bypass this warning and compile lua with nginx.org direct install.

## Deployment

AFNSec-Nginx-Reputation

Enterprise IP reputation enforcement for NGINX powered by the AFNSec Intel API
Protects all vhosts by querying AFNSec’s live intelligence service before requests reach your app.

⚙️ Installation

1️⃣ Clone & install

#Install latest stable version v1.0.0 (Recommended)
```bash
curl -L -o afnsec-nginx-reputation-v1.0.0.tar.gz https://github.com/AFNSec/afnsec-nginx-reputation/archive/refs/tags/v1.0.0.tar.gz
tar -xzf afnsec-nginx-reputation-v1.0.0.tar.gz
sudo chmod +x install.sh
sudo ./install.sh
```
#Install absolutely latest code (Not recommended)

```bash
sudo apt update
sudo apt install -y git
git clone https://github.com/theewick/afnsec-nginx-reputation.git
cd afnsec-nginx-reputation
sudo chmod +x install.sh
sudo ./install.sh
```

🧩 Prompts for your AFNSec API key (hidden input).
Default output is quiet; view logs at /var/log/afnsec-install.log
Use --verbose for full live output:

```bash
sudo ./install.sh --verbose
```
🧹 Uninstallation

To completely remove AFNSec and optionally Lua packages:

```bash
cd afnsec-nginx-reputatio-*
sudo chmod +x uninstall.sh
sudo ./uninstall.sh
```

Removes only AFNSec edits and files; nginx and your sites remain untouched.
Offers to remove Lua modules (libnginx-mod-http-lua, libnginx-mod-http-ndk, lua-cjson).

📄 Logs

Installer transcript: /var/log/afnsec-install.log

Runtime AFNSec events: /var/log/nginx/error.log (default)

🧰 Requirements
Component	Min version	Notes
Ubuntu	22.04 / 24.04	Server or minimal install
nginx	1.24.0+	Must be Ubuntu package (not nginx.org)
Lua modules	from Ubuntu repos	Installed automatically
AFNSec API key	—	Provided by AFNSec SOC
🧾 License

© 2025 AFNSec — All rights reserved.
Enterprise internal use only.
Contact: secops@afnsec.com
 | intel.afnsec.com

🧾 License & Credits

© 2025 AFNSec — All rights reserved | Enterprise use only
Contact: secops@afnsec.com

Docs: intel.afnsec.com

