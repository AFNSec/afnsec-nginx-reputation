#!/usr/bin/env bash
set -euo pipefail

# =========================
# AFNSec-Nginx-Reputation Installer (Global Enforcement)
# =========================

TARBALL_URL="https://github.com/theewick/afnsec-nginx-reputation/archive/refs/tags/v1.0.0.tar.gz"
TARBALL_NAME="afnsec-nginx-reputation-v1.0.0.tar.gz"
WORKDIR=""
API_KEY=""

info(){ echo -e "\e[32m[INFO]\e[0m $*"; }
warn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
err(){  echo -e "\e[31m[ERROR]\e[0m $*"; }
die(){  err "$*"; exit 1; }

have_candidate() {
  local pkg="$1"
  local pc; pc="$(apt-cache policy "$pkg" || true)"
  echo "$pc" | grep -qE '^  Candidate:\s*[0-9]' || return 1
  echo "$pc" | grep -qi 'nginx.org' && return 1
  return 0
}

need_pkg() { dpkg -s "$1" >/dev/null 2>&1 || return 0; return 1; }

# -------- preflight
[ "$(id -u)" -eq 0 ] || die "Please run as root (sudo)."

. /etc/os-release || die "Cannot read /etc/os-release"
case "${ID}-${VERSION_ID}" in
  ubuntu-22.*|ubuntu-24.*) : ;;
  *) die "Unsupported OS: ${PRETTY_NAME}. Use Ubuntu 22/24 (or OpenResty manually)." ;;
esac

# Reject nginx.org apt source
if ls /etc/apt/sources.list.d/nginx*.list >/dev/null 2>&1; then
  die "Detected nginx.org repository. This installer supports Ubuntu nginx only. Remove nginx.org repo and try again."
fi

# ===== Prompt for API key at the beginning (hidden) =====
echo
echo "AFNSec API key is required to proceed."
while :; do
  read -r -s -p "Enter AFNSec API Key (input hidden): " API_KEY; echo
  [ -n "${API_KEY}" ] && break || echo "API key cannot be empty. Please try again."
done
echo

info "Updating package lists…"
apt-get update -y

# Ensure base tools
DEBIAN_FRONTEND=noninteractive apt-get install -y curl tar gzip ca-certificates
update-ca-certificates || true

# nginx must be available from Ubuntu archives
if ! have_candidate nginx; then
  die "nginx package not available from Ubuntu archives (or nginx.org detected)."
fi

# Install nginx if needed
if need_pkg nginx; then
  info "Installing nginx…"
  DEBIAN_FRONTEND=noninteractive apt-get install -y nginx
fi

# Ensure Lua modules are available and installed (non-interactive)
for pkg in libnginx-mod-http-lua libnginx-mod-http-ndk lua-cjson; do
  have_candidate "$pkg" || die "$pkg not available from Ubuntu archives. System not compatible."
done
MISSING_PKGS=()
for pkg in libnginx-mod-http-lua libnginx-mod-http-ndk lua-cjson; do
  if need_pkg "$pkg"; then MISSING_PKGS+=("$pkg"); fi
done
if ((${#MISSING_PKGS[@]})); then
  info "Installing Lua modules: ${MISSING_PKGS[*]} …"
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${MISSING_PKGS[@]}"
fi

# Ensure modules-enabled include exists in nginx.conf (top-level); do NOT add any load_module stubs ourselves
if ! grep -q 'include /etc/nginx/modules-enabled/\*\.conf;' /etc/nginx/nginx.conf; then
  info "Adding 'include /etc/nginx/modules-enabled/*.conf;' to /etc/nginx/nginx.conf"
  sed -i '1 a include /etc/nginx/modules-enabled/*.conf;' /etc/nginx/nginx.conf
fi

# Download release tarball
WORKDIR="$(mktemp -d /tmp/afnsec-install-XXXXXX)"
cd "$WORKDIR"
info "Downloading ${TARBALL_URL}"
curl -fsSL "$TARBALL_URL" -o "$TARBALL_NAME" || die "Failed to download release tarball."

# Verify gzip before extracting
info "Verifying tarball integrity…"
gzip -t "$TARBALL_NAME" || die "gzip -t failed: corrupted tarball."

# Determine top directory name dynamically and extract
TOPDIR="$(tar -tzf "$TARBALL_NAME" | head -1 | cut -d/ -f1)"
tar -xzf "$TARBALL_NAME"
[ -d "$TOPDIR" ] || die "Unexpected archive layout."

# Validate repo content (loader + Lua + block page)
for f in lua/reputation.lua lua/util.lua conf/afnsec-reputation.conf html/block.html; do
  [ -f "$TOPDIR/$f" ] || die "Missing expected file in release: $f"
done

# Deploy files
info "Deploying AFNSec files…"
mkdir -p /usr/local/share/afnsec-reputation /etc/afnsec-reputation /var/www/afnsec
cp -f "$TOPDIR/lua/reputation.lua" /usr/local/share/afnsec-reputation/
cp -f "$TOPDIR/lua/util.lua"       /usr/local/share/afnsec-reputation/
cp -f "$TOPDIR/conf/afnsec-reputation.conf" /etc/nginx/conf.d/
cp -f "$TOPDIR/html/block.html"    /var/www/afnsec/

# Create runtime config from sample if not present (support both sample locations)
if [ ! -f /etc/afnsec-reputation/reputation.conf ]; then
  if   [ -f "$TOPDIR/reputation.conf.sample" ]; then
    cp -f "$TOPDIR/reputation.conf.sample" /etc/afnsec-reputation/reputation.conf
  elif [ -f "$TOPDIR/conf/reputation.conf.example" ]; then
    cp -f "$TOPDIR/conf/reputation.conf.example" /etc/afnsec-reputation/reputation.conf
  else
    die "Could not find reputation.conf sample in the release."
  fi
  chmod 600 /etc/afnsec-reputation/reputation.conf
fi

# Always write the API key (replace or append API_KEY=…)
if grep -q '^API_KEY=' /etc/afnsec-reputation/reputation.conf; then
  sed -i "s|^API_KEY=.*|API_KEY=${API_KEY}|" /etc/afnsec-reputation/reputation.conf
else
  echo "API_KEY=${API_KEY}" >> /etc/afnsec-reputation/reputation.conf
fi
chmod 600 /etc/afnsec-reputation/reputation.conf

# Backup nginx.conf once
STAMP="$(date +%Y%m%d-%H%M%S)"
cp -a /etc/nginx/nginx.conf "/etc/nginx/nginx.conf.bak.${STAMP}"

# Ensure resolver + CA trust inside http{}
if ! grep -q 'lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;' /etc/nginx/nginx.conf; then
  info "Adding resolver/CA trust lines to http{}"
  awk '
    BEGIN{added=0}
    /http[[:space:]]*\{/ && added==0 {
      print;
      print "    lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;";
      print "    lua_ssl_verify_depth 3;";
      print "    resolver 1.1.1.1 1.0.0.1 9.9.9.9 valid=300s ipv6=off;";
      print "    resolver_timeout 2s;";
      added=1; next
    }
    { print }
  ' /etc/nginx/nginx.conf > /etc/nginx/nginx.conf.new && mv /etc/nginx/nginx.conf.new /etc/nginx/nginx.conf
fi

# Insert global enforcement access_by_lua_block (once, above sites-enabled include)
if ! grep -q 'AFNSEC-GLOBAL-ENFORCE-BEGIN' /etc/nginx/nginx.conf; then
  info "Enabling global AFNSec enforcement for ALL vhosts"
  awk '
    BEGIN{done=0}
    /include[[:space:]]+\/etc\/nginx\/sites-enabled\/\*;/ && done==0 {
      print "    # AFNSEC-GLOBAL-ENFORCE-BEGIN";
      print "    access_by_lua_block {";
      print "      local rep = require(\"reputation\")";
      print "      rep.enforce()";
      print "    }";
      print "    # AFNSEC-GLOBAL-ENFORCE-END";
      print;
      done=1; next
    }
    { print }
  ' /etc/nginx/nginx.conf > /etc/nginx/nginx.conf.new && mv /etc/nginx/nginx.conf.new /etc/nginx/nginx.conf
else
  info "Global enforcement already present (skipping)."
fi

# Validate and reload
info "Validating nginx configuration…"
if ! nginx -t; then
  warn "nginx -t failed. Restoring backup."
  cp -a "/etc/nginx/nginx.conf.bak.${STAMP}" /etc/nginx/nginx.conf
  nginx -t || die "nginx configuration invalid after restore. Please review /etc/nginx/nginx.conf."
  die "Aborting due to invalid configuration. No changes applied."
fi

info "Reloading nginx…"
systemctl reload nginx
info "AFNSec-Nginx-Reputation installed with GLOBAL enforcement."

cat <<'EOSUM'

Next steps:
- Logs:
  * Startup health & 5-minute stats → GLOBAL: /var/log/nginx/error.log  (set to 'info' to see health OK lines)
  * Per-request decisions → whichever error_log your vhost uses (set per-site error_log to keep AFNSec logs separate)

- Test:
  curl -I https://yourdomain.com
  curl -i -H 'X-Forwarded-For: 1.1.1.1' https://yourdomain.com   # expect 403 if that IP is blocked

- Fail-closed test:
  * Set FAIL_MODE=closed in /etc/afnsec-reputation/reputation.conf
  * Reload nginx: systemctl reload nginx
  * Temporarily block egress to api.afnsec.com and hit a NON-excluded path → expect 403 and 'api_fail_block' in logs

- Config security:
  chmod 600 /etc/afnsec-reputation/reputation.conf

Uninstall (manual steps):
- Remove AFNSEC-GLOBAL-ENFORCE block from /etc/nginx/nginx.conf and reload nginx.
- Optionally remove /etc/nginx/conf.d/afnsec-reputation.conf and /usr/local/share/afnsec-reputation/.

EOSUM

rm -rf "$WORKDIR"
exit 0
