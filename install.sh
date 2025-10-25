#!/usr/bin/env bash
set -euo pipefail

# =========================
# AFNSec-Nginx-Reputation Installer (Global Enforcement)
# Bullet-proof: verifies Lua modules by actually parsing a temp config.
# =========================

TARBALL_URL="https://github.com/theewick/afnsec-nginx-reputation/archive/refs/tags/v1.0.0.tar.gz"
TARBALL_NAME="afnsec-nginx-reputation-v1.0.0.tar.gz"
WORKDIR="$(mktemp -d /tmp/afnsec-install-XXXXXX)"
API_KEY=""

info(){ echo -e "\e[32m[INFO]\e[0m $*"; }
warn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
err(){  echo -e "\e[31m[ERROR]\e[0m $*"; }
die(){  err "$*"; exit 1; }
cleanup(){ rm -rf "$WORKDIR" >/dev/null 2>&1 || true; }
trap cleanup EXIT

have_candidate() {
  local pc; pc="$(apt-cache policy "$1" || true)"
  echo "$pc" | grep -qE '^  Candidate:\s*[0-9]' || return 1
  echo "$pc" | grep -qi 'nginx.org' && return 1
  return 0
}
pkg_installed_ok() { dpkg-query -W -f='${Status}\n' "$1" 2>/dev/null | grep -q 'install ok installed'; }

ensure_pkg() {
  local pkg="$1"
  if pkg_installed_ok "$pkg"; then
    info "Package present: $pkg"
    return 0
  fi
  have_candidate "$pkg" || die "$pkg not available from Ubuntu archives."
  info "Installing $pkg …"
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$pkg"
  if ! pkg_installed_ok "$pkg"; then
    warn "Package $pkg not in 'install ok installed' state. Reinstalling…"
    DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall "$pkg"
    pkg_installed_ok "$pkg" || die "Failed to install $pkg (unexpected dpkg state)."
  fi
}

# ===== Preflight
[ "$(id -u)" -eq 0 ] || die "Run as root (sudo)."
. /etc/os-release || die "Cannot read /etc/os-release"
case "${ID}-${VERSION_ID}" in ubuntu-22.*|ubuntu-24.*) : ;; *) die "Unsupported OS: ${PRETTY_NAME} (Ubuntu 22/24 required)." ;; esac
if ls /etc/apt/sources.list.d/nginx*.list >/dev/null 2>&1; then die "Detected nginx.org repository. Use Ubuntu nginx packages."; fi

echo
echo "AFNSec API key is required to proceed."
while :; do
  read -r -s -p "Enter AFNSec API Key (hidden): " API_KEY; echo
  [ -n "$API_KEY" ] && break || echo "API key cannot be empty."
done
echo

info "Updating package lists…"
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y curl tar gzip ca-certificates
update-ca-certificates || true

# ===== Ensure nginx + Lua modules truly installed
have_candidate nginx || die "nginx not available from Ubuntu archives."
ensure_pkg nginx
ensure_pkg libnginx-mod-http-ndk
ensure_pkg libnginx-mod-http-lua
ensure_pkg lua-cjson

# Ensure modules-enabled include exists (we rely on distro loader files)
if ! grep -q 'include /etc/nginx/modules-enabled/\*\.conf;' /etc/nginx/nginx.conf; then
  info "Adding modules-enabled include to nginx.conf"
  sed -i '1 a include /etc/nginx/modules-enabled/*.conf;' /etc/nginx/nginx.conf
fi

# ===== Active probe: verify that Lua modules & directives work in a temp config
info "Actively probing Lua support with a temporary nginx config…"
TMP_CONF="$WORKDIR/nginx-probe.conf"
cat > "$TMP_CONF" <<'EOF'
# Probe config for Lua readiness (does not touch system config)
load_module /usr/lib/nginx/modules/ndk_http_module.so;
load_module /usr/lib/nginx/modules/ngx_http_lua_module.so;
events {}
http {
    lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
    lua_ssl_verify_depth 3;
    server { listen 127.0.0.1:65535; }
}
EOF
# If this fails, modules are not actually usable—abort before touching real nginx.conf
nginx -t -c "$TMP_CONF" -g 'pid /tmp/nginx-probe.pid; error_log /dev/null;' \
  || die "Lua modules or directives not loadable by nginx (probe failed)."

# ===== Download & verify release
cd "$WORKDIR"
info "Downloading ${TARBALL_URL}"
curl -fsSL "$TARBALL_URL" -o "$TARBALL_NAME" || die "Failed to download release tarball."
info "Verifying tarball integrity…"
gzip -t "$TARBALL_NAME" || die "gzip -t failed (corrupted tarball)."
info "Extracting release…"
set +o pipefail
TOPDIR="$(tar -tzf "$TARBALL_NAME" | head -n 1 | cut -d/ -f1)" || TOPDIR=""
set -o pipefail
[ -n "$TOPDIR" ] || die "Archive appears empty or unexpected layout."
tar -xzf "$TARBALL_NAME" || die "Extraction failed."
[ -d "$TOPDIR" ] || die "Unexpected archive layout after extraction."

# Validate expected files exist
for f in lua/reputation.lua lua/util.lua conf/afnsec-reputation.conf html/block.html; do
  [ -f "$TOPDIR/$f" ] || die "Missing expected file in release: $f"
done

# ===== Deploy files
info "Deploying AFNSec files…"
mkdir -p /usr/local/share/afnsec-reputation /etc/afnsec-reputation /var/www/afnsec
cp -f "$TOPDIR/lua/reputation.lua" /usr/local/share/afnsec-reputation/
cp -f "$TOPDIR/lua/util.lua"       /usr/local/share/afnsec-reputation/
cp -f "$TOPDIR/conf/afnsec-reputation.conf" /etc/nginx/conf.d/
cp -f "$TOPDIR/html/block.html"    /var/www/afnsec/

# Create runtime config from sample (support both locations)
if [ ! -f /etc/afnsec-reputation/reputation.conf ]; then
  if   [ -f "$TOPDIR/reputation.conf.sample" ]; then
    cp -f "$TOPDIR/reputation.conf.sample" /etc/afnsec-reputation/reputation.conf
  elif [ -f "$TOPDIR/conf/reputation.conf.example" ]; then
    cp -f "$TOPDIR/conf/reputation.conf.example" /etc/afnsec-reputation/reputation.conf
  else
    die "Could not find reputation.conf sample in the release."
  fi
fi
# Always write API key (replace or append)
if grep -q '^API_KEY=' /etc/afnsec-reputation/reputation.conf; then
  sed -i "s|^API_KEY=.*|API_KEY=${API_KEY}|" /etc/afnsec-reputation/reputation.conf
else
  echo "API_KEY=${API_KEY}" >> /etc/afnsec-reputation/reputation.conf
fi
chmod 600 /etc/afnsec-reputation/reputation.conf

# ===== Safe nginx.conf edits (strictly inside http{})
NGINX_CONF="/etc/nginx/nginx.conf"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="/etc/nginx/nginx.conf.bak.${STAMP}"
cp -a "$NGINX_CONF" "$BACKUP"

insert_inside_http() {
  local payload="$1"
  awk -v payload="$payload" '
    BEGIN{http=0;depth=0;inserted=0}
    {
      line=$0
      if (http==0 && match(line,/^[ \t]*http[ \t]*\{/)) { http=1; depth=1; print line; next }
      if (http==1) {
        if (inserted==0) { print payload; inserted=1 }
        # track braces
        nopen=gsub(/\{/,"{",line); nclose=gsub(/\}/,"}",line); depth+=nopen-nclose
        if (depth==0) http=0
        print line; next
      }
      print line
    }
  ' "$NGINX_CONF" > "${NGINX_CONF}.new" && mv "${NGINX_CONF}.new" "$NGINX_CONF"
}

# Add resolver/CA trust block only if absent
if ! grep -q 'lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;' "$NGINX_CONF"; then
  info "Adding resolver/CA trust lines to http{}"
  insert_inside_http \
"    lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
    lua_ssl_verify_depth 3;
    resolver 1.1.1.1 1.0.0.1 9.9.9.9 valid=300s ipv6=off;
    resolver_timeout 2s;"
fi

# Ensure include conf.d and sites-enabled live inside http{} (if layout is non-standard)
if ! grep -q 'include /etc/nginx/conf.d/\*' "$NGINX_CONF"; then
  insert_inside_http "    include /etc/nginx/conf.d/*.conf;"
fi
if ! grep -q 'include /etc/nginx/sites-enabled/\*' "$NGINX_CONF"; then
  insert_inside_http "    include /etc/nginx/sites-enabled/*;"
fi

# Insert global enforcement (once). We insert early in http{} (before includes) for deterministic order.
if ! grep -q 'AFNSEC-GLOBAL-ENFORCE-BEGIN' "$NGINX_CONF"; then
  info "Enabling GLOBAL AFNSec enforcement for ALL vhosts"
  insert_inside_http \
"    # AFNSEC-GLOBAL-ENFORCE-BEGIN
    access_by_lua_block {
      local rep = require(\"reputation\")
      rep.enforce()
    }
    # AFNSEC-GLOBAL-ENFORCE-END"
fi

# Ensure global error_log is at least info
if grep -qE '^[ \t]*error_log[ \t]+/var/log/nginx/error\.log[ \t]*;[ \t]*$' "$NGINX_CONF"; then
  info "Updating global error_log level to info"
  sed -i 's|^\([ \t]*error_log[ \t]\+/var/log/nginx/error\.log\)[ \t]*;[ \t]*$|\1 info;|' "$NGINX_CONF"
elif ! grep -qE '^[ \t]*error_log[ \t]+/var/log/nginx/error\.log' "$NGINX_CONF"; then
  info "Adding global error_log /var/log/nginx/error.log info;"
  awk '
    BEGIN{added=0}
    /^[ \t]*pid[ \t]+\/var\/run\/nginx\.pid;[ \t]*$/ && added==0 {print; print "error_log /var/log/nginx/error.log info;"; added=1; next}
    {print}
  ' "$NGINX_CONF" > "${NGINX_CONF}.new" && mv "${NGINX_CONF}.new" "$NGINX_CONF"
fi

# ===== Validate & reload with rollback
info "Validating nginx configuration…"
if ! nginx -t; then
  warn "nginx -t failed. Restoring backup."
  cp -a "$BACKUP" "$NGINX_CONF"
  nginx -t || die "nginx configuration invalid after restore. Review $NGINX_CONF."
  die "Aborting: restored original nginx.conf."
fi

info "Reloading nginx…"
systemctl reload nginx || die "Failed to reload nginx."

info "AFNSec-Nginx-Reputation installed with GLOBAL enforcement."
cat <<'EOSUM'

Next steps:
- Logs:
  * Startup health & 5-minute stats → GLOBAL: /var/log/nginx/error.log  (level 'info' already set)
  * Per-request decisions → whichever error_log your vhost uses (add per-site error_log if you want a dedicated AFNSec file)

- Test:
  curl -I https://yourdomain.com
  curl -i -H 'X-Forwarded-For: 1.1.1.1' https://yourdomain.com   # expect 403 if that IP is blocked

- Fail-closed test:
  * Set FAIL_MODE=closed in /etc/afnsec-reputation/reputation.conf
  * Reload nginx: systemctl reload nginx
  * Temporarily block egress to api.afnsec.com and hit a NON-excluded path → expect 403 and 'api_fail_block' in logs

- Config security:
  chmod 600 /etc/afnsec-reputation/reputation.conf

Uninstall (manual):
  ./uninstall.sh  # removes AFNSec blocks/files and optionally Lua packages (keeps nginx)
EOSUM
