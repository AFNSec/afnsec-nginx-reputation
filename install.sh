#!/usr/bin/env bash
set -euo pipefail

# =========================
# AFNSec-Nginx-Reputation Installer (Global Enforcement for ALL vhosts)
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
  local pc; pc="$(apt-cache policy "$1" || true)"
  echo "$pc" | grep -qE '^  Candidate:\s*[0-9]' || return 1
  echo "$pc" | grep -qi 'nginx.org' && return 1
  return 0
}
need_pkg(){ dpkg -s "$1" >/dev/null 2>&1 || return 0; return 1; }

# ========== Preflight ==========
[ "$(id -u)" -eq 0 ] || die "Run as root (sudo)."

. /etc/os-release || die "Cannot read /etc/os-release"
case "${ID}-${VERSION_ID}" in
  ubuntu-22.*|ubuntu-24.*) : ;;
  *) die "Unsupported OS: ${PRETTY_NAME}. Use Ubuntu 22/24 (or OpenResty)." ;;
esac

# Hard-block nginx.org repo
if ls /etc/apt/sources.list.d/nginx*.list >/dev/null 2>&1; then
  die "Detected nginx.org repository. Use Ubuntu nginx packages."
fi

# Prompt for API key upfront
echo
echo "AFNSec API key is required to proceed."
while :; do
  read -r -s -p "Enter AFNSec API Key (hidden): " API_KEY; echo
  [ -n "${API_KEY}" ] && break || echo "API key cannot be empty."
done
echo

info "Updating package lists…"
apt-get update -y

# base tools
DEBIAN_FRONTEND=noninteractive apt-get install -y curl tar gzip ca-certificates
update-ca-certificates || true

# nginx + Lua modules availability
have_candidate nginx || die "nginx package not available from Ubuntu archives."
for pkg in libnginx-mod-http-lua libnginx-mod-http-ndk lua-cjson; do
  have_candidate "$pkg" || die "$pkg not available from Ubuntu archives."
done

# install if missing
if need_pkg nginx; then
  info "Installing nginx…"
  DEBIAN_FRONTEND=noninteractive apt-get install -y nginx
fi
MISSING_PKGS=()
for pkg in libnginx-mod-http-lua libnginx-mod-http-ndk lua-cjson; do
  if need_pkg "$pkg"; then MISSING_PKGS+=("$pkg"); fi
done
if ((${#MISSING_PKGS[@]})); then
  info "Installing Lua modules: ${MISSING_PKGS[*]} …"
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${MISSING_PKGS[@]}"
fi

# Ensure modules-enabled include exists (we rely on distro loaders; we do NOT create load_module stubs ourselves)
if ! grep -q 'include /etc/nginx/modules-enabled/\*\.conf;' /etc/nginx/nginx.conf; then
  info "Adding modules-enabled include to nginx.conf"
  sed -i '1 a include /etc/nginx/modules-enabled/*.conf;' /etc/nginx/nginx.conf
fi

# ========== Download & verify release ==========
WORKDIR="$(mktemp -d /tmp/afnsec-install-XXXXXX)"
cd "$WORKDIR"
info "Downloading ${TARBALL_URL}"
curl -fsSL "$TARBALL_URL" -o "$TARBALL_NAME" || die "Failed to download release tarball."
info "Verifying tarball integrity…"
gzip -t "$TARBALL_NAME" || die "gzip -t failed (corrupted tarball)."

# Extract first (robust), then discover top directory by glob
info "Extracting release…"
tar -xzf "$TARBALL_NAME" || die "Extraction failed."
TOPDIR="$(find . -maxdepth 1 -type d -name 'afnsec-nginx-reputation-*' -printf '%f\n' | head -1)"
[ -n "$TOPDIR" ] || die "Unexpected archive layout: top directory not found."

# Validate expected files exist
for f in lua/reputation.lua lua/util.lua conf/afnsec-reputation.conf html/block.html; do
  [ -f "$TOPDIR/$f" ] || die "Missing expected file in release: $f"
done

# ========== Deploy files ==========
info "Deploying AFNSec files…"
mkdir -p /usr/local/share/afnsec-reputation /etc/afnsec-reputation /var/www/afnsec
cp -f "$TOPDIR/lua/reputation.lua" /usr/local/share/afnsec-reputation/
cp -f "$TOPDIR/lua/util.lua"       /usr/local/share/afnsec-reputation/
cp -f "$TOPDIR/conf/afnsec-reputation.conf" /etc/nginx/conf.d/
cp -f "$TOPDIR/html/block.html"    /var/www/afnsec/

# Create runtime config from sample if not present
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

# ========== Safe nginx.conf edits (HTTP-context only) ==========
STAMP="$(date +%Y%m%d-%H%M%S)"
cp -a /etc/nginx/nginx.conf "/etc/nginx/nginx.conf.bak.${STAMP}"

# Helper: idempotent injection inside http{} using awk with scope tracking
insert_inside_http() {
  local payload="$*"
  awk -v payload="$payload" '
    BEGIN{http=0;depth=0;inserted=0}
    {
      line=$0
      if (http==0) {
        print line
        if (match(line,/^[ \t]*http[ \t]*\{/)) { http=1; depth=1 }
        next
      }
      if (http==1) {
        if (inserted==0) { print payload; inserted=1 }
        print line
        # track brace nesting to know when http ends
        nopen=gsub(/\{/,"{",line); nclose=gsub(/\}/,"}",line); depth+=nopen-nclose
        if (depth==0) { http=0 }
        next
      }
    }
  ' /etc/nginx/nginx.conf > /etc/nginx/nginx.conf.new && mv /etc/nginx/nginx.conf.new /etc/nginx/nginx.conf
}

# Ensure resolver/CA trust block is inside http{} (only if not already present)
if ! grep -q 'lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;' /etc/nginx/nginx.conf; then
  info "Adding resolver/CA trust lines to http{}"
  insert_inside_http \
"    lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
    lua_ssl_verify_depth 3;
    resolver 1.1.1.1 1.0.0.1 9.9.9.9 valid=300s ipv6=off;
    resolver_timeout 2s;"
fi

# Ensure include conf.d and sites-enabled are inside http{} (if layout is non-standard)
if ! grep -q 'include /etc/nginx/conf.d/\*' /etc/nginx/nginx.conf; then
  info "Adding include /etc/nginx/conf.d/*.conf inside http{}"
  insert_inside_http "    include /etc/nginx/conf.d/*.conf;"
fi
if ! grep -q 'include /etc/nginx/sites-enabled/\*' /etc/nginx/nginx.conf; then
  info "Adding include /etc/nginx/sites-enabled/* inside http{}"
  insert_inside_http "    include /etc/nginx/sites-enabled/*;"
fi

# Insert global enforcement (once): before sites-enabled include if present, else early in http{}
if ! grep -q 'AFNSEC-GLOBAL-ENFORCE-BEGIN' /etc/nginx/nginx.conf; then
  info "Enabling GLOBAL AFNSec enforcement for ALL vhosts"
  awk '
    BEGIN{http=0;depth=0;done=0}
    {
      line=$0
      if (http==0) {
        print line
        if (match(line,/^[ \t]*http[ \t]*\{/)) { http=1; depth=1 }
        next
      }
      if (http==1) {
        if (done==0 && line ~ /include[[:space:]]+\/etc\/nginx\/sites-enabled\/\*\;/) {
          print "    # AFNSEC-GLOBAL-ENFORCE-BEGIN"
          print "    access_by_lua_block {"
          print "      local rep = require(\"reputation\")"
          print "      rep.enforce()"
          print "    }"
          print "    # AFNSEC-GLOBAL-ENFORCE-END"
          print line
          done=1; next
        }
        print line
        nopen=gsub(/\{/,"{",line); nclose=gsub(/\}/,"}",line); depth+=nopen-nclose
        if (depth==0 && done==0) {
          # if sites-enabled include wasn’t found, inject just before http closes
          # reopen and inject at the end of http block
          system("awk \047BEGIN{h=0;d=0} {l=$0; if(h==0){print l; if(l~ /^[ \\t]*http[ \\t]*\\{/){h=1; d=1}} else {nopen=gsub(/\\{/,\"{\",l); nclose=gsub(/\\}/,\"}\",l); if(d==1){print \"    # AFNSEC-GLOBAL-ENFORCE-BEGIN\\n    access_by_lua_block {\\n      local rep = require(\\\"reputation\\\")\\n      rep.enforce()\\n    }\\n    # AFNSEC-GLOBAL-ENFORCE-END\"; d=2} print l; if(d>0){d+=nopen-nclose; if(d==0){h=0}} }}\047 /etc/nginx/nginx.conf > /etc/nginx/nginx.conf.tmp && mv /etc/nginx/nginx.conf.tmp /etc/nginx/nginx.conf")
          done=1
        }
        next
      }
    }
  ' /etc/nginx/nginx.conf > /etc/nginx/nginx.conf.new && mv /etc/nginx/nginx.conf.new /etc/nginx/nginx.conf
fi

# Ensure global error_log has at least info level
if grep -qE '^[ \t]*error_log[ \t]+/var/log/nginx/error\.log[ \t]*;[ \t]*$' /etc/nginx/nginx.conf; then
  info "Updating global error_log level to info"
  sed -i 's|^\([ \t]*error_log[ \t]\+/var/log/nginx/error\.log\)[ \t]*;[ \t]*$|\1 info;|' /etc/nginx/nginx.conf
elif ! grep -qE '^[ \t]*error_log[ \t]+/var/log/nginx/error\.log' /etc/nginx/nginx.conf; then
  info "Adding global error_log /var/log/nginx/error.log info;"
  awk '
    BEGIN{added=0}
    /^[ \t]*pid[ \t]+\/var\/run\/nginx\.pid;[ \t]*$/ && added==0 {print; print "error_log /var/log/nginx/error.log info;"; added=1; next}
    {print}
  ' /etc/nginx/nginx.conf > /etc/nginx/nginx.conf.new && mv /etc/nginx/nginx.conf.new /etc/nginx/nginx.conf
else
  info "Global error_log already configured; leaving as is."
fi

# ========== Validate & reload with rollback ==========
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

Uninstall (manual steps):
- Remove AFNSEC-GLOBAL-ENFORCE block from /etc/nginx/nginx.conf and reload nginx.
- Optionally remove /etc/nginx/conf.d/afnsec-reputation.conf and /usr/local/share/afnsec-reputation/.

EOSUM

rm -rf "$WORKDIR"
exit 0
