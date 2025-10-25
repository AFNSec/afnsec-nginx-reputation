#!/usr/bin/env bash
set -euo pipefail

# =========================
# AFNSec-Nginx-Reputation Uninstaller
# - Removes AFNSec edits from nginx.conf
# - Removes AFNSec files and directories
# - Optionally removes Lua packages
# - Leaves NGINX installed and other configs unchanged
# =========================

info(){ echo -e "\e[32m[INFO]\e[0m $*"; }
warn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
err(){  echo -e "\e[31m[ERROR]\e[0m $*"; }
die(){  err "$*"; exit 1; }
confirm(){ read -r -p "${1:-Proceed?} [y/N]: " r; [[ "$r" =~ ^([yY]|yes|YES)$ ]]; }

pkg_installed(){ dpkg -s "$1" >/dev/null 2>&1; }

# -------- preflight
[ "$(id -u)" -eq 0 ] || die "Run as root (sudo)."
. /etc/os-release || die "Cannot read /etc/os-release"
case "${ID}-${VERSION_ID}" in
  ubuntu-22.*|ubuntu-24.*) : ;;
  *) die "Unsupported OS: ${PRETTY_NAME}. This uninstaller targets Ubuntu nginx layout." ;;
esac

echo
echo "This will remove AFNSec-Nginx-Reputation from this server:"
echo "  • Remove AFNSec GLOBAL enforcement block from nginx.conf"
echo "  • Remove AFNSec loader: /etc/nginx/conf.d/afnsec-reputation.conf"
echo "  • Remove AFNSec Lua:    /usr/local/share/afnsec-reputation/"
echo "  • Remove AFNSec config: /etc/afnsec-reputation/"
echo "  • Remove block page:    /var/www/afnsec/block.html"
echo "  • Remove ONLY Lua HTTP directives we inserted (lua_ssl_*)."
echo "  • Leave nginx installed and other site configs untouched."
echo
confirm "Continue with AFNSec uninstall?" || die "Aborted."

NGINX_CONF="/etc/nginx/nginx.conf"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="/etc/nginx/nginx.conf.bak.afnsec-uninstall.${STAMP}"

# -------- backup nginx.conf
cp -a "$NGINX_CONF" "$BACKUP"
info "Backed up nginx.conf -> $BACKUP"

# -------- remove AFNSec GLOBAL enforcement block (between markers)
if grep -q 'AFNSEC-GLOBAL-ENFORCE-BEGIN' "$NGINX_CONF"; then
  info "Removing AFNSec GLOBAL enforcement from nginx.conf"
  awk '
    BEGIN{skip=0}
    /AFNSEC-GLOBAL-ENFORCE-BEGIN/ {skip=1; next}
    /AFNSEC-GLOBAL-ENFORCE-END/   {skip=0; next}
    { if (!skip) print }
  ' "$NGINX_CONF" > "${NGINX_CONF}.new" && mv "${NGINX_CONF}.new" "$NGINX_CONF"
else
  info "GLOBAL enforcement markers not found (already removed)."
fi

# -------- remove ONLY Lua HTTP directives we inserted (inside http{}): lua_ssl_trusted_certificate & lua_ssl_verify_depth
# We do NOT remove resolver lines unless you explicitly want that.
info "Removing AFNSec Lua HTTP directives (lua_ssl_* only) from http{}"
awk '
  BEGIN{http=0; depth=0}
  {
    line=$0
    # detect start of http{
    if (http==0 && match(line,/^[ \t]*http[ \t]*\{/)) { http=1; depth=1; print line; next }
    if (http==1) {
      # inside http{}: drop lua_ssl_* lines
      if (line ~ /^[ \t]*lua_ssl_trusted_certificate[ \t]/) next
      if (line ~ /^[ \t]*lua_ssl_verify_depth[ \t]/)      next
      # track braces to know when http ends
      nopen = gsub(/\{/,"{",line)
      nclose= gsub(/\}/,"}",line)
      depth += nopen - nclose
      if (depth==0) http=0
      print line; next
    }
    print line
  }
' "$NGINX_CONF" > "${NGINX_CONF}.new" && mv "${NGINX_CONF}.new" "$NGINX_CONF"

# -------- remove AFNSec loader & files
if [ -f /etc/nginx/conf.d/afnsec-reputation.conf ]; then
  info "Removing /etc/nginx/conf.d/afnsec-reputation.conf"
  rm -f /etc/nginx/conf.d/afnsec-reputation.conf
else
  info "Loader not present: /etc/nginx/conf.d/afnsec-reputation.conf"
fi

if [ -d /usr/local/share/afnsec-reputation ]; then
  info "Removing Lua directory /usr/local/share/afnsec-reputation/"
  rm -rf /usr/local/share/afnsec-reputation
fi

if [ -d /etc/afnsec-reputation ]; then
  info "Removing AFNSec runtime config /etc/afnsec-reputation/"
  rm -rf /etc/afnsec-reputation
fi

if [ -f /var/www/afnsec/block.html ]; then
  info "Removing block page /var/www/afnsec/block.html"
  rm -f /var/www/afnsec/block.html
fi

# -------- validate & reload (rollback on failure)
info "Validating nginx configuration…"
if ! nginx -t; then
  warn "nginx -t failed. Restoring backup."
  cp -a "$BACKUP" "$NGINX_CONF"
  nginx -t || die "nginx configuration invalid even after restore. Review $NGINX_CONF."
  die "Aborting: restored original nginx.conf."
fi

info "Reloading nginx…"
systemctl reload nginx || die "Failed to reload nginx."

# -------- optional: remove Lua packages
echo
if confirm "Remove Lua packages (libnginx-mod-http-lua, libnginx-mod-http-ndk, lua-cjson)?"; then
  TO_REMOVE=()
  pkg_installed libnginx-mod-http-lua   && TO_REMOVE+=("libnginx-mod-http-lua")
  pkg_installed libnginx-mod-http-ndk   && TO_REMOVE+=("libnginx-mod-http-ndk")
  pkg_installed lua-cjson               && TO_REMOVE+=("lua-cjson")
  if ((${#TO_REMOVE[@]})); then
    info "Removing packages: ${TO_REMOVE[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get remove -y "${TO_REMOVE[@]}" || warn "Package removal had issues (continuing)."
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y || true
  else
    info "Lua packages already absent."
  fi
else
  info "Keeping Lua packages."
fi

echo
info "AFNSec uninstall complete."
echo "Backup of nginx.conf saved at: $BACKUP"
exit 0
