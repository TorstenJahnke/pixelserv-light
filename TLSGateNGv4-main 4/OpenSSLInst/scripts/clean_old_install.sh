#!/bin/bash
# Clean Old OpenSSL Installation
# Ausführung: sudo /opt/openssl-3.6.0/scripts/clean_old_install.sh

set -e

echo "🧹 Reinige alte OpenSSL Installation..."

# Backup der environment
cp /etc/environment /etc/environment.backup.$(date +%Y%m%d_%H%M%S)

# Entferne manuelle Installation
rm -rf /usr/local/ssl/
rm -f /usr/local/bin/openssl
rm -f /usr/local/include/openssl/

# Entferne Symlinks
find /usr/local/bin -name "*openssl*" -type l -delete 2>/dev/null || true
find /usr/local/lib -name "*ssl*" -type l -delete 2>/dev/null || true

# Setze System-OpenSSL zurück
apt update
apt install --reinstall openssl libssl3t64 libssl-dev -y

# Bereinige environment
cat > /etc/environment << 'EOF'
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
LANG="en_US.UTF-8"
LC_ALL="en_US.UTF-8"
LC_CTYPE="de_DE.UTF-8"
EDITOR="/usr/bin/nano"
PAGER="/usr/bin/less"
TERM="xterm-256color"
SHELL="/bin/bash"
EOF

echo "✅ Alte Installation bereinigt"
echo "📁 Backup: /etc/environment.backup.*"
openssl version
