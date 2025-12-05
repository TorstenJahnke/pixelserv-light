#!/bin/bash
# =============================================================================
# SSL Library Switcher - OpenSSL / Tongsuo
# =============================================================================
# Wechselt zwischen OpenSSL und Tongsuo (reboot-fest)
#
# Installation:
#   cp ssl-switch.sh /usr/local/bin/ssl-switch
#   chmod +x /usr/local/bin/ssl-switch
#
# Verwendung:
#   ssl-switch          # Interaktives Menü
#   ssl-switch openssl  # Direkt zu OpenSSL wechseln
#   ssl-switch tongsuo  # Direkt zu Tongsuo wechseln
#   ssl-switch status   # Aktuelle Version anzeigen
# =============================================================================

OPENSSL_PATH="/opt/openssl-3.6.0"
TONGSUO_PATH="/opt/tongsuo-8.4.0"
ACTIVE_LINK="/opt/ssl-active"
LDCONF_FILE="/etc/ld.so.conf.d/ssl-active.conf"

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Root-Check
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Fehler: Dieses Script muss als root ausgeführt werden.${NC}"
        exit 1
    fi
}

# Aktuelle Version ermitteln
get_current() {
    if [[ -L "$ACTIVE_LINK" ]]; then
        local target=$(readlink -f "$ACTIVE_LINK")
        if [[ "$target" == "$TONGSUO_PATH" ]]; then
            echo "tongsuo"
        elif [[ "$target" == "$OPENSSL_PATH" ]]; then
            echo "openssl"
        else
            echo "unknown"
        fi
    else
        echo "none"
    fi
}

# Status anzeigen
show_status() {
    echo -e "${BLUE}=== SSL Library Status ===${NC}"
    echo ""

    local current=$(get_current)

    if [[ "$current" == "tongsuo" ]]; then
        echo -e "Aktiv:     ${GREEN}Tongsuo 8.4.0${NC}"
    elif [[ "$current" == "openssl" ]]; then
        echo -e "Aktiv:     ${GREEN}OpenSSL 3.6.0${NC}"
    else
        echo -e "Aktiv:     ${RED}Nicht konfiguriert${NC}"
    fi

    echo ""
    echo "Symlink:   $ACTIVE_LINK -> $(readlink "$ACTIVE_LINK" 2>/dev/null || echo 'nicht vorhanden')"
    echo ""

    if [[ -f "$ACTIVE_LINK/bin/openssl" ]]; then
        echo "Version:   $($ACTIVE_LINK/bin/openssl version 2>/dev/null)"
    fi
    echo ""
}

# Zu OpenSSL wechseln
switch_openssl() {
    echo -e "${YELLOW}Wechsle zu OpenSSL 3.6.0...${NC}"

    if [[ ! -d "$OPENSSL_PATH" ]]; then
        echo -e "${RED}Fehler: $OPENSSL_PATH nicht gefunden${NC}"
        exit 1
    fi

    ln -sfn "$OPENSSL_PATH" "$ACTIVE_LINK"
    echo "$ACTIVE_LINK/lib" > "$LDCONF_FILE"
    ldconfig

    echo -e "${GREEN}Gewechselt zu OpenSSL 3.6.0${NC}"
    echo ""
    $ACTIVE_LINK/bin/openssl version
}

# Zu Tongsuo wechseln
switch_tongsuo() {
    echo -e "${YELLOW}Wechsle zu Tongsuo 8.4.0...${NC}"

    if [[ ! -d "$TONGSUO_PATH" ]]; then
        echo -e "${RED}Fehler: $TONGSUO_PATH nicht gefunden${NC}"
        exit 1
    fi

    ln -sfn "$TONGSUO_PATH" "$ACTIVE_LINK"
    echo "$ACTIVE_LINK/lib" > "$LDCONF_FILE"
    ldconfig

    echo -e "${GREEN}Gewechselt zu Tongsuo 8.4.0${NC}"
    echo ""
    $ACTIVE_LINK/bin/openssl version
}

# Erstinstallation
setup_initial() {
    echo -e "${YELLOW}Ersteinrichtung...${NC}"

    # Profile.d für PATH
    cat > /etc/profile.d/ssl-active.sh << 'EOF'
export PATH=/opt/ssl-active/bin:$PATH
EOF
    chmod +x /etc/profile.d/ssl-active.sh

    echo -e "${GREEN}Ersteinrichtung abgeschlossen.${NC}"
    echo "Hinweis: PATH wird erst nach neuem Login aktiv."
}

# Interaktives Menü
show_menu() {
    local current=$(get_current)

    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     SSL Library Switcher               ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo ""

    if [[ "$current" == "tongsuo" ]]; then
        echo -e "  Aktuell: ${GREEN}Tongsuo 8.4.0${NC} (SM2/SM3/SM4)"
    elif [[ "$current" == "openssl" ]]; then
        echo -e "  Aktuell: ${GREEN}OpenSSL 3.6.0${NC}"
    else
        echo -e "  Aktuell: ${RED}Nicht konfiguriert${NC}"
    fi

    echo ""
    echo "  1) OpenSSL 3.6.0   - Standard"
    echo "  2) Tongsuo 8.4.0   - Mit SM2/SM3/SM4 Support"
    echo "  3) Status anzeigen"
    echo "  4) Beenden"
    echo ""
    read -p "  Auswahl [1-4]: " choice

    case $choice in
        1)
            switch_openssl
            ;;
        2)
            switch_tongsuo
            ;;
        3)
            show_status
            ;;
        4)
            echo "Beendet."
            exit 0
            ;;
        *)
            echo -e "${RED}Ungültige Auswahl${NC}"
            ;;
    esac
}

# Hauptprogramm
main() {
    case "${1:-}" in
        openssl)
            check_root
            switch_openssl
            ;;
        tongsuo)
            check_root
            switch_tongsuo
            ;;
        status)
            show_status
            ;;
        setup)
            check_root
            setup_initial
            ;;
        *)
            check_root

            # Ersteinrichtung wenn nötig
            if [[ ! -f /etc/profile.d/ssl-active.sh ]]; then
                setup_initial
            fi

            show_menu
            ;;
    esac
}

main "$@"
