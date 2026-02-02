#!/bin/bash
# =============================================================================
# Secondary DNS Server - Installations-Script
# PowerDNS Authoritative (rein autoritativ, kein Recursor)
#
# GitHub: https://github.com/bauer-group/IP-Helper.SecondaryDNS
# =============================================================================
#
# VERWENDUNG:
#
#   Option 1: Mit .env Datei
#     cp .env.example .env
#     nano .env  # Werte anpassen
#     sudo ./install.sh
#
#   Option 2: Mit Umgebungsvariablen
#     sudo PRIMARY_DNS_IP="1.2.3.4" PRIMARY_DNS_HOSTNAME="ns1.example.com" \
#          ADMIN_EMAIL="admin@example.com" ./install.sh
#
#   Option 3: Via Cloud-Init (lädt Script von GitHub)
#     Siehe cloud-init.yaml
#
# =============================================================================

set -euo pipefail

# =============================================================================
# Farben für Ausgabe
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC} $1"; }

# =============================================================================
# .env Datei laden (falls vorhanden)
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

if [[ -f "$ENV_FILE" ]]; then
    log_info "Lade Konfiguration aus $ENV_FILE"
    set -a
    source "$ENV_FILE"
    set +a
elif [[ -f "/tmp/.env" ]]; then
    log_info "Lade Konfiguration aus /tmp/.env"
    set -a
    source "/tmp/.env"
    set +a
fi

# =============================================================================
# Standardwerte setzen
# =============================================================================
PRIMARY_DNS_IP="${PRIMARY_DNS_IP:-}"
PRIMARY_DNS_HOSTNAME="${PRIMARY_DNS_HOSTNAME:-}"
ADMIN_EMAIL="${ADMIN_EMAIL:-root@localhost}"

SECONDARY_HOSTNAME="${SECONDARY_HOSTNAME:-ns2}"
SECONDARY_FQDN="${SECONDARY_FQDN:-ns2.local}"
TIMEZONE="${TIMEZONE:-Etc/UTC}"

SSH_PUBKEY="${SSH_PUBKEY:-}"
SSH_PASSWORD_AUTH="${SSH_PASSWORD_AUTH:-true}"

AUTO_REBOOT="${AUTO_REBOOT:-true}"
REBOOT_TIME="${REBOOT_TIME:-03:00}"

# TSIG-Key für sichere Zone-Transfers (optional)
# Format: name:algorithm:secret (z.B. "transfer-key:hmac-sha256:BASE64SECRET")
TSIG_KEY="${TSIG_KEY:-}"

# =============================================================================
# Validierung
# =============================================================================
validate_config() {
    local errors=0

    if [[ -z "$PRIMARY_DNS_IP" ]]; then
        log_error "PRIMARY_DNS_IP ist nicht gesetzt!"
        errors=$((errors + 1))
    fi

    if [[ -z "$PRIMARY_DNS_HOSTNAME" ]]; then
        log_error "PRIMARY_DNS_HOSTNAME ist nicht gesetzt!"
        errors=$((errors + 1))
    fi

    if [[ $errors -gt 0 ]]; then
        echo ""
        log_error "Konfiguration unvollständig. Bitte .env Datei prüfen."
        echo ""
        echo "Beispiel:"
        echo "  PRIMARY_DNS_IP=\"203.0.113.10\""
        echo "  PRIMARY_DNS_HOSTNAME=\"ns1.example.com\""
        echo "  ADMIN_EMAIL=\"admin@example.com\""
        exit 1
    fi
}

# =============================================================================
# Root-Check
# =============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Dieses Script muss als root ausgeführt werden!"
        log_info "Verwende: sudo $0"
        exit 1
    fi
}

# =============================================================================
# OS-Check
# =============================================================================
check_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Betriebssystem nicht erkannt!"
        exit 1
    fi

    source /etc/os-release

    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        log_error "Dieses Script unterstützt nur Ubuntu und Debian!"
        log_error "Erkannt: $PRETTY_NAME"
        exit 1
    fi

    log_info "Betriebssystem: $PRETTY_NAME"
}

# =============================================================================
# Konfiguration anzeigen
# =============================================================================
show_config() {
    echo ""
    echo "============================================"
    echo "  Konfiguration"
    echo "============================================"
    echo "  Primary DNS IP:       $PRIMARY_DNS_IP"
    echo "  Primary DNS Hostname: $PRIMARY_DNS_HOSTNAME"
    echo "  Admin E-Mail:         $ADMIN_EMAIL"
    echo "  Secondary Hostname:   $SECONDARY_HOSTNAME"
    echo "  Secondary FQDN:       $SECONDARY_FQDN"
    echo "  SSH Password Auth:    $SSH_PASSWORD_AUTH"
    echo "  Auto Reboot:          $AUTO_REBOOT"
    echo "  Reboot Time:          $REBOOT_TIME"
    if [[ -n "$TSIG_KEY" ]]; then
        echo "  TSIG-Key:             (konfiguriert)"
    fi
    echo "============================================"
    echo ""
}

# =============================================================================
# System vorbereiten
# =============================================================================
prepare_system() {
    log_step "System wird vorbereitet..."

    # Hostname setzen
    hostnamectl set-hostname "$SECONDARY_HOSTNAME"

    # Zeitzone setzen
    timedatectl set-timezone "$TIMEZONE" || true

    # systemd-resolved deaktivieren (kollidiert mit Port 53)
    log_info "Deaktiviere systemd-resolved..."
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true

    # resolv.conf neu erstellen (Dual-Stack: IPv4 + IPv6)
    rm -f /etc/resolv.conf
    cat > /etc/resolv.conf << 'EOF'
nameserver 9.9.9.9
nameserver 2620:fe::fe
nameserver 149.112.112.112
nameserver 2620:fe::9
EOF

    # Pakete aktualisieren
    log_info "Aktualisiere Paketlisten..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
}

# =============================================================================
# Pakete installieren
# =============================================================================
install_packages() {
    log_step "Installiere Pakete..."

    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        pdns-server \
        pdns-backend-sqlite3 \
        sqlite3 \
        ufw \
        fail2ban \
        unattended-upgrades \
        apt-listchanges \
        needrestart \
        chrony \
        curl \
        dnsutils \
        htop
}

# =============================================================================
# Chrony (NTP) konfigurieren
# =============================================================================
configure_chrony() {
    log_step "Konfiguriere Chrony (NTP)..."

    # Standard-Konfiguration ist bereits gut, nur aktivieren
    systemctl enable chrony
    systemctl restart chrony

    log_info "Chrony gestartet - Zeit wird synchronisiert"
}

# =============================================================================
# SQLite Datenbank einrichten
# =============================================================================
setup_database() {
    log_step "Richte SQLite Datenbank ein..."

    mkdir -p /var/lib/powerdns

    # Schema erstellen
    sqlite3 /var/lib/powerdns/pdns.sqlite3 << 'EOFSCHEMA'
PRAGMA foreign_keys = 1;

CREATE TABLE IF NOT EXISTS domains (
  id                    INTEGER PRIMARY KEY,
  name                  VARCHAR(255) NOT NULL COLLATE NOCASE,
  master                VARCHAR(128) DEFAULT NULL,
  last_check            INTEGER DEFAULT NULL,
  type                  VARCHAR(8) NOT NULL,
  notified_serial       INTEGER DEFAULT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  options               VARCHAR(65535) DEFAULT NULL,
  catalog               VARCHAR(255) DEFAULT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS name_index ON domains(name);
CREATE INDEX IF NOT EXISTS catalog_idx ON domains(catalog);

CREATE TABLE IF NOT EXISTS records (
  id                    INTEGER PRIMARY KEY,
  domain_id             INTEGER DEFAULT NULL,
  name                  VARCHAR(255) DEFAULT NULL,
  type                  VARCHAR(10) DEFAULT NULL,
  content               VARCHAR(65535) DEFAULT NULL,
  ttl                   INTEGER DEFAULT NULL,
  prio                  INTEGER DEFAULT NULL,
  disabled              BOOLEAN DEFAULT 0,
  ordername             VARCHAR(255),
  auth                  BOOL DEFAULT 1,
  FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS records_lookup_idx ON records(name, type);
CREATE INDEX IF NOT EXISTS records_lookup_id_idx ON records(domain_id, name, type);
CREATE INDEX IF NOT EXISTS records_order_idx ON records(domain_id, ordername);

CREATE TABLE IF NOT EXISTS supermasters (
  ip                    VARCHAR(64) NOT NULL,
  nameserver            VARCHAR(255) NOT NULL COLLATE NOCASE,
  account               VARCHAR(40) NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ip_nameserver_pk ON supermasters(ip, nameserver);

CREATE TABLE IF NOT EXISTS comments (
  id                    INTEGER PRIMARY KEY,
  domain_id             INTEGER NOT NULL,
  name                  VARCHAR(255) NOT NULL,
  type                  VARCHAR(10) NOT NULL,
  modified_at           INT NOT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  comment               VARCHAR(65535) NOT NULL,
  FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS comments_idx ON comments(domain_id, name, type);
CREATE INDEX IF NOT EXISTS comments_order_idx ON comments(domain_id, modified_at);

CREATE TABLE IF NOT EXISTS domainmetadata (
  id                    INTEGER PRIMARY KEY,
  domain_id             INT NOT NULL,
  kind                  VARCHAR(32) COLLATE NOCASE,
  content               TEXT,
  FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS domainmetadata_idx ON domainmetadata(domain_id, kind);

CREATE TABLE IF NOT EXISTS cryptokeys (
  id                    INTEGER PRIMARY KEY,
  domain_id             INT NOT NULL,
  flags                 INT NOT NULL,
  active                BOOL,
  published             BOOL DEFAULT 1,
  content               TEXT,
  FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS domainidindex ON cryptokeys(domain_id);

CREATE TABLE IF NOT EXISTS tsigkeys (
  id                    INTEGER PRIMARY KEY,
  name                  VARCHAR(255) COLLATE NOCASE,
  algorithm             VARCHAR(50) COLLATE NOCASE,
  secret                VARCHAR(255)
);

CREATE UNIQUE INDEX IF NOT EXISTS namealgoindex ON tsigkeys(name, algorithm);
EOFSCHEMA

    # Supermaster-Einträge für alle Primary IPs
    IFS=',' read -ra PRIMARY_ARRAY <<< "$PRIMARY_DNS_IP"
    for ip in "${PRIMARY_ARRAY[@]}"; do
        ip=$(echo "$ip" | xargs)  # Whitespace entfernen
        log_info "Füge Supermaster hinzu: $ip ($PRIMARY_DNS_HOSTNAME)"
        sqlite3 /var/lib/powerdns/pdns.sqlite3 \
            "INSERT OR IGNORE INTO supermasters (ip, nameserver, account) VALUES ('$ip', '$PRIMARY_DNS_HOSTNAME', 'primary');"
    done

    # TSIG-Key einrichten falls konfiguriert
    if [[ -n "$TSIG_KEY" ]]; then
        log_info "Richte TSIG-Key ein..."
        IFS=':' read -r TSIG_NAME TSIG_ALGO TSIG_SECRET <<< "$TSIG_KEY"
        sqlite3 /var/lib/powerdns/pdns.sqlite3 \
            "INSERT OR REPLACE INTO tsigkeys (name, algorithm, secret) VALUES ('$TSIG_NAME', '$TSIG_ALGO', '$TSIG_SECRET');"
        log_info "TSIG-Key '$TSIG_NAME' mit Algorithmus '$TSIG_ALGO' eingerichtet"
    fi

    # Berechtigungen setzen
    chown -R pdns:pdns /var/lib/powerdns
    chmod 640 /var/lib/powerdns/pdns.sqlite3
}

# =============================================================================
# PowerDNS konfigurieren
# =============================================================================
configure_powerdns() {
    log_step "Konfiguriere PowerDNS..."

    # IPs für Konfiguration formatieren (Komma-separiert)
    local ALLOWED_IPS
    ALLOWED_IPS=$(echo "$PRIMARY_DNS_IP" | tr ',' ',')

    # CPU-Kerne für receiver-threads (1:1 Mapping)
    local CPU_CORES
    CPU_CORES=$(nproc)

    # Alte Konfiguration sichern
    [[ -f /etc/powerdns/pdns.conf ]] && cp /etc/powerdns/pdns.conf /etc/powerdns/pdns.conf.bak

    cat > /etc/powerdns/pdns.conf << EOF
# ==========================================================================
# PowerDNS Authoritative Server - Secondary/Slave Konfiguration
# REIN AUTORITATIV - Keine Rekursion, kein Forwarding
# Generiert am: $(date)
# ==========================================================================

setuid=pdns
setgid=pdns

# Netzwerk - IPv4 UND IPv6 auf allen Interfaces
local-address=0.0.0.0,::
local-port=53

# Backend: SQLite3
launch=gsqlite3
gsqlite3-database=/var/lib/powerdns/pdns.sqlite3
gsqlite3-pragma-synchronous=1
gsqlite3-pragma-foreign-keys=1

# Slave/Secondary Modus mit Autosecondary (SuperSlave)
secondary=yes
autosecondary=yes

# Whitelist für AXFR/NOTIFY
allow-axfr-ips=127.0.0.1,::1,${ALLOWED_IPS}
allow-notify-from=127.0.0.1,::1,${ALLOWED_IPS}

# DNSSEC
dnssec=process-no-validate

# Performance (receiver-threads = Anzahl CPU-Kerne)
receiver-threads=${CPU_CORES}
cache-ttl=60
negquery-cache-ttl=60
query-cache-ttl=20

# Rate Limiting (Anti-DDoS)
# Hoher Wert wegen NAT (viele User hinter einer IP)
max-qps-per-ip=1000
max-ent-entries=100000

# Logging (Production)
log-dns-queries=no
log-dns-details=no
loglevel=4

# API deaktiviert
api=no
webserver=no

# Version verstecken
version-string=anonymous
EOF

    chown pdns:pdns /etc/powerdns/pdns.conf
    chmod 640 /etc/powerdns/pdns.conf
}

# =============================================================================
# Log-Rotation konfigurieren
# =============================================================================
configure_log_rotation() {
    log_step "Konfiguriere Log-Rotation..."

    # Journald Limits setzen
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/size-limit.conf << 'EOF'
[Journal]
# Maximale Größe für Logs
SystemMaxUse=500M
SystemKeepFree=1G
SystemMaxFileSize=50M
MaxRetentionSec=1month
EOF

    systemctl restart systemd-journald

    log_info "Log-Rotation konfiguriert (max 500MB, 1 Monat)"
}

# =============================================================================
# Sysctl Optimierungen
# =============================================================================
configure_sysctl() {
    log_step "Optimiere Kernel-Parameter..."

    cat > /etc/sysctl.d/99-dns-performance.conf << 'EOF'
# DNS Server Optimierungen
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.netdev_max_backlog = 50000
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.core.somaxconn = 65535
EOF

    sysctl -p /etc/sysctl.d/99-dns-performance.conf 2>/dev/null || true
}

# =============================================================================
# Firewall konfigurieren
# =============================================================================
configure_firewall() {
    log_step "Konfiguriere Firewall..."

    ufw --force reset >/dev/null 2>&1 || true
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh comment 'SSH Zugang'
    ufw allow 53/tcp comment 'DNS TCP'
    ufw allow 53/udp comment 'DNS UDP'
    ufw --force enable
}

# =============================================================================
# Fail2ban konfigurieren
# =============================================================================
configure_fail2ban() {
    log_step "Konfiguriere Fail2ban..."

    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
}

# =============================================================================
# Unattended Upgrades konfigurieren
# =============================================================================
configure_updates() {
    log_step "Konfiguriere automatische Updates..."

    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}:\${distro_codename}-updates";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::DevRelease "auto";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";

Unattended-Upgrade::Mail "${ADMIN_EMAIL}";
Unattended-Upgrade::MailReport "only-on-error";

Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";

Unattended-Upgrade::Automatic-Reboot "${AUTO_REBOOT}";
Unattended-Upgrade::Automatic-Reboot-Time "${REBOOT_TIME}";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

    systemctl enable unattended-upgrades
    systemctl restart unattended-upgrades
}

# =============================================================================
# SSH konfigurieren
# =============================================================================
configure_ssh() {
    log_step "Konfiguriere SSH..."

    # Root-Login Einstellung basierend auf Password-Auth
    local ROOT_LOGIN="prohibit-password"
    if [[ "${SSH_PASSWORD_AUTH}" == "true" ]]; then
        ROOT_LOGIN="yes"
    fi

    cat > /etc/ssh/sshd_config.d/hardening.conf << EOF
# SSH Hardening - Generiert am $(date)
PermitRootLogin ${ROOT_LOGIN}
PasswordAuthentication ${SSH_PASSWORD_AUTH}
PubkeyAuthentication yes
X11Forwarding no
AllowTcpForwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

    # SSH Key hinzufügen falls angegeben
    if [[ -n "$SSH_PUBKEY" ]]; then
        log_info "Füge SSH Public Key hinzu..."
        mkdir -p /root/.ssh
        echo "$SSH_PUBKEY" >> /root/.ssh/authorized_keys
        chmod 700 /root/.ssh
        chmod 600 /root/.ssh/authorized_keys
    fi

    systemctl restart sshd
}

# =============================================================================
# Status-Script erstellen
# =============================================================================
create_status_script() {
    log_step "Erstelle Status-Script..."

    cat > /usr/local/bin/dns-status << 'EOFSCRIPT'
#!/bin/bash
# DNS Server Status Script

echo "============================================"
echo "  Secondary DNS Server Status"
echo "============================================"
echo ""

# PowerDNS Status
echo "--- PowerDNS Service ---"
systemctl is-active pdns >/dev/null 2>&1 && echo "Status: RUNNING" || echo "Status: STOPPED"
echo ""

# Zonen
echo "--- Zonen ($(pdnsutil list-all-zones 2>/dev/null | wc -l)) ---"
pdnsutil list-all-zones 2>/dev/null | head -10
ZONE_COUNT=$(pdnsutil list-all-zones 2>/dev/null | wc -l)
if [[ $ZONE_COUNT -gt 10 ]]; then
    echo "... und $((ZONE_COUNT - 10)) weitere"
fi
echo ""

# Supermaster
echo "--- Supermaster (Primary DNS) ---"
sqlite3 /var/lib/powerdns/pdns.sqlite3 "SELECT ip, nameserver FROM supermasters;" 2>/dev/null || echo "Keine Supermasters konfiguriert"
echo ""

# Netzwerk
echo "--- Listening ---"
ss -tulpn | grep pdns | head -5
echo ""

# Zeit
echo "--- System Zeit ---"
echo "Lokal:  $(date)"
echo "Chrony: $(chronyc tracking 2>/dev/null | grep 'System time' || echo 'nicht verfügbar')"
echo ""

# Ressourcen
echo "--- Ressourcen ---"
echo "Disk:   $(df -h /var/lib/powerdns 2>/dev/null | tail -1 | awk '{print $3 " / " $2 " (" $5 " used)"}')"
echo "Memory: $(free -h | grep Mem | awk '{print $3 " / " $2}')"
echo ""

echo "============================================"
EOFSCRIPT

    chmod +x /usr/local/bin/dns-status
}

# =============================================================================
# Health-Check Script erstellen
# =============================================================================
create_health_check() {
    log_step "Erstelle Health-Check Script..."

    cat > /usr/local/bin/dns-health-check << 'EOFSCRIPT'
#!/bin/bash
# DNS Server Health Check
# Exit codes: 0 = OK, 1 = WARNING, 2 = CRITICAL

ERRORS=0
WARNINGS=0

# Prüfe PowerDNS Service
if ! systemctl is-active pdns >/dev/null 2>&1; then
    echo "CRITICAL: PowerDNS ist nicht aktiv"
    ERRORS=$((ERRORS + 1))
fi

# Prüfe ob Port 53 offen ist
if ! ss -tulpn | grep -q ':53 '; then
    echo "CRITICAL: Port 53 nicht erreichbar"
    ERRORS=$((ERRORS + 1))
fi

# Prüfe DNS-Antwort (localhost)
if ! dig @127.0.0.1 +short +time=2 version.bind chaos txt >/dev/null 2>&1; then
    echo "CRITICAL: DNS antwortet nicht auf localhost"
    ERRORS=$((ERRORS + 1))
fi

# Prüfe Chrony
if ! systemctl is-active chrony >/dev/null 2>&1; then
    echo "WARNING: Chrony ist nicht aktiv"
    WARNINGS=$((WARNINGS + 1))
fi

# Prüfe Disk Space (warnung bei >90%)
DISK_USAGE=$(df /var/lib/powerdns 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%')
if [[ -n "$DISK_USAGE" ]] && [[ $DISK_USAGE -gt 90 ]]; then
    echo "WARNING: Disk usage bei ${DISK_USAGE}%"
    WARNINGS=$((WARNINGS + 1))
fi

# Prüfe Zonenanzahl
ZONE_COUNT=$(pdnsutil list-all-zones 2>/dev/null | wc -l)
if [[ $ZONE_COUNT -eq 0 ]]; then
    echo "WARNING: Keine Zonen vorhanden"
    WARNINGS=$((WARNINGS + 1))
fi

# Ergebnis
if [[ $ERRORS -gt 0 ]]; then
    echo "HEALTH CHECK: CRITICAL ($ERRORS errors, $WARNINGS warnings)"
    exit 2
elif [[ $WARNINGS -gt 0 ]]; then
    echo "HEALTH CHECK: WARNING ($WARNINGS warnings)"
    exit 1
else
    echo "HEALTH CHECK: OK (${ZONE_COUNT} zones)"
    exit 0
fi
EOFSCRIPT

    chmod +x /usr/local/bin/dns-health-check
}

# =============================================================================
# MOTD erstellen
# =============================================================================
create_motd() {
    cat > /etc/motd << 'EOF'

============================================
  Secondary DNS Server (PowerDNS)
  Rein autoritativ - Keine Rekursion
============================================

Befehle:
  dns-status              - Vollständiger Status
  dns-health-check        - Health Check für Monitoring
  pdnsutil list-all-zones - Alle Zonen
  pdnsutil show-zone X    - Zone Details
  systemctl status pdns   - Service Status

============================================

EOF
}

# =============================================================================
# Dienste starten
# =============================================================================
start_services() {
    log_step "Starte Dienste..."

    systemctl enable pdns
    systemctl restart pdns
    sleep 2
}

# =============================================================================
# Status anzeigen
# =============================================================================
show_status() {
    echo ""
    echo "============================================"
    log_info "Installation abgeschlossen!"
    echo "============================================"
    echo ""

    echo "PowerDNS Status:"
    systemctl status pdns --no-pager -l | head -5
    echo ""

    echo "Listening on:"
    ss -tulpn | grep pdns | head -5
    echo ""

    echo "Firewall Status:"
    ufw status | head -10
    echo ""

    echo "============================================"
    echo "NÄCHSTE SCHRITTE:"
    echo "============================================"
    echo ""
    echo "1. Auf dem PRIMARY DNS (Plesk/BIND):"
    echo "   - Diesen Server als Secondary hinzufügen"
    echo "   - NOTIFY aktivieren"
    echo ""
    echo "2. Testen:"
    echo "   dns-status"
    echo "   dns-health-check"
    echo ""
    echo "3. Zonen erscheinen automatisch nach NOTIFY vom Primary"
    echo ""
    echo "============================================"
}

# =============================================================================
# Hauptprogramm
# =============================================================================
main() {
    echo ""
    echo "============================================"
    echo "  Secondary DNS Server Installation"
    echo "  PowerDNS (rein autoritativ)"
    echo "============================================"
    echo ""

    check_root
    check_os
    validate_config
    show_config

    # Interaktive Bestätigung (außer bei Cloud-Init)
    if [[ -t 0 ]]; then
        read -p "Installation starten? (j/n) " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[JjYy]$ ]]; then
            log_warn "Installation abgebrochen."
            exit 0
        fi
    fi

    prepare_system
    install_packages
    configure_chrony
    setup_database
    configure_powerdns
    configure_log_rotation
    configure_sysctl
    configure_firewall
    configure_fail2ban
    configure_updates
    configure_ssh
    create_status_script
    create_health_check
    create_motd
    start_services
    show_status
}

# Script starten
main "$@"
