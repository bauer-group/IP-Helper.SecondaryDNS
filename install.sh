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
#     sudo PRIMARY_1_HOSTNAME="ns1.example.com" \
#          PRIMARY_1_IPV4="1.2.3.4" \
#          PRIMARY_1_IPV6="2001:db8::1" \
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
# Primary DNS Server werden über numerierte Variablen konfiguriert:
#   PRIMARY_1_HOSTNAME, PRIMARY_1_IPV4, PRIMARY_1_IPV6
#   PRIMARY_2_HOSTNAME, PRIMARY_2_IPV4, PRIMARY_2_IPV6
#   ... (beliebig viele)
# Mindestens ein Primary mit Hostname und einer IP (v4 oder v6) ist Pflicht.
ADMIN_EMAIL="${ADMIN_EMAIL:-root@localhost}"

# Aggregierte Arrays werden von parse_primary_servers() befüllt
PRIMARY_HOSTS=()
PRIMARY_V4S=()
PRIMARY_V6S=()
PRIMARY_ALL_IPS=()
PRIMARY_PAIRS=()

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
# Primary-Server aus PRIMARY_N_* Variablen einlesen
# =============================================================================
parse_primary_servers() {
    PRIMARY_HOSTS=()
    PRIMARY_V4S=()
    PRIMARY_V6S=()
    PRIMARY_ALL_IPS=()
    PRIMARY_PAIRS=()

    local i=1
    while true; do
        local host_var="PRIMARY_${i}_HOSTNAME"
        local v4_var="PRIMARY_${i}_IPV4"
        local v6_var="PRIMARY_${i}_IPV6"

        local host="${!host_var:-}"
        # Stoppen sobald ein Index ohne Hostname kommt (zusammenhängende Liste)
        [[ -z "$host" ]] && break

        local v4="${!v4_var:-}"
        local v6="${!v6_var:-}"

        if [[ -z "$v4" && -z "$v6" ]]; then
            log_error "PRIMARY_${i}_HOSTNAME=\"$host\" gesetzt, aber weder PRIMARY_${i}_IPV4 noch PRIMARY_${i}_IPV6!"
            exit 1
        fi

        PRIMARY_HOSTS+=("$host")
        PRIMARY_V4S+=("$v4")
        PRIMARY_V6S+=("$v6")
        if [[ -n "$v4" ]]; then
            PRIMARY_ALL_IPS+=("$v4")
            PRIMARY_PAIRS+=("$v4|$host")
        fi
        if [[ -n "$v6" ]]; then
            PRIMARY_ALL_IPS+=("$v6")
            PRIMARY_PAIRS+=("$v6|$host")
        fi

        i=$((i + 1))
    done
}

# =============================================================================
# Validierung
# =============================================================================
validate_config() {
    parse_primary_servers

    if [[ ${#PRIMARY_HOSTS[@]} -eq 0 ]]; then
        echo ""
        log_error "Mindestens ein Primary DNS Server muss konfiguriert sein!"
        echo ""
        echo "Beispiel:"
        echo "  PRIMARY_1_HOSTNAME=\"ns1.example.com\""
        echo "  PRIMARY_1_IPV4=\"203.0.113.10\""
        echo "  PRIMARY_1_IPV6=\"2001:db8::10\""
        echo "  ADMIN_EMAIL=\"admin@example.com\""
        echo ""
        echo "Optional weitere Primaries: PRIMARY_2_HOSTNAME, PRIMARY_2_IPV4, ..."
        exit 1
    fi

    log_info "Konfiguration: ${#PRIMARY_HOSTS[@]} Primary Server, ${#PRIMARY_ALL_IPS[@]} IPs gesamt"
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
    echo "  Primary DNS Server:"
    local i
    for i in "${!PRIMARY_HOSTS[@]}"; do
        echo "    $((i+1)). ${PRIMARY_HOSTS[$i]}"
        [[ -n "${PRIMARY_V4S[$i]}" ]] && echo "       IPv4: ${PRIMARY_V4S[$i]}"
        [[ -n "${PRIMARY_V6S[$i]}" ]] && echo "       IPv6: ${PRIMARY_V6S[$i]}"
    done
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

    # Supermaster-Einträge: ein Eintrag pro (IP, Hostname)-Paar
    # PowerDNS akzeptiert NOTIFYs nur, wenn IP UND SOA-MNAME zu einem Eintrag passen.
    local entry ip host
    for entry in "${PRIMARY_PAIRS[@]}"; do
        IFS='|' read -r ip host <<< "$entry"
        log_info "Füge Supermaster hinzu: $ip ($host)"
        sqlite3 /var/lib/powerdns/pdns.sqlite3 \
            "INSERT OR IGNORE INTO supermasters (ip, nameserver, account) VALUES ('$ip', '$host', 'primary');"
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

    # IP-Liste für AXFR/NOTIFY (alle Primary-IPs, Komma-separiert)
    local ALLOWED_IPS
    ALLOWED_IPS=$(IFS=','; echo "${PRIMARY_ALL_IPS[*]}")

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

# Whitelist für AXFR/NOTIFY - wird von dns-admin verwaltet, NICHT manuell editieren!
# BEGIN PRIMARY-IPS (managed by dns-admin)
allow-axfr-ips=127.0.0.1,::1,${ALLOWED_IPS}
allow-notify-from=127.0.0.1,::1,${ALLOWED_IPS}
# END PRIMARY-IPS

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

# API/Webserver deaktiviert (nicht benoetigt - dns-admin nutzt sqlite3 + pdns_control)
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

    # Service-Name unterscheidet sich: Debian/Ubuntu = 'ssh', RHEL/Fedora = 'sshd'
    local ssh_unit=""
    if systemctl list-unit-files ssh.service 2>/dev/null | grep -qE '^ssh\.service'; then
        ssh_unit="ssh"
    elif systemctl list-unit-files sshd.service 2>/dev/null | grep -qE '^sshd\.service'; then
        ssh_unit="sshd"
    else
        log_error "Kein SSH-Service gefunden (weder ssh.service noch sshd.service)"
        exit 1
    fi

    # WICHTIG: reload (SIGHUP) statt restart - Installer laeuft typischerweise
    # ueber genau diese SSH-Session. restart wuerde Master-Daemon killen und
    # uns aus dem Skript-Lauf werfen. reload liest nur die Config neu, ohne
    # bestehende Sessions zu beruehren.
    log_info "Lade SSH-Config neu via SIGHUP ($ssh_unit reload)..."
    systemctl reload "$ssh_unit"
}

# =============================================================================
# Zentrales Management-Tool 'dns-admin' erstellen
# =============================================================================
create_admin_tool() {
    log_step "Erstelle dns-admin Management-Tool..."

    cat > /usr/local/bin/dns-admin << 'EOFSCRIPT'
#!/bin/bash
# =============================================================================
# dns-admin - Secondary DNS Management Tool
#
# Zentrales Tool fuer Verwaltung, Status und Monitoring eines PowerDNS
# Secondary-Servers. Zonen werden automatisch via NOTIFY/AXFR vom Primary
# uebernommen - dieses Tool verwaltet ausschliesslich:
#   - Primary-Server (Add/Remove/List)
#   - Zonen-Status (Read/Refresh)
#   - Server-Status, Health-Checks und Statistiken
# =============================================================================

set -euo pipefail

DB="/var/lib/powerdns/pdns.sqlite3"
CONF="/etc/powerdns/pdns.conf"

# --- Helpers ---------------------------------------------------------------
err()  { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARN:  $*" >&2; }
need_root() { [[ $EUID -eq 0 ]] || err "Befehl benoetigt root-Rechte"; }

# Sanitize: Hostnames duerfen nur a-z, 0-9, '.', '-' enthalten.
# IPs nur 0-9, a-f, '.', ':'. Verhindert SQL-Injection ueber User-Input.
validate_hostname() {
    [[ "$1" =~ ^[a-zA-Z0-9.-]+$ ]] || err "Ungueltiger Hostname: $1"
}
validate_ip() {
    [[ "$1" =~ ^[0-9a-fA-F.:]+$ ]] || err "Ungueltige IP-Adresse: $1"
}

# Regeneriert den BEGIN/END PRIMARY-IPS Block in pdns.conf aus der DB
regen_pdns_conf() {
    need_root
    local ips
    ips=$(sqlite3 "$DB" "SELECT DISTINCT ip FROM supermasters ORDER BY ip;" | paste -sd ',')
    local prefix=""
    [[ -n "$ips" ]] && prefix=","

    if ! grep -q "^# BEGIN PRIMARY-IPS" "$CONF"; then
        err "Sentinel-Marker 'BEGIN PRIMARY-IPS' fehlt in $CONF - bitte install.sh erneut laufen lassen"
    fi

    local tmp
    tmp=$(mktemp)
    awk -v ips="$ips" -v prefix="$prefix" '
        /^# BEGIN PRIMARY-IPS/ {
            print "# BEGIN PRIMARY-IPS (managed by dns-admin)"
            print "allow-axfr-ips=127.0.0.1,::1" prefix ips
            print "allow-notify-from=127.0.0.1,::1" prefix ips
            print "# END PRIMARY-IPS"
            in_block = 1
            next
        }
        /^# END PRIMARY-IPS/ { in_block = 0; next }
        !in_block { print }
    ' "$CONF" > "$tmp"

    mv "$tmp" "$CONF"
    chown pdns:pdns "$CONF"
    chmod 640 "$CONF"
}

reload_pdns() {
    need_root
    if systemctl reload pdns 2>/dev/null; then
        echo "PowerDNS neu geladen"
    else
        systemctl restart pdns
        echo "PowerDNS neu gestartet"
    fi
}

# --- primary subcommands ---------------------------------------------------
cmd_primary_list() {
    local count
    count=$(sqlite3 "$DB" "SELECT COUNT(*) FROM supermasters;" 2>/dev/null || echo 0)
    if [[ "$count" -eq 0 ]]; then
        echo "Keine Primary-Server konfiguriert."
        return 0
    fi
    echo "Primary DNS Server (${count} Eintraege):"
    echo ""
    sqlite3 -header -column "$DB" \
        "SELECT nameserver AS Hostname, ip AS IP, account AS Account FROM supermasters ORDER BY nameserver, ip;"
}

cmd_primary_add() {
    need_root
    local hostname="${1:-}"
    [[ -z "$hostname" ]] && err "Verwendung: dns-admin primary add <hostname> <ip> [<ip> ...]"
    validate_hostname "$hostname"
    shift
    [[ $# -eq 0 ]] && err "Mindestens eine IP angeben (IPv4 und/oder IPv6)"

    local ip
    for ip in "$@"; do
        validate_ip "$ip"
        sqlite3 "$DB" \
            "INSERT OR IGNORE INTO supermasters (ip, nameserver, account) VALUES ('$ip', '$hostname', 'primary');"
        echo "  + $ip ($hostname)"
    done
    chown pdns:pdns "$DB"

    regen_pdns_conf
    reload_pdns
}

cmd_primary_remove() {
    need_root
    local target="${1:-}"
    [[ -z "$target" ]] && err "Verwendung: dns-admin primary remove <hostname-oder-ip>"

    # Erlaube hostname ODER ip (validate beide Formate; mindestens eines muss matchen)
    [[ "$target" =~ ^[a-zA-Z0-9.:.-]+$ ]] || err "Ungueltiger Wert: $target"

    local count
    count=$(sqlite3 "$DB" \
        "SELECT COUNT(*) FROM supermasters WHERE nameserver='$target' OR ip='$target';")
    [[ "$count" -eq 0 ]] && err "Kein Eintrag fuer '$target' gefunden"

    sqlite3 "$DB" \
        "DELETE FROM supermasters WHERE nameserver='$target' OR ip='$target';"
    echo "Entfernt: $count Eintrag(e) fuer '$target'"

    regen_pdns_conf
    reload_pdns
}

cmd_primary_reload() {
    need_root
    regen_pdns_conf
    reload_pdns
}

# --- zone subcommands (read-only / refresh) --------------------------------
cmd_zone_list() {
    local count
    count=$(sqlite3 "$DB" "SELECT COUNT(*) FROM domains;" 2>/dev/null || echo 0)
    if [[ "$count" -eq 0 ]]; then
        echo "Keine Zonen vorhanden."
        echo "Zonen werden automatisch angelegt, sobald der Primary einen NOTIFY sendet."
        return 0
    fi
    echo "Zonen (${count}, automatisch synchronisiert via NOTIFY/AXFR):"
    echo ""
    sqlite3 -header -column "$DB" "
        SELECT
            d.name AS Zone,
            d.type AS Type,
            d.master AS Master,
            COALESCE(d.last_check, 0) AS LastCheck,
            (SELECT COUNT(*) FROM records WHERE domain_id = d.id) AS Records
        FROM domains d
        ORDER BY d.name;"
}

cmd_zone_show() {
    local zone="${1:-}"
    [[ -z "$zone" ]] && err "Verwendung: dns-admin zone show <zone>"
    pdnsutil show-zone "$zone"
}

cmd_zone_retrieve() {
    need_root
    local zone="${1:-}"
    [[ -z "$zone" ]] && err "Verwendung: dns-admin zone retrieve <zone>"
    pdnsutil retrieve-zone "$zone"
}

cmd_zone_check() {
    local zone="${1:-}"
    if [[ -n "$zone" ]]; then
        pdnsutil check-zone "$zone"
    else
        pdnsutil check-all-zones
    fi
}

cmd_zone_delete() {
    need_root
    local zone="${1:-}"
    [[ -z "$zone" ]] && err "Verwendung: dns-admin zone delete <zone>"
    echo ""
    echo "WARNUNG: Diese Zone wird beim naechsten NOTIFY vom Primary erneut angelegt."
    echo "Nur sinnvoll, wenn die Zone auf dem Primary ebenfalls geloescht wurde."
    echo ""
    if [[ -t 0 ]]; then
        read -p "Trotzdem loeschen? (j/n): " -n 1 -r reply
        echo
        [[ ! "$reply" =~ ^[JjYy]$ ]] && { echo "Abgebrochen."; return 0; }
    fi
    pdnsutil delete-zone "$zone"
}

# --- status / health / stats ----------------------------------------------
cmd_status() {
    echo "============================================"
    echo "  Secondary DNS Server Status"
    echo "============================================"

    if systemctl is-active pdns >/dev/null 2>&1; then
        local since
        since=$(systemctl show pdns --property=ActiveEnterTimestamp --value 2>/dev/null || echo "?")
        echo "PowerDNS:    RUNNING (seit ${since})"
    else
        echo "PowerDNS:    STOPPED"
    fi

    echo ""
    echo "--- Listening ---"
    ss -tulpn 2>/dev/null | grep pdns | head -5 || echo "  (keine Daten)"

    echo ""
    echo "--- Primary DNS Server ---"
    local pcount
    pcount=$(sqlite3 "$DB" "SELECT COUNT(*) FROM supermasters;" 2>/dev/null || echo 0)
    if [[ "$pcount" -eq 0 ]]; then
        echo "  (keine konfiguriert)"
    else
        sqlite3 "$DB" "SELECT '  ' || nameserver || '  ' || ip FROM supermasters ORDER BY nameserver, ip;"
    fi

    echo ""
    local zcount
    zcount=$(sqlite3 "$DB" "SELECT COUNT(*) FROM domains;" 2>/dev/null || echo 0)
    echo "--- Zonen: ${zcount} ---"
    if [[ "$zcount" -gt 0 ]]; then
        sqlite3 "$DB" "SELECT '  ' || name FROM domains ORDER BY name LIMIT 10;"
        [[ "$zcount" -gt 10 ]] && echo "  ... und $((zcount - 10)) weitere"
    fi

    echo ""
    echo "--- Statistik ---"
    if command -v pdns_control >/dev/null 2>&1 && pdns_control rping >/dev/null 2>&1; then
        local q ch cm up
        q=$(pdns_control show udp-queries 2>/dev/null || echo "?")
        ch=$(pdns_control show packetcache-hit 2>/dev/null || echo "?")
        cm=$(pdns_control show packetcache-miss 2>/dev/null || echo "?")
        up=$(pdns_control show uptime 2>/dev/null || echo "?")
        echo "  UDP-Queries:  ${q}"
        echo "  Cache-Hits:   ${ch}"
        echo "  Cache-Miss:   ${cm}"
        echo "  Uptime:       ${up}s"
    else
        echo "  (pdns_control nicht erreichbar)"
    fi

    echo ""
    echo "--- System ---"
    echo "  Disk:   $(df -h /var/lib/powerdns 2>/dev/null | tail -1 | awk '{print $3 " / " $2 " (" $5 ")"}')"
    echo "  Memory: $(free -h | awk '/^Mem:/ {print $3 " / " $2}')"
    echo "  Time:   $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "============================================"
}

cmd_health() {
    local errors=0 warnings=0

    if ! systemctl is-active pdns >/dev/null 2>&1; then
        echo "CRITICAL: PowerDNS ist nicht aktiv"
        errors=$((errors + 1))
    fi

    if ! ss -tulpn 2>/dev/null | grep -q ':53 '; then
        echo "CRITICAL: Port 53 nicht erreichbar"
        errors=$((errors + 1))
    fi

    if ! dig @127.0.0.1 +short +time=2 version.bind chaos txt >/dev/null 2>&1; then
        echo "CRITICAL: DNS antwortet nicht auf localhost"
        errors=$((errors + 1))
    fi

    local pcount
    pcount=$(sqlite3 "$DB" "SELECT COUNT(*) FROM supermasters;" 2>/dev/null || echo 0)
    if [[ "$pcount" -eq 0 ]]; then
        echo "CRITICAL: Keine Primary-Server konfiguriert"
        errors=$((errors + 1))
    fi

    if ! systemctl is-active chrony >/dev/null 2>&1; then
        echo "WARNING: Chrony ist nicht aktiv (Zeitsynchronisation)"
        warnings=$((warnings + 1))
    fi

    local disk_usage
    disk_usage=$(df /var/lib/powerdns 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%')
    if [[ -n "$disk_usage" && "$disk_usage" -gt 90 ]]; then
        echo "WARNING: Disk usage bei ${disk_usage}%"
        warnings=$((warnings + 1))
    fi

    local zcount
    zcount=$(sqlite3 "$DB" "SELECT COUNT(*) FROM domains;" 2>/dev/null || echo 0)
    if [[ "$zcount" -eq 0 ]]; then
        echo "WARNING: Keine Zonen (warte auf NOTIFY vom Primary)"
        warnings=$((warnings + 1))
    fi

    if [[ "$errors" -gt 0 ]]; then
        echo "HEALTH: CRITICAL (${errors} errors, ${warnings} warnings)"
        exit 2
    elif [[ "$warnings" -gt 0 ]]; then
        echo "HEALTH: WARNING (${warnings} warnings, ${zcount} zones, ${pcount} primaries)"
        exit 1
    else
        echo "HEALTH: OK (${zcount} zones, ${pcount} primaries)"
        exit 0
    fi
}

cmd_stats() {
    if ! command -v pdns_control >/dev/null 2>&1; then
        err "pdns_control nicht gefunden"
    fi
    echo "============================================"
    echo "  PowerDNS Statistiken"
    echo "============================================"
    pdns_control show '*' 2>/dev/null | sort
}

# --- help -----------------------------------------------------------------
cmd_help() {
    cat << 'HELP'
dns-admin - Secondary DNS Management Tool

VERWENDUNG:
    dns-admin <befehl> [argumente]

PRIMARY-VERWALTUNG (root):
    primary list                                Alle konfigurierten Primaries
    primary add <hostname> <ip> [<ip> ...]      Primary hinzufuegen (IPv4/IPv6)
    primary remove <hostname-oder-ip>           Primary entfernen
    primary reload                              pdns.conf regenerieren + reload

ZONEN (read-only / refresh - Anlage automatisch via NOTIFY):
    zone list                                   Zonen mit Status anzeigen
    zone show <zone>                            Zone-Details
    zone retrieve <zone>                        AXFR erzwingen (root)
    zone check [<zone>]                         Zone(n) validieren
    zone delete <zone>                          Verwaiste Zone entfernen (root)

STATUS & MONITORING:
    status                                      Vollstaendiger Server-Status
    health                                      Health-Check (exit 0/1/2)
    stats                                       PowerDNS-Statistiken

BEISPIELE:
    dns-admin primary add ns1.example.com 192.0.2.10 2001:db8::10
    dns-admin primary add ns2.example.com 192.0.2.11 2001:db8::11
    dns-admin primary remove ns1.example.com
    dns-admin zone retrieve example.com
    dns-admin status
    dns-admin health
HELP
}

# --- Dispatcher -----------------------------------------------------------
main() {
    local cmd="${1:-help}"
    case "$cmd" in
        primary)
            shift
            local sub="${1:-list}"
            shift || true
            case "$sub" in
                list|ls)        cmd_primary_list ;;
                add)            cmd_primary_add "$@" ;;
                remove|rm|del)  cmd_primary_remove "$@" ;;
                reload)         cmd_primary_reload ;;
                *) err "Unbekannter primary-Befehl: $sub (siehe 'dns-admin help')" ;;
            esac
            ;;
        zone)
            shift
            local sub="${1:-list}"
            shift || true
            case "$sub" in
                list|ls)        cmd_zone_list ;;
                show)           cmd_zone_show "$@" ;;
                retrieve|fetch) cmd_zone_retrieve "$@" ;;
                check)          cmd_zone_check "$@" ;;
                delete|rm|del)  cmd_zone_delete "$@" ;;
                *) err "Unbekannter zone-Befehl: $sub (siehe 'dns-admin help')" ;;
            esac
            ;;
        status)         cmd_status ;;
        health)         cmd_health ;;
        stats)          cmd_stats ;;
        help|-h|--help) cmd_help ;;
        *) err "Unbekannter Befehl: $cmd (siehe 'dns-admin help')" ;;
    esac
}

main "$@"
EOFSCRIPT

    chmod +x /usr/local/bin/dns-admin
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

Zentrales Management-Tool: dns-admin

  dns-admin status                   Server-Status
  dns-admin health                   Health-Check (Monitoring)
  dns-admin stats                    PowerDNS-Statistiken
  dns-admin primary list             Primary-Server anzeigen
  dns-admin primary add <fqdn> <ip>  Primary hinzufuegen
  dns-admin zone list                Zonen anzeigen (Auto-Sync)
  dns-admin help                     Vollstaendige Hilfe

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
    echo "NAECHSTE SCHRITTE:"
    echo "============================================"
    echo ""
    echo "1. Auf jedem PRIMARY DNS (Plesk/BIND):"
    echo "   - Diesen Server als Secondary hinzufuegen"
    echo "   - NOTIFY aktivieren"
    echo ""
    echo "2. Status pruefen:"
    echo "   dns-admin status"
    echo "   dns-admin health"
    echo "   dns-admin primary list"
    echo ""
    echo "3. Zonen erscheinen automatisch nach NOTIFY vom Primary."
    echo ""
    echo "4. Weitere Primaries spaeter hinzufuegen:"
    echo "   dns-admin primary add ns2.example.com 192.0.2.20 2001:db8::20"
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
    create_admin_tool
    create_motd
    start_services
    show_status
}

# Script starten
main "$@"
