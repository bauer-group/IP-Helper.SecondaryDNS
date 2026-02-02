# Secondary DNS Server - PowerDNS

Hochverfügbarer, rein autoritativer Secondary DNS Server auf Basis von PowerDNS.

**Repository:** https://github.com/bauer-group/IP-Helper.SecondaryDNS

## Features

- Rein autoritativ (kein offener Resolver)
- Automatische Zonenverwaltung via NOTIFY/AXFR
- DNSSEC-Unterstützung
- Automatische Updates (OS + PowerDNS)
- Minimale Angriffsfläche

## Quick Start

### Option A: Cloud-Init (empfohlen)

1. Parameter in `cloud-init.yaml` anpassen (ganz oben im `.env` Block)
2. Als User-Data bei VM-Erstellung verwenden
3. Fertig!

### Option B: Manuell mit Script

```bash
# Repository klonen
git clone https://github.com/bauer-group/IP-Helper.SecondaryDNS.git
cd IP-Helper.SecondaryDNS

# Konfiguration erstellen
cp .env.example .env
nano .env  # Parameter anpassen

# Installation starten
sudo ./install.sh
```

### Option C: One-Liner (mit Umgebungsvariablen)

```bash
curl -fsSL https://raw.githubusercontent.com/bauer-group/IP-Helper.SecondaryDNS/main/install.sh | \
  sudo PRIMARY_DNS_IP="1.2.3.4" \
       PRIMARY_DNS_HOSTNAME="ns1.example.com" \
       ADMIN_EMAIL="admin@example.com" \
  bash
```

## Dateien

| Datei | Beschreibung |
|-------|--------------|
| [install.sh](install.sh) | Haupt-Installationsscript |
| [.env.example](.env.example) | Konfigurationsvorlage |
| [cloud-init.yaml](cloud-init.yaml) | Cloud-Init für automatisches Deployment |
| [CHECKLISTE.md](CHECKLISTE.md) | Deployment-Checkliste |

## Architektur

```
                    INTERNET
                        │
                        ▼
┌─────────────────────────────────────────┐
│         SECONDARY DNS (PowerDNS)        │
│                                         │
│  • Bekannte Zone    → Autoritative      │
│                        Antwort          │
│                                         │
│  • Unbekannte Zone  → REFUSED           │
│                        (keine Rekursion)│
└─────────────────────────────────────────┘
                        ▲
                        │ NOTIFY / AXFR
                        │
┌─────────────────────────────────────────┐
│         PRIMARY DNS (Plesk/BIND)        │
└─────────────────────────────────────────┘
```

## Anforderungen

- Ubuntu 24.04 LTS oder Debian 12
- 2 vCPU, 4 GB RAM, 10 GB SSD
- Offene Ports: 22 (SSH), 53 (DNS)

## Nach der Installation

Zonen werden **automatisch** vom Primary übernommen:

1. Zone auf Primary anlegen
2. NOTIFY wird gesendet
3. Secondary lädt Zone via AXFR
4. Fertig!

```bash
# Status prüfen
pdnsutil list-all-zones
systemctl status pdns
```

## Befehle & Monitoring

### Status & Übersicht

```bash
# Installierte Helper-Scripts
dns-status                    # Vollständiger Server-Status
dns-health-check              # Health-Check für Monitoring

# PowerDNS Service
systemctl status pdns         # Service-Status
journalctl -u pdns -f         # Live-Logs
```

### Zonen-Verwaltung

```bash
# Zonen anzeigen
pdnsutil list-all-zones                 # Alle Zonen auflisten
pdnsutil show-zone example.com          # Zone-Details anzeigen
pdnsutil list-zone example.com          # Alle Records einer Zone

# Zone manuell abrufen (bei Problemen)
pdnsutil retrieve-zone example.com      # Zone neu vom Primary holen
```

### Performance & Statistiken

```bash
# Live-Statistiken
pdns_control show '*'                   # Alle Statistiken
pdns_control show queries               # Anzahl Queries gesamt
pdns_control show qsize-q               # Warteschlange
pdns_control show packetcache-hit       # Cache-Treffer
pdns_control show packetcache-miss      # Cache-Misses

# Top-Statistiken
pdns_control show uptime                # Laufzeit
pdns_control show latency               # Durchschnittliche Latenz
```

### DNS-Tests

```bash
# Lokale Abfragen
dig @localhost example.com A            # A-Record abfragen
dig @localhost example.com ANY          # Alle Records
dig @localhost example.com AXFR         # Zone-Transfer testen

# Authoritative vs. Recursive Test
dig @localhost google.com A             # Sollte REFUSED liefern (gut!)
dig @localhost example.com A +short     # Nur IP-Adresse
```

### Troubleshooting

```bash
# Konfiguration prüfen
pdns_control rping                      # PowerDNS erreichbar?
pdnsutil check-all-zones                # Alle Zonen auf Fehler prüfen

# Netzwerk
ss -ulnp | grep :53                     # Port 53 UDP
ss -tlnp | grep :53                     # Port 53 TCP
ufw status                              # Firewall-Regeln
```

## Hilfe

```bash
dns-status        # Vollständiger Server-Status
dns-health-check  # Health-Check für Monitoring
```

## Optional: Web-Interface

Für eine grafische Verwaltungsoberfläche kann [PowerDNS-Admin](https://github.com/PowerDNS-Admin/PowerDNS-Admin) separat installiert werden.

> **Hinweis:** Für diesen Secondary DNS ist keine Weboberfläche erforderlich, da alle Zonen automatisch vom Primary synchronisiert werden.
