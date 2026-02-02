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
| [KONZEPT.md](KONZEPT.md) | Vollständiges Lösungskonzept |
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

## Dokumentation

Siehe [KONZEPT.md](KONZEPT.md) für das vollständige technische Konzept.
