# Secondary DNS Server - PowerDNS

Hochverfuegbarer, rein autoritativer Secondary DNS Server auf Basis von PowerDNS.
Unterstuetzt **mehrere Primary-Server** mit jeweils **IPv4 und IPv6**.

**Repository:** https://github.com/bauer-group/IP-Helper.SecondaryDNS

## Features

- Rein autoritativ (kein offener Resolver)
- Automatische Zonenverwaltung via NOTIFY/AXFR
- Mehrere Primaries parallel - jeder mit IPv4/IPv6
- Zentrales Management-Tool: `dns-admin`
- DNSSEC-Unterstuetzung
- Automatische Updates (OS + PowerDNS)
- Minimale Angriffsflaeche (kein API, kein Webserver)

## Quick Start

### Option A: Cloud-Init (empfohlen)

1. Parameter in [cloud-init.yaml](cloud-init.yaml) anpassen (im `.env` Block oben)
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
  sudo PRIMARY_1_HOSTNAME="ns1.example.com" \
       PRIMARY_1_IPV4="203.0.113.10" \
       PRIMARY_1_IPV6="2001:db8::10" \
       ADMIN_EMAIL="admin@example.com" \
  bash
```

## Dateien

| Datei | Beschreibung |
|-------|--------------|
| [install.sh](install.sh) | Haupt-Installationsscript |
| [.env.example](.env.example) | Konfigurationsvorlage |
| [cloud-init.yaml](cloud-init.yaml) | Cloud-Init fuer automatisches Deployment |
| [CHECKLISTE.md](CHECKLISTE.md) | Deployment-Checkliste |

## Architektur

```
                           INTERNET
                              |
                              v
         +-------------------------------------+
         |     SECONDARY DNS (PowerDNS)        |
         |                                     |
         |  - Bekannte Zone   -> Autoritative  |
         |                       Antwort       |
         |  - Unbekannte Zone -> REFUSED       |
         +-------------------------------------+
                ^               ^               ^
                | NOTIFY/AXFR   |               |
                |               |               |
       +--------+-------+ +-----+--------+ +----+--------+
       | Primary 1      | | Primary 2    | | Primary N   |
       | IPv4 + IPv6    | | IPv4 + IPv6  | | IPv4 + IPv6 |
       +----------------+ +--------------+ +-------------+
```

## Anforderungen

- Debian 12 (Bookworm) / Debian 13 (Trixie) oder Ubuntu 22.04 / 24.04 LTS
- **Minimal:** 1 vCPU, 1 GB RAM, 10 GB SSD
- **Empfohlen:** 2 vCPU, 2 GB RAM, 10 GB SSD
- Offene Ports: 22 (SSH), 53 (DNS, TCP+UDP, IPv4+IPv6)

> Das Installationsskript prueft nur die Distro-Familie (Debian/Ubuntu),
> keine spezifische Version. Neuere Releases derselben Familie sollten
> funktionieren, sobald die PowerDNS-Pakete dort verfuegbar sind.

## Konfiguration mehrerer Primaries

Im `.env` (oder im Cloud-Init `.env`-Block):

```bash
# Pflicht: mindestens ein Primary mit Hostname und einer IP
PRIMARY_1_HOSTNAME="ns1.example.com"
PRIMARY_1_IPV4="203.0.113.10"
PRIMARY_1_IPV6="2001:db8::10"

# Optional: weitere Primaries
PRIMARY_2_HOSTNAME="ns2.example.com"
PRIMARY_2_IPV4="203.0.113.11"
PRIMARY_2_IPV6="2001:db8::11"
```

Zur Laufzeit aenderbar via `dns-admin` - kein Re-Install noetig.

## Zentrales Management: `dns-admin`

Nach der Installation steht das `dns-admin` Tool zur Verfuegung. Es ist die
**einzige** Anlaufstelle fuer Verwaltung, Status und Monitoring.

### Primary-Server verwalten

```bash
dns-admin primary list                                # Alle Primaries
dns-admin primary add ns3.example.com 192.0.2.30 2001:db8::30   # Hinzufuegen
dns-admin primary remove ns3.example.com              # Entfernen (alle IPs)
dns-admin primary remove 192.0.2.30                   # Einzelne IP entfernen
dns-admin primary reload                              # pdns.conf regenerieren
```

Add/Remove laden die PowerDNS-Konfiguration automatisch neu.

### Zonen (read-only / refresh)

Zonen werden **automatisch** vom Primary uebernommen, sobald dieser einen NOTIFY
sendet. Dieses Tool legt **keine** Zonen manuell an.

```bash
dns-admin zone list                          # Zonen mit Status
dns-admin zone show example.com              # Details
dns-admin zone retrieve example.com          # AXFR erzwingen
dns-admin zone check                         # Alle Zonen validieren
dns-admin zone delete example.com            # Verwaiste Zone entfernen
```

### Status, Health, Statistiken

```bash
dns-admin status      # Vollstaendiger Server-Status
dns-admin health      # Health-Check fuer Monitoring (exit 0/1/2)
dns-admin stats       # PowerDNS-Statistiken
dns-admin help        # Vollstaendige Hilfe
```

## Nach der Installation

1. Auf jedem Primary DNS:
   - Diesen Server als Slave/Secondary eintragen
   - NOTIFY aktivieren

2. Status pruefen:

   ```bash
   dns-admin status
   dns-admin primary list
   dns-admin zone list
   ```

3. Bei Bedarf einen weiteren Primary nachtraeglich hinzufuegen:

   ```bash
   sudo dns-admin primary add ns4.example.com 192.0.2.40 2001:db8::40
   ```

## Troubleshooting

```bash
# Service-Status
systemctl status pdns
journalctl -u pdns -f

# Health-Check (gut fuer Monitoring-Tools)
dns-admin health

# DNS-Tests
dig @localhost example.com A          # Autoritative Antwort
dig @localhost google.com A           # Sollte REFUSED liefern
dig @localhost example.com AXFR       # Zone-Transfer testen

# Primary-Konfiguration falsch?
dns-admin primary list                # IPs/Hostnamen pruefen
dns-admin primary reload              # pdns.conf aus DB neu erzeugen
```

## Sicherheit / Bruteforce-Schutz

Der Installer richtet zwei fail2ban-Jails ein:

- **sshd**: 24h Ban nach 5 Fehlversuchen in 15 Minuten
- **recidive**: 1 Woche Ban fuer IPs, die innerhalb von 24h dreimal von einem
  Jail gebannt wurden (eskalierende Strafe gegen hartnaeckige Bots)

```bash
# Status / Banlist
sudo fail2ban-client status               # Aktive Jails
sudo fail2ban-client status sshd          # SSH-Banlist
sudo fail2ban-client status recidive      # Wiederholungstaeter

# IP entbannen (nuetzlich nach eigenem Tippfehler)
sudo fail2ban-client set sshd unbanip 1.2.3.4

# Aktive Bans im dns-admin status sehen
dns-admin status
```

Die globale Aktivitaet (Anzahl gebannter IPs) wird auch in `dns-admin status`
unter "--- Sicherheit ---" angezeigt; `dns-admin health` warnt, wenn fail2ban
nicht laeuft.

## Optional: Web-Interface

Fuer eine grafische Verwaltungsoberflaeche kann
[PowerDNS-Admin](https://github.com/PowerDNS-Admin/PowerDNS-Admin) separat
installiert werden. Dafuer muss die HTTP-API in `/etc/powerdns/pdns.conf`
zusaetzlich aktiviert werden (default: aus).

> **Hinweis:** Fuer den reinen Secondary-Betrieb nicht erforderlich -
> alle Zonen kommen automatisch vom Primary und alle Verwaltungsaufgaben
> deckt `dns-admin` ab.
