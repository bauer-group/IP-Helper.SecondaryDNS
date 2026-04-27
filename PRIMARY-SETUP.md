# Primary DNS Server: Korrekte Einrichtung fuer Auto-Sync

Dieses Dokument erklaert, wie ein Primary DNS Server (Plesk, BIND, ...)
konfiguriert werden muss, damit Zonen automatisch via NOTIFY/AXFR vom
hier installierten Secondary uebernommen werden.

> Verwandte Doku: [README](README.md), [CHECKLISTE](CHECKLISTE.md)

## Inhalt

- [Die zwei Bedingungen](#die-zwei-bedingungen)
- [SOA-MNAME-Mechanik](#soa-mname-mechanik)
- [Diagnose: Was sendet mein Primary?](#diagnose-was-sendet-mein-primary)
- [Plesk-spezifisch](#plesk-spezifisch)
- [BIND-spezifisch](#bind-spezifisch)
- [Workflow](#workflow-vom-primary-zur-ersten-zone-auf-dem-secondary)
- [Haeufige Fehler](#haeufige-fehler)
- [Troubleshooting](#troubleshooting)

## Die zwei Bedingungen

Damit eine Zone vom Secondary automatisch akzeptiert wird, muessen ZWEI
Dinge gleichzeitig stimmen:

1. **Source-IP des NOTIFY** muss in der `supermasters`-Tabelle stehen
   (verwaltet via `dns-admin primary add`)
2. **MNAME im SOA-Record** der Zone muss als `nameserver` beim
   entsprechenden IP-Eintrag stehen

PowerDNS prueft beide als Tupel `(ip, nameserver)`. **Kein Wildcard,
kein Domain-Suffix-Match**, keine "loose"-Option. Das ist Schutz gegen
NOTIFY-Spoofing: ohne diese strikte Pruefung koennte jeder, der die
Source-IP spooft, beliebige Zonen unterjubeln.

## SOA-MNAME-Mechanik

Jede DNS-Zone hat einen SOA-Record:

```dns
@ SOA <mname> <rname> ( <serial> <refresh> <retry> <expire> <minimum> )
```

`<mname>` ist der **autoritative Master-Nameserver** dieser Zone.
Beispiele:

| Zone | SOA-MNAME (Beispiel) |
|------|----------------------|
| `example.com` | `ns1.example.com` |
| `kunde-a.de` | `ns1.kunde-a.de` |
| `bauer-group.com` | `25000-040.cloud.bauer-group.com` |

Beim NOTIFY signalisiert der Primary "Zone X hat sich geaendert".
Der Secondary holt die Zone via AXFR und liest dabei den SOA. Der MNAME
muss zur supermasters-Konfig passen, sonst wird die Zone abgewiesen.

## Diagnose: Was sendet mein Primary?

**Auf dem Secondary:**

```bash
sudo dns-admin primary discover <primary-ip> <bekannte-zone>
```

Beispiel:

```text
$ sudo dns-admin primary discover 88.99.66.3 example.com

Frage SOA von 'example.com' bei Primary 88.99.66.3 ab...

============================================
  Discovery-Ergebnis
============================================
  Zone:    example.com
  Primary: 88.99.66.3
  MNAME:   ns1.example.com
  Status:  NICHT in supermasters - dieser MNAME wird beim NOTIFY abgewiesen!

  Eintrag hinzufuegen mit:
    sudo dns-admin primary add ns1.example.com 88.99.66.3
```

**Manuell mit dig:**

```bash
dig @88.99.66.3 example.com SOA +short
# Beispiel-Output: ns1.example.com. hostmaster.example.com. 2024010101 ...
# Erste Spalte = MNAME -> der gehoert in supermasters
```

## Plesk-spezifisch

### Variante 1: DNS-Template vereinheitlichen (empfohlen)

`Tools & Settings → DNS Template`. Setze die NS-Records so, dass alle
Zonen denselben MNAME haben - typischerweise den FQDN des Plesk-Servers:

```text
NS-Record:    <server-fqdn>.
SOA-Record:   <server-fqdn>.
```

Beispiel: alle Zonen bekommen MNAME = `25000-040.cloud.bauer-group.com`.
Damit reicht ein einziger supermaster-Eintrag.

> Plesk wendet Template-Aenderungen nur auf **neue** Zonen an. Bestehende
> Zonen muessen einzeln aktualisiert werden:
> `Domains → DNS Settings → Restore default zone records`

### Variante 2: Pro-Zone-MNAMEs

Wenn jede Zone einen eigenen NS hat (z.B. `ns1.kunde-a.de`,
`ns1.kunde-b.de`), muessen alle vorkommenden MNAMEs eingetragen werden:

```bash
sudo dns-admin primary add ns1.kunde-a.de 88.99.66.3 2a01:4f8:10a:125d::2
sudo dns-admin primary add ns1.kunde-b.de 88.99.66.3 2a01:4f8:10a:125d::2
sudo dns-admin primary add ns1.kunde-c.de 88.99.66.3 2a01:4f8:10a:125d::2
```

Bei vielen Zonen wird das schnell unwartbar - dann lieber Variante 1.

### Plesk: Secondary als Slave eintragen

`Tools & Settings → Slave DNS Servers → Add`:

| Feld | Wert |
|------|------|
| IP-Adresse | `78.46.253.197` (IPv4 dieses Secondary) |
| IPv6-Adresse | `2a01:4f8:c014:8177::1` |

Plesk sendet automatisch NOTIFY an alle eingetragenen Slave-Server bei
Zone-Aenderungen. Es triggert NOTIFY auch initial fuer alle bestehenden
Zonen, sobald der Slave hinzugefuegt wird.

### Plesk: NOTIFY pro Zone aktivieren

Standardmaessig aktiv. Falls deaktiviert: `Domain → DNS Settings →` und
NOTIFY-Optionen pruefen.

## BIND-spezifisch

In `named.conf` pro Zone:

```bind
zone "example.com" {
    type master;
    file "/var/named/example.com.zone";
    also-notify { 78.46.253.197; 2a01:4f8:c014:8177::1; };
    allow-transfer { 78.46.253.197; 2a01:4f8:c014:8177::1; };
    notify yes;
};
```

Globale Einstellungen koennen die Liste fuer alle Zonen festlegen:

```bind
options {
    also-notify { 78.46.253.197; 2a01:4f8:c014:8177::1; };
    allow-transfer { 78.46.253.197; 2a01:4f8:c014:8177::1; };
    notify yes;
};
```

NOTIFY manuell ausloesen:

```bash
sudo rndc notify example.com
```

## Workflow: Vom Primary zur ersten Zone auf dem Secondary

1. **Primary konfigurieren:** Secondary als Slave eintragen +
   NOTIFY aktivieren (siehe oben).
2. **MNAME ermitteln:**

   ```bash
   sudo dns-admin primary discover <primary-ip> <eine-bestehende-zone>
   ```

3. **Supermaster anpassen** falls noetig:

   ```bash
   sudo dns-admin primary add <mname> <ipv4> <ipv6>
   ```

4. **NOTIFY ausloesen:**
   - Plesk: Zone aendern (z.B. TTL anpassen) oder Slave neu eintragen
   - BIND: `rndc notify <zone>`
5. **Pruefen:**

   ```bash
   sudo dns-admin zone list                     # Zone sollte erscheinen
   dig @127.0.0.1 example.com SOA               # Auth-Antwort
   sudo journalctl -u pdns -f                   # NOTIFY-Empfang live
   ```

## Haeufige Fehler

| Symptom | Ursache | Loesung |
|---------|---------|---------|
| Zone erscheint nicht nach NOTIFY | MNAME passt nicht zu supermasters | `dns-admin primary discover` |
| `Received NOTIFY but no master found` im Journal | Source-IP nicht in supermasters | `dns-admin primary add` |
| AXFR schlaegt fehl | `allow-transfer` auf Primary fehlt | Primary konfigurieren |
| Zone kommt durch, aber nicht erreichbar | Firewall blockiert Port 53 | `sudo ufw status`, ggf. `sudo ufw allow 53` |
| `dns-admin primary discover` Timeout | Primary blockt Queries vom Secondary | Auf Primary: `allow-query` pruefen |
| MNAME haendelt das `.` am Ende inkonsistent | normaler trailing dot der DNS-Notation | `discover` entfernt ihn automatisch |

## Troubleshooting

### NOTIFY-Empfang im Log beobachten

```bash
sudo journalctl -u pdns -f
```

Erwartet bei korrekter Konfig:

```text
Received NOTIFY for example.com from 88.99.66.3
AXFR done for example.com (123 records)
```

Bei MNAME-Mismatch:

```text
Received NOTIFY for example.com from 88.99.66.3 with serial 2024010101,
however we are not auto-secondary, ignoring (no matching supermaster)
```

### Manueller AXFR-Test

Wenn NOTIFY-Empfang funktioniert, aber AXFR fehlschlaegt:

```bash
# Auf dem Secondary - holt die Zone manuell
dig @<primary-ip> example.com AXFR
```

Erwartet: komplette Zone-Records. Bei `Transfer failed`: `allow-transfer`
auf dem Primary pruefen.

### Supermasters-Tabelle direkt inspizieren

```bash
sudo sqlite3 /var/lib/powerdns/pdns.sqlite3 \
  "SELECT ip, nameserver, account FROM supermasters ORDER BY nameserver, ip;"
```

### Zone-Status pro Zone

```bash
sudo dns-admin zone show example.com
# oder
sudo pdnsutil show-zone example.com
```

Letzte erfolgreiche AXFR + naechster Refresh-Zeitpunkt:

```bash
sudo sqlite3 /var/lib/powerdns/pdns.sqlite3 \
  "SELECT name, master, last_check, datetime(last_check, 'unixepoch') AS last_check_human
   FROM domains;"
```
