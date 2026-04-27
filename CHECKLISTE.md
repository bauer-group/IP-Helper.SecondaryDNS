# Deployment-Checkliste Secondary DNS

## Vor dem Deployment

Pro Primary-Server vorbereiten (es koennen mehrere sein):

- [ ] **Primary 1 Hostname:** ___________________
- [ ] **Primary 1 IPv4:** ___________________
- [ ] **Primary 1 IPv6:** ___________________
- [ ] **Primary 2 Hostname:** ___________________ (optional)
- [ ] **Primary 2 IPv4:** ___________________ (optional)
- [ ] **Primary 2 IPv6:** ___________________ (optional)

Allgemein:

- [ ] **Admin E-Mail:** ___________________
- [ ] **Cloud-Provider ausgewaehlt:** ___________________

## Konfiguration

### Bei Cloud-Init (`cloud-init.yaml`)

Parameter im `.env` Block anpassen:

- [ ] `PRIMARY_1_HOSTNAME`, `PRIMARY_1_IPV4`, `PRIMARY_1_IPV6` gesetzt
- [ ] Weitere `PRIMARY_N_*`-Bloecke einkommentieren falls benoetigt
- [ ] `ADMIN_EMAIL` gesetzt
- [ ] `SSH_PUBKEY` eingetragen (optional)
- [ ] `SECONDARY_HOSTNAME` angepasst
- [ ] `SECONDARY_FQDN` angepasst

### Bei manuellem Script (`install.sh`)

- [ ] `.env` Datei aus `.env.example` erstellt
- [ ] Alle Pflichtparameter in `.env` gesetzt

## Deployment

- [ ] VM erstellt (mind. 1 vCPU, 1 GB RAM, 10 GB SSD)
- [ ] Cloud-Init/Script ausgefuehrt
- [ ] Server erreichbar via SSH
- [ ] PowerDNS laeuft: `systemctl status pdns`
- [ ] Firewall aktiv: `ufw status`

## Primary DNS Konfiguration (Plesk/BIND)

> **Wichtig:** Detail-Anleitung pro Primary-Typ in [PRIMARY-SETUP.md](PRIMARY-SETUP.md).
> Wenn Zonen nach NOTIFY nicht erscheinen, ist meist der **MNAME im SOA**
> nicht in `supermasters` - siehe `dns-admin primary discover`.

Pro konfiguriertem Primary:

- [ ] Secondary als Slave eingetragen (IPv4 + IPv6)
- [ ] NOTIFY fuer Secondary aktiviert
- [ ] Test-Zone angelegt
- [ ] MNAME-Diagnose durchgefuehrt:
      `sudo dns-admin primary discover <primary-ip> <test-zone>`
- [ ] Falls MNAME-Mismatch: passender `dns-admin primary add` ausgefuehrt

## Funktionstest

```bash
# Auf dem Secondary Server:

# 1. Status & Primaries
dns-admin status
dns-admin primary list

# 2. Zonen vom Primary uebernommen?
dns-admin zone list

# 3. Autoritative Abfrage funktioniert?
dig @localhost example.com A

# 4. Unbekannte Domain wird abgelehnt? (REFUSED erwartet)
dig @localhost google.com A

# 5. Health-Check
dns-admin health

# 6. Von extern erreichbar?
dig @<SECONDARY_IP> example.com A
```

- [ ] `dns-admin status` zeigt alle Primaries
- [ ] Zonen sind synchronisiert (`dns-admin zone list`)
- [ ] Autoritative Antworten korrekt
- [ ] Unbekannte Domains -> REFUSED (keine Rekursion!)
- [ ] Von extern erreichbar (IPv4 + IPv6)
- [ ] `dns-admin health` -> OK

## DNS-Registrar

- [ ] NS-Records beim Registrar aktualisiert
- [ ] Propagation geprueft (nach 24-48h)

## Spaeteres Hinzufuegen weiterer Primaries

```bash
sudo dns-admin primary add ns3.example.com 192.0.2.30 2001:db8::30
```

PowerDNS wird automatisch neu geladen. Kein Re-Install noetig.

## Abschluss

- [ ] Dokumentation aktualisiert
- [ ] Uebergabe an Betrieb

---

**Deployment durchgefuehrt von:** ___________________

**Datum:** ___________________
