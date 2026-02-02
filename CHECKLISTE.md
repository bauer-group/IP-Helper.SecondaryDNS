# Deployment-Checkliste Secondary DNS

## Vor dem Deployment

- [ ] **Primary DNS IP(s):** ___________________
- [ ] **Primary DNS Hostname:** ___________________
- [ ] **Admin E-Mail:** ___________________
- [ ] **Cloud-Provider ausgewählt:** ___________________

## Konfiguration

### Bei Cloud-Init (`cloud-init.yaml`)

Parameter im `.env` Block anpassen (Zeilen 20-50):

- [ ] `PRIMARY_DNS_IP` gesetzt
- [ ] `PRIMARY_DNS_HOSTNAME` gesetzt
- [ ] `ADMIN_EMAIL` gesetzt
- [ ] `SSH_PUBKEY` eingetragen (optional)
- [ ] `SECONDARY_HOSTNAME` angepasst
- [ ] `SECONDARY_FQDN` angepasst

### Bei manuellem Script (`install.sh`)

- [ ] `.env` Datei aus `.env.example` erstellt
- [ ] Alle Pflichtparameter in `.env` gesetzt

## Deployment

- [ ] VM erstellt (2 vCPU, 4 GB RAM, 10 GB SSD)
- [ ] Cloud-Init/Script ausgeführt
- [ ] Server erreichbar via SSH
- [ ] PowerDNS läuft: `systemctl status pdns`
- [ ] Firewall aktiv: `ufw status`

## Primary DNS Konfiguration (Plesk/BIND)

- [ ] Secondary als Slave eingetragen
- [ ] NOTIFY für Secondary aktiviert
- [ ] Test-Zone angelegt

## Funktionstest

```bash
# Auf dem Secondary Server:

# 1. Zonen vom Primary übernommen?
pdnsutil list-all-zones

# 2. Autoritative Abfrage funktioniert?
dig @localhost example.com A

# 3. Unbekannte Domain wird abgelehnt? (REFUSED erwartet)
dig @localhost google.com A

# 4. Von extern erreichbar?
dig @<SECONDARY_IP> example.com A
```

- [ ] Zonen sind synchronisiert
- [ ] Autoritative Antworten korrekt
- [ ] Unbekannte Domains → REFUSED (keine Rekursion!)
- [ ] Von extern erreichbar

## DNS-Registrar

- [ ] NS-Records beim Registrar aktualisiert
- [ ] Propagation geprüft (nach 24-48h)

## Abschluss

- [ ] Dokumentation aktualisiert
- [ ] Übergabe an Betrieb

---

**Deployment durchgeführt von:** ___________________

**Datum:** ___________________
