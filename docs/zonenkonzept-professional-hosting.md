# Zonenkonzept: `professional-hosting.com` (n:1, PowerDNS + Plesk)

Konzeptionelle Gesamtsicht des DNS-Aufbaus fuer
`professional-hosting.com`: welche Hostnamen welche Rolle haben, wie die
Zonen zwischen Plesk-Primaries und PowerDNS-Secondary verteilt sind, und
wo welche Konfiguration eingetragen werden muss.

> **Geltungsbereich:** Diese Datei beschreibt das **Pattern**. Den
> konkreten Vorgang "neuer Plesk-Primary wird angebunden" Schritt-fuer-
> Schritt zeigt [plesk-musterfall-professional-hosting.md](plesk-musterfall-professional-hosting.md)
> am Beispiel `ns8`. Mechanik-Hintergrund (NOTIFY/AXFR, MNAME-Pruefung)
> in [PRIMARY-SETUP.md](../PRIMARY-SETUP.md).

## Inhalt

- [Architektur-Pattern](#architektur-pattern)
- [Rollen und Hostnamen](#rollen-und-hostnamen)
- [DNS-Template pro Plesk-Server](#dns-template-pro-plesk-server)
- [Plesk -> Secondary: Slave-DNS-Eintrag](#plesk---secondary-slave-dns-eintrag)
- [Secondary -> PowerDNS: Supermasters](#secondary---powerdns-supermasters)
- [Zentrale Basis-Zone `professional-hosting.com`](#zentrale-basis-zone-professional-hostingcom)
- [Kundendomain-Delegation](#kundendomain-delegation)
- [Resilienz-Eigenschaften](#resilienz-eigenschaften)
- [Lebenszyklus](#lebenszyklus)

## Architektur-Pattern

```text
                    .com Registry (Glue nur bei Variante B)
                              |
              +---------------+----------------+
              |                                |
              v                                v
+-------------------------+      +-------------------------+
| Secondary (PowerDNS)    |      | Plesk-Primaries         |
|                         | <----+ ns2  (Plesk Server 1)   |
| ns1.professional-       |  N   + ns3  (Plesk Server 2)   |
| hosting.com             |  O   + ...                     |
|                         |  T   + nsN  (Plesk Server N-1) |
| - SLAVE, stabil         |  I   |                         |
| - aggregiert alle Zonen |  F   | - kommen + gehen        |
| - read-only Mirror      |  Y   | - jeder ist MASTER      |
|                         | <----+   eigener Kundenzonen   |
| supermasters:           |      | - SOA-MNAME = eigener   |
|   (ns2-ip, ns2-host)    |      |   Hostname              |
|   (ns3-ip, ns3-host)    |      +-------------------------+
|   ...                   |
+-------------------------+
```

**Konsequenzen aus dem Pattern:**

- `ns1` ist **Slave** — pflegt keine Quelldaten, sondern zieht alle Zonen
  via AXFR aus den jeweiligen Plesks. Wird einmal mit [install.sh](../install.sh)
  installiert und im Hostnamen/IP nicht mehr veraendert.
- Jeder Plesk ist **Master seiner Kundenzonen** und gibt sich auch im
  SOA-Record so aus: SOA-MNAME jeder Zone = Plesk-Hostname (z.B.
  `ns2.professional-hosting.com.` fuer Zonen auf Plesk Server 1).
- Die NS-Records **in jeder Zone** listen den jeweiligen Plesk-Primary
  **plus** `ns1` (zwei oeffentliche NS fuer Resilienz) — beides wird
  ueber das Plesk-DNS-Template ausgerollt.

## Rollen und Hostnamen

| Rolle                    | Hostname                       | IPv4              | IPv6              | Funktion                                  |
|--------------------------|--------------------------------|-------------------|-------------------|-------------------------------------------|
| Secondary / Aggregator   | `ns1.professional-hosting.com` | `<POWERDNS_IPV4>` | `<POWERDNS_IPV6>` | Slave, stabil, aggregiert alle Kundenzonen|
| Primary (Plesk Server 1) | `ns2.professional-hosting.com` | `<PLESK1_IPV4>`   | `<PLESK1_IPV6>`   | Master der auf Plesk #1 angelegten Zonen  |
| Primary (Plesk Server 2) | `ns3.professional-hosting.com` | `<PLESK2_IPV4>`   | `<PLESK2_IPV6>`   | Master der auf Plesk #2 angelegten Zonen  |
| Primary (Plesk Server X) | `nsN.professional-hosting.com` | `<PLESKN_IPV4>`   | `<PLESKN_IPV6>`   | analog, je eigener Master                 |

> **Konvention:** `ns1` ist dauerhaft der Aggregator, `nsN` (N>=2) sind
> Plesk-Primaries. Der Aggregator wird einmal installiert und im
> Hostnamen/IP nicht mehr veraendert. Plesks kommen und gehen.

## DNS-Template pro Plesk-Server

Jeder Plesk hat sein eigenes Template — der **eigene** Hostname wird
**zuerst** als NS-Record eingetragen, dann `ns1`.

> **Plesk-Quirk:** Der SOA-MNAME ist im Plesk-UI nicht direkt setzbar.
> Plesk leitet ihn aus dem **erstangelegten** NS-Record ab. Reihenfolge
> ist deshalb nicht kosmetisch. Details:
> [Musterfall Schritt 1b](plesk-musterfall-professional-hosting.md#schritt-1---dns-zonen-template-auf-plesk-ns8-umbauen).

### Plesk Server 1 (`ns2`)

```text
{DOMAIN}.   NS   ns2.professional-hosting.com.   ; zuerst -> wird zum MNAME
{DOMAIN}.   NS   ns1.professional-hosting.com.   ; danach -> zusaetzlicher NS

; Resultierender SOA wird von Plesk so generiert:
{DOMAIN}.   SOA  ns2.professional-hosting.com. hostmaster.professional-hosting.com. (
              <serial> 10800 3600 604800 10800 )
```

### Plesk Server 2 (`ns3`)

```text
{DOMAIN}.   NS   ns3.professional-hosting.com.   ; zuerst -> wird zum MNAME
{DOMAIN}.   NS   ns1.professional-hosting.com.

{DOMAIN}.   SOA  ns3.professional-hosting.com. hostmaster.professional-hosting.com. (
              <serial> 10800 3600 604800 10800 )
```

### Weitere Plesks (`ns4`, `ns5`, ...)

Bauen ihr Template analog: **eigener Hostname zuerst**, `ns1` als
zweiter NS. Der trailing dot ist Pflicht (sonst haengt Plesk die
Kundendomain dran -> `ns4.professional-hosting.com.kunde-a.de.`).

## Plesk -> Secondary: Slave-DNS-Eintrag

Auf **jedem** Plesk unter `Tools & Einstellungen -> Slave DNS Servers
-> Hinzufuegen`:

| Feld         | Wert              |
|--------------|-------------------|
| IP-Adresse   | `<POWERDNS_IPV4>` |
| IPv6-Adresse | `<POWERDNS_IPV6>` |

Bewirkt zweierlei:

- `allow-transfer` fuer `ns1` -> AXFR erlaubt
- NOTIFY an `ns1` bei jeder Zonen-Aenderung + initialer Push beim
  Eintragen

> **Beide IPs** (v4 + v6) eintragen. PowerDNS prueft NOTIFY pro
> Source-IP einzeln gegen `supermasters`. IPv6-NOTIFY ohne IPv6-Eintrag
> -> "no matching supermaster" -> ignoriert.

## Secondary -> PowerDNS: Supermasters

Auf `ns1` einmal pro Plesk-Primary registrieren:

```bash
# Plesk Server 1 aufnehmen
sudo dns-admin primary add ns2.professional-hosting.com \
  <PLESK1_IPV4> <PLESK1_IPV6>

# Plesk Server 2 aufnehmen
sudo dns-admin primary add ns3.professional-hosting.com \
  <PLESK2_IPV4> <PLESK2_IPV6>
```

Das schreibt vier Eintraege in `supermasters`:

| ip              | nameserver                     |
|-----------------|--------------------------------|
| `<PLESK1_IPV4>` | `ns2.professional-hosting.com` |
| `<PLESK1_IPV6>` | `ns2.professional-hosting.com` |
| `<PLESK2_IPV4>` | `ns3.professional-hosting.com` |
| `<PLESK2_IPV6>` | `ns3.professional-hosting.com` |

> **Strikte Pruefung:** PowerDNS akzeptiert NOTIFY nur, wenn
> `(Source-IP, MNAME)` als Paar in der Tabelle steht. Kein Wildcard,
> kein Suffix-Match. Hintergrund:
> [PRIMARY-SETUP.md "Die zwei Bedingungen"](../PRIMARY-SETUP.md#die-zwei-bedingungen).

**Selbstcheck pro Primary** (empfohlen vor jedem `primary add`):

```bash
sudo dns-admin primary discover <PLESK_IPV4> <eine-zone-auf-diesem-plesk>
# Erste Spalte muss der ns*-Hostname dieses Plesk sein (NICHT ns1!)
```

Wenn `discover` `ns1` zurueckmeldet, ist das Plesk-Template noch nicht
korrekt -> Reihenfolge der NS-Records pruefen.

## Zentrale Basis-Zone `professional-hosting.com`

Loest die Hostnamen `ns1..nsN` zu IPs auf. **Wo** diese Zone gehostet
wird, ist eine bewusste Architekturentscheidung.

### Variante A (empfohlen): extern hosten

`professional-hosting.com` liegt z.B. bei Cloudflare, Hetzner-DNS,
Registrar-DNS, einem Anycast-Provider — **nicht** auf diesem Aufbau.
Zone-Inhalt:

```dns
ns1   IN  A     <POWERDNS_IPV4>
ns1   IN  AAAA  <POWERDNS_IPV6>
ns2   IN  A     <PLESK1_IPV4>
ns2   IN  AAAA  <PLESK1_IPV6>
ns3   IN  A     <PLESK2_IPV4>
ns3   IN  AAAA  <PLESK2_IPV6>
; ... fuer jeden weiteren Plesk eine A + AAAA
```

**Vorteil:** Glue-Records bei `.com`-Registry sind **nicht** noetig —
Resolver folgen normaler Recursion ueber `.com` zum externen DNS und
finden die A/AAAA dort. Kein Henne-Ei-Problem, kein Schicksal an dieser
Infrastruktur.

### Variante B: auf eigenem Aufbau hosten

`professional-hosting.com` liegt z.B. auf `ns2` als Master und auf
`ns1` als Mirror. Dann entsteht das Henne-Ei-Problem: die A/AAAA fuer
`ns1`/`ns2` stehen in einer Zone, die ohne `ns1`/`ns2` nicht aufloesbar
ist.

Loesung: **Glue-Records bei der `.com`-Registry** — einmalig, NUR fuer
die Provider-Domain (nicht fuer jede Kundendomain):

| Hostname                       | IPv4              | IPv6              |
|--------------------------------|-------------------|-------------------|
| `ns1.professional-hosting.com` | `<POWERDNS_IPV4>` | `<POWERDNS_IPV6>` |
| `ns2.professional-hosting.com` | `<PLESK1_IPV4>`   | `<PLESK1_IPV6>`   |
| `ns3.professional-hosting.com` | `<PLESK2_IPV4>`   | `<PLESK2_IPV6>`   |

UI-Pfad: bei Hetzner Robot `Domains -> professional-hosting.com ->
Nameservers -> Add own nameserver`; bei INWX/united-domains/Cloudflare
Registrar heisst die Funktion meist "Hostnames" oder "Child
Nameservers".

> Glue bei den **Kundendomain**-Registrars (`.de`, `.org`, ...) ist
> **nicht** noetig — die ns-Hosts liegen out-of-bailiwick. Details:
> [Musterfall Schritt 3b](plesk-musterfall-professional-hosting.md#schritt-3---ns-hostnamen-ns1-und-ns8-aufloesbar-machen).

## Kundendomain-Delegation

Pro Kundendomain — z.B. `aschenbrenner-bau.de`, `kunde-b.com` — muss
beim Registrar der Kundendomain die NS-Liste auf den Plesk gesetzt
werden, der die Zone haelt, **plus** `ns1`:

```text
Nameserver 1:  ns<X>.professional-hosting.com   ; der Plesk, der diese Zone haelt
Nameserver 2:  ns1.professional-hosting.com     ; immer ns1 als Mirror
```

Sind mehr NS-Slots beim Registrar verfuegbar (typisch 4-8): leer
lassen ODER mit zusaetzlichen `nsY` befuellen, sobald sie existieren —
das erhoeht die Resilienz, ist aber nicht zwingend.

> **Pre-Switch-Check:** Vor dem Umstellen einer Kundendomain
> verifizieren, dass Plesk und Secondary identisch antworten:
>
> ```bash
> dig @<PLESK_IPV4>  <kundendomain> SOA +short   # Plesk direkt
> dig @<POWERDNS_IPV4> <kundendomain> SOA +short # Secondary
> # Beide muessen identische SOA-Serial liefern.
> ```

## Resilienz-Eigenschaften

| Ausfall                                | Verhalten                                                   |
|----------------------------------------|-------------------------------------------------------------|
| Plesk `nsX` faellt aus                 | `ns1` antwortet weiter autoritativ (Mirror); Aenderungen    |
|                                        | auf den `nsX`-Zonen sind pausiert bis `nsX` zurueck ist     |
| `ns1` (Aggregator) faellt aus          | Jeder Plesk antwortet weiter fuer **seine eigenen** Zonen   |
| Beide NS einer Kundendomain ausgefallen| SERVFAIL nach Cache-TTL — daher mindestens 2 NS pro Domain  |
| Basis-Zone (Variante A) extern haengt  | Resolver-Cache puffert TTL (`.com` default 24h); nach       |
|                                        | TTL-Ablauf SERVFAIL fuer **alle** Kundendomains             |

> **Minimum:** zwei NS pro Kundendomain (eigener Plesk + `ns1`). Mehr
> Resilienz durch zusaetzliche Plesks in der NS-Liste — orthogonal
> dazu, welchem Plesk die Zone gehoert.

## Lebenszyklus

| Event                       | Vorgehen                                                                |
|-----------------------------|-------------------------------------------------------------------------|
| Secondary `ns1` neu aufbauen| [install.sh](../install.sh) mit `PRIMARY_*`-Bloecken fuer alle bekannten Plesks |
| Neuer Plesk `nsN` kommt     | Komplett-Walkthrough: [plesk-musterfall-professional-hosting.md](plesk-musterfall-professional-hosting.md) |
| Plesk `nsN` geht (Decom)    | Auf `ns1`: `sudo dns-admin primary remove nsN.professional-hosting.com` |
|                             | + verwaiste Zonen aufraeumen ([Musterfall Anhang](plesk-musterfall-professional-hosting.md#spaeter-weitere-primaries-ns9-ns10--anbinden)) |
| Plesk-Hostname-Aenderung    | Wie "geht + kommt": alten Eintrag entfernen, neuen anlegen — Plesk-     |
|                             | seitig Template + SOA-MNAME anpassen, dann `primary add` mit neuem Wert |
| Secondary-Wartung           | Plesks antworten weiter; kein Customer-Impact solange `ns1` + ein `nsN` |
|                             | je Domain extern erreichbar bleiben                                     |
