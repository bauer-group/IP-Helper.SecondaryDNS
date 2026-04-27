## [1.1.0](https://github.com/bauer-group/IP-Helper.SecondaryDNS/compare/v1.0.3...v1.1.0) (2026-04-27)

### 🚀 Features

* **security:** haerterer fail2ban-Schutz und Sichtbarkeit in dns-admin ([db5bd29](https://github.com/bauer-group/IP-Helper.SecondaryDNS/commit/db5bd29d14da378f533bf61d3f9dbb3823ff8389))

## [1.0.3](https://github.com/bauer-group/IP-Helper.SecondaryDNS/compare/v1.0.2...v1.0.3) (2026-04-27)

### 🐛 Bug Fixes

* **install:** konvertiere true/false zu yes/no fuer sshd_config ([7ebef7f](https://github.com/bauer-group/IP-Helper.SecondaryDNS/commit/7ebef7fa5e91aff555d03f21b459112999850e36))

## [1.0.2](https://github.com/bauer-group/IP-Helper.SecondaryDNS/compare/v1.0.1...v1.0.2) (2026-04-27)

### 🐛 Bug Fixes

* **install:** reload SSH-Service via SIGHUP statt restart ([1098b3b](https://github.com/bauer-group/IP-Helper.SecondaryDNS/commit/1098b3b9d45d3450a4873bc07c551be1a66dd71a))

## [1.0.1](https://github.com/bauer-group/IP-Helper.SecondaryDNS/compare/v1.0.0...v1.0.1) (2026-04-27)

### 🐛 Bug Fixes

* **install:** erkannte SSH-Service-Name dynamisch (ssh vs sshd) ([f3c4546](https://github.com/bauer-group/IP-Helper.SecondaryDNS/commit/f3c45462497590aa0d9cc3900d73bffa1b99a01e))

## [1.0.0](https://github.com/bauer-group/IP-Helper.SecondaryDNS/compare/v0.0.0...v1.0.0) (2026-04-27)

### ⚠ BREAKING CHANGES

* PRIMARY_DNS_IP und PRIMARY_DNS_HOSTNAME werden nicht mehr
gelesen. Bestehende Deployments muessen die .env / cloud-init.yaml auf das
neue Format umstellen (siehe .env.example).

### 🚀 Features

* erweiterte Multi-Primary-Unterstuetzung mit IPv4+IPv6 und dns-admin Tool ([fbba7ee](https://github.com/bauer-group/IP-Helper.SecondaryDNS/commit/fbba7ee71209a0c5729b606068f20bb72b737855))
