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
