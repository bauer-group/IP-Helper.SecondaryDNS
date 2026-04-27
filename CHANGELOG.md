## [1.0.0](https://github.com/bauer-group/IP-Helper.SecondaryDNS/compare/v0.0.0...v1.0.0) (2026-04-27)

### ⚠ BREAKING CHANGES

* PRIMARY_DNS_IP und PRIMARY_DNS_HOSTNAME werden nicht mehr
gelesen. Bestehende Deployments muessen die .env / cloud-init.yaml auf das
neue Format umstellen (siehe .env.example).

### 🚀 Features

* erweiterte Multi-Primary-Unterstuetzung mit IPv4+IPv6 und dns-admin Tool ([fbba7ee](https://github.com/bauer-group/IP-Helper.SecondaryDNS/commit/fbba7ee71209a0c5729b606068f20bb72b737855))
