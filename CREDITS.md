# Credits & third-party licenses

This project stands on a lot of excellent open-source software. With thanks:

## Self-hosted web assets (served from this site)

Because these are served from our own origin (so visitors' browsers never call a
third-party CDN), their licenses are reproduced/linked here as the licenses require:

- **JetBrains Mono** — © The JetBrains Mono Project Authors. SIL Open Font License 1.1
  (OFL-1.1). https://github.com/JetBrains/JetBrainsMono
- **xterm.js** and **@xterm/addon-fit** — © The xterm.js authors. MIT License (the notice
  is preserved in the minified bundles we serve). https://github.com/xtermjs/xterm.js

JetBrains Mono is the only web font we serve; the rest of the UI uses the visitor's system
Helvetica/Arial stack, which is not redistributed. (Space Grotesk was previously self-hosted
but was dropped in the Swiss-editorial redesign.) The full SIL Open Font License 1.1 text is
served alongside the font itself (`/assets/fonts/OFL-JetBrainsMono.txt`) and is also available
at https://openfontlicense.org.

## Platform & infrastructure (run/hosted, not redistributed)

- **OWASP Juice Shop** — MIT License. https://github.com/juice-shop/juice-shop
- **Caddy** — Apache-2.0. https://github.com/caddyserver/caddy
- **Wazuh** (manager · indexer · dashboard · agent) — GPL-2.0 / Apache-2.0.
  https://github.com/wazuh/wazuh
- **OpenSearch & OpenSearch Dashboards** — Apache-2.0. https://github.com/opensearch-project
- **Grafana** — AGPL-3.0, run unmodified (config/provisioning only).
  https://github.com/grafana/grafana
- **Grafana Infinity** and **Grafana OpenSearch** datasource plugins.
- **Docker**, **Node.js**, and the orchestrator's npm deps (**express**, **dockerode**,
  **ws**, **http-proxy**) — used under their respective MIT/Apache/ISC licenses.

Each project remains the property of its respective authors and is used under its own license.
