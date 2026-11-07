# ha-sophos-traffic

Home Assistant app (add-on) die het internetverkeer van een Sophos Firewall (SFOS)
per applicatiecategorie telt en als sensoren in Home Assistant zet — bedoeld voor
een Sankey-overzicht zoals het Energy dashboard.

- Ontvangt de firewall-syslog (UDP 5514), telt bytes per afgesloten LAN→WAN-sessie
  per `app_category` en publiceert via MQTT discovery.
- Slaat **geen** ruwe logs op; alleen tellerstanden (`/data/state.json`, paar KB).
- Leest zelf het WAN-totaal uit via SNMP; geen YAML in HA nodig.
- `dst_overrides` en `app_overrides` om vaste bestemmingen of niet-herkende
  protocollen een eigen categorie te geven.

## Installatie

**Settings → Apps → App store → ⋮ → Repositories** →
`https://github.com/hbvdh/ha-sophos-traffic` → installeer *Sophos Traffic Collector*.

Volledige uitleg (Sophos-instellingen, SNMP, dashboard): zie
[`sophos_traffic/DOCS.md`](sophos_traffic/DOCS.md). Een voorbeeld-Sankey-card staat in [`ha/`](ha/).
