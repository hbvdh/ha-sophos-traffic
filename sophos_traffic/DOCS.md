# Sophos Traffic Collector — installatie

Lokale HA-add-on die Sophos-firewall-syslog ontvangt (UDP 5514), per afgesloten
LAN→WAN-sessie de bytes optelt per `app_category`, en dat via MQTT discovery als
sensoren in HA zet. Er worden **geen logregels opgeslagen**; alleen
`/data/state.json` met tellerstanden (paar KB, wordt overschreven).

Bestanden:

| Pad | Doel |
|---|---|
| `sophos_traffic/` | de app |
| `ha/packages/sophos_traffic.yaml` | SNMP-sensoren WAN-totaal |
| `ha/sankey-card.yaml` | dashboard-card |

## 1. App installeren

1. **Settings → Apps → App store** → ⋮ → **Repositories** → voeg
   `https://github.com/hbvdh/ha-sophos-traffic` toe.
2. Installeer **Sophos Traffic Collector** (bouwt lokaal, paar minuten).
3. Tab **Configuration**: `firewall_ip` = het IP waarmee de XG syslog verstuurt.
   Pas `dst_overrides` aan naar wens.
4. **Start**, controleer de **Log**: `Verbonden met MQTT` en `Luistert op UDP 5514`.

### Opties

| Optie | Standaard | Betekenis |
|---|---|---|
| `firewall_ip` | leeg | Alleen syslog van dit adres verwerken |
| `flush_interval` | 30 | Seconden tussen MQTT-updates en opslaan van tellers |
| `max_categories` | 60 | Daarboven komt alles in *Other categories* |
| `log_level` | info | `debug` toont genegeerde regels (max. 5 per 15 min) |
| `dst_overrides` | Pulseway | Lijst `ip` (adres of subnet) → `category` |
| `app_overrides` | QUIC, SSL | Lijst `app` (Sophos `app_name`, hoofdletterongevoelig) → `category` |

Volgorde: `dst_overrides` gaat voor `app_overrides`, daarna de Sophos-categorie.

## 2. Sophos (SFOS 22)

Labels kunnen per build iets afwijken — controleer op het scherm.

1. **QUIC**: regel boven `#Default_OptimusPrime_Policy` (en evt. andere
   uitgaande regels): LAN → WAN, UDP 443, actie **Reject**, *Log firewall traffic* uit.
2. **Syslog**: *System services → Log settings* → syslog-server toevoegen:
   IP van HA, **UDP 5514**, facility DAEMON, severity Information,
   format **Standard syslog protocol**.
3. Vink in de log-settings-tabel voor deze server **alleen Firewall → Firewall rules** aan.
4. Controleer dat *Log firewall traffic* aanstaat op alle uitgaande regels.
5. **SNMP**: *Administration → SNMP* → agent aan, v2c-community alleen voor het
   HA-IP; *Administration → Device access* → SNMP aan voor de zone waar HA in zit.

Na een paar minuten verschijnt in HA onder
**Settings → Devices & services → MQTT** het device **Sophos Traffic** met per
categorie een download- en uploadsensor, plus `Total download/upload`.

## 3. ifIndex van Port11 opzoeken

In **Advanced SSH & Web Terminal**:

```sh
apk add net-snmp-tools
snmpwalk -v2c -c <community> <xg-ip> 1.3.6.1.2.1.31.1.1.1.1
```

De regel met `Port11` eindigt op het ifIndex-nummer, bijv. `...1.1.1.1.11 = STRING: "Port11"` → ifIndex 11.
Controleer: `snmpget -v2c -c <community> <xg-ip> 1.3.6.1.2.1.31.1.1.1.6.<ifIndex>` geeft een grote, oplopende teller.

## 4. SNMP-package in HA

1. Zet in `configuration.yaml` (eenmalig, als je nog geen packages gebruikt):

   ```yaml
   homeassistant:
     packages: !include_dir_named packages
   ```

2. Kopieer `ha/packages/sophos_traffic.yaml` naar `/config/packages/`,
   vul `host` en `<IFINDEX>` in.
3. `secrets.yaml`: `sophos_snmp_community: "<jouw community>"`
4. **Developer tools → YAML → Check configuration**, daarna herstarten.

## 5. Dashboard

**Ha Sankey Chart** is al geïnstalleerd. Nieuwe card → **Manual** → inhoud van
`ha/sankey-card.yaml`. Na een dag de categorieën aanvullen met wat er echt
binnenkomt. Weergave in GB stel je per sensor in via entity-instellingen
(*Unit of measurement*), de card doet dat zelf met `unit_prefix: auto`.

## Opslag en opruiming

- Add-on: alleen `state.json` (overschreven, groeit niet). Stdout gaat naar de
  HA OS-journal (eigen limieten). Elke 15 min één regel met statistieken.
- Max. aantal categorieën is begrensd (`max_categories`, standaard 60);
  daarboven gaat alles naar *Other categories*.
- HA: sensoren vallen onder je recorder (`sensor`-domein, 120 dagen);
  long-term statistics zijn één rij per uur per sensor.

## Bekende beperkingen

- Bytes tellen pas mee bij het **afsluiten** van een sessie; lange streams ijlen na.
  Het SNMP-totaal is wel realtime → het verschil zie je als *Niet geclassificeerd*.
- *Niet geclassificeerd* bevat ook inkomend verkeer (port forwards), verkeer van de
  firewall zelf en protocol-overhead.
- UDP-syslog: tijdens een HA-herstart afgesloten sessies gaan verloren.
