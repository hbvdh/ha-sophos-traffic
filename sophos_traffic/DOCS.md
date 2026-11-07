# Sophos Traffic Collector

Home Assistant-app die het internetverkeer van een Sophos Firewall (SFOS) per
applicatiecategorie telt, plus het totaal over de WAN-lijn, en dat via MQTT
discovery als sensoren in Home Assistant zet. Bedoeld voor een Sankey-overzicht
zoals het Energy dashboard.

- **Categorieën**: de firewall-syslog komt binnen op UDP 5514. Per afgesloten
  LAN→WAN-sessie worden de bytes opgeteld per `app_category`.
- **WAN-totaal**: de app leest zelf de 64-bit interfacetellers van de
  WAN-poort uit via SNMP. Een YAML-package in HA is niet nodig.
- **Geen logopslag**: alleen `/data/state.json` met tellerstanden (paar KB,
  wordt steeds overschreven).

Alles komt onder één device **Sophos Traffic** (Settings → Devices & services → MQTT).

## 1. Installeren

1. **Settings → Apps → App store** → ⋮ → **Repositories** → voeg
   `https://github.com/hbvdh/ha-sophos-traffic` toe.
2. Installeer **Sophos Traffic Collector** (bouwt lokaal, paar minuten).
3. Tab **Configuration**: vul de opties in (zie hieronder). De SNMP-opties zijn
   optioneel; je ziet ze via **Show unused optional configuration options**.
4. **Start** en controleer de **Log**:
   - `Verbonden met MQTT` en `Luistert op UDP 5514`
   - met SNMP: `SNMP: Port11 op … = ifIndex …` en `WAN-tellers worden uitgelezen`

### Opties

| Optie | Standaard | Betekenis |
|---|---|---|
| `firewall_ip` | leeg | Alleen syslog van dit adres verwerken; ook standaard SNMP-host |
| `flush_interval` | 30 | Seconden tussen MQTT-updates en opslaan van tellers |
| `max_categories` | 60 | Daarboven komt alles in *Other categories* |
| `log_level` | info | `debug` toont genegeerde regels (max. 5 per 15 min) |
| `snmp_host` | `firewall_ip` | IP van de firewall voor SNMP (optioneel `host:poort`) |
| `snmp_community` | leeg | SNMP v2c-community. Leeg = SNMP uit |
| `snmp_interface` | leeg | WAN-interface op naam (`Port11`) of als ifIndex (`16`). Leeg = SNMP uit |
| `snmp_interval` | 60 | Seconden tussen SNMP-metingen (10–600) |
| `devices` | leeg | Benoemde apparaten: `mac`, `name`, `profile` (zie hieronder) |
| `meld_software_update` | aan | Ook melden als een `lokaal`-apparaat een update ophaalt |
| `melding_interval` | 60 | Minuten tussen meldingen per apparaat (1–1440) |
| `negeer_ntp` | aan | Tijdsync (UDP 123) van benoemde apparaten niet als internetcontact tellen |
| `dst_overrides` | Pulseway | Lijst `ip` (adres of subnet) → `category` |
| `app_overrides` | QUIC, SSL | Lijst `app` (Sophos `app_name`, hoofdletterongevoelig) → `category` |

Volgorde bij het indelen: `dst_overrides`, dan `app_overrides`, dan de Sophos-categorie.

Met `snmp_interface` op naam zoekt de app zelf het ifIndex op, en opnieuw als het
na een firmware-update verandert. Valt SNMP weg, dan gaan de WAN-sensoren op
*unavailable* en probeert de app het elke `snmp_interval` opnieuw.

### Apparaten en profielen

Apparaten worden herkend aan hun **MAC-adres** (niet het IP, want dat kan wisselen).
Alleen apparaten in de lijst krijgen eigen sensoren; de rest wordt per netwerk
samengevoegd. Persoonlijke apparaten verschijnen dus alleen als je ze zelf toevoegt.

| Profiel | Bedoeld voor | Wat de app doet |
|---|---|---|
| `lokaal` | IoT dat internet mag maar niet hoort te gebruiken | Melding bij elk contact met internet |
| `internet` | Servers, NAS, pc's, apparaten die de cloud nodig hebben | Alleen tellers en trends |
| `geblokkeerd` | Apparaten die in de firewall dichtstaan | Teller met geblokkeerde pogingen |

Invullen via **Configuration** → ⋮ → **Edit in YAML**:

```yaml
devices:
  - mac: D8:85:AC:EF:40:10
    name: Shelly EM Mini 1
    profile: lokaal
  - mac: 02:11:32:2A:5F:4A
    name: NAS03
    profile: internet
```

Telefoons met een willekeurig (privé) wifi-adres zet je voor je eigen netwerk op
*Vast*, anders verandert het MAC.

## 2. Sophos (SFOS 22)

Labels kunnen per build iets afwijken; controleer op het scherm.

1. **Syslog**: *System services → Log settings* → syslog-server toevoegen:
   IP van HA, **UDP 5514**, facility DAEMON, severity Information,
   format **Standard syslog protocol**.
2. Vink in de log-settings-tabel voor deze server **alleen Firewall → Firewall rules** aan.
3. Controleer dat *Log firewall traffic* aanstaat op alle uitgaande regels, en dat
   application control actief is op die regels.
4. **SNMP**: *Administration → SNMP* → agent aan, v2c-community alleen voor het
   HA-IP; *Administration → Device access* → SNMP aan voor de zone waar HA in zit.

Testen vanuit de **Advanced SSH & Web Terminal**:

```sh
apk add net-snmp-tools
snmpwalk -v2c -c <community> <xg-ip> 1.3.6.1.2.1.31.1.1.1.1
```

Daar zie je de interfacenamen voor `snmp_interface`.

## 3. Sensoren

| Sensor | Bron |
|---|---|
| `sensor.sophos_traffic_wan_download` / `_upload` | SNMP, realtime totaal over de WAN-lijn |
| `sensor.sophos_traffic_<categorie>_download` / `_upload` | Syslog, per categorie |
| `sensor.sophos_traffic_total_download` / `_upload` | Som van alle categorieën |
| `sensor.sophos_traffic_netwerk_<interface>_download` / `_upload` | Syslog, per inkomende interface (VLAN) |
| `sensor.sophos_traffic_apparaat_<naam>_download` / `_upload` | Per benoemd apparaat, bytes naar/van internet |
| `sensor.sophos_traffic_apparaat_<naam>_sessies` | Aantal afgesloten sessies naar internet |
| `sensor.sophos_traffic_apparaat_<naam>_geblokkeerd` | Aantal geweigerde pogingen naar internet |
| `sensor.sophos_traffic_apparaat_<naam>_laatste_internetcontact` | Tijdstip van het laatste internetcontact |
| `event.sophos_traffic_melding` | Melding bij internetcontact van een `lokaal`-apparaat |

Elke apparaatsensor heeft de attributen `naam`, `profiel` en `mac`.

De melding draagt als attributen: `apparaat`, `mac`, `categorie`, `app`,
`bestemming`, `poort`, `land`, `netwerk`, `tijd`. Een voorbeeld-automation staat in
[`ha/automation-melding.yaml`](https://github.com/hbvdh/ha-sophos-traffic/blob/main/ha/automation-melding.yaml).

De netwerksensoren heten naar de interface op de firewall, bijvoorbeeld
`sensor.sophos_traffic_netwerk_lag01_11_download` voor `LAG01.11`. Een leesbare
naam geef je in de card (`name:`). Sessies zonder interface komen in
*Netwerk onbekend*. Maximaal 20 netwerken; daarboven *Netwerk overig*.

Alle sensoren: `device_class: data_size`, `state_class: total_increasing`, in bytes.
Weergave in GB stel je per sensor in (*Unit of measurement*); de long-term
statistics blijven in bytes.

## 4. Dashboard

Installeer **Sankey Chart Card** (MindFreeze) via HACS. Voeg daarna op één
dashboard twee cards toe (Edit dashboard → **Add card** → **Manual**):

1. [`ha/date-picker-card.yaml`](https://github.com/hbvdh/ha-sophos-traffic/blob/main/ha/date-picker-card.yaml):
   de datumkiezer (dag, week, maand, jaar of eigen periode).
2. [`ha/sankey-card.yaml`](https://github.com/hbvdh/ha-sophos-traffic/blob/main/ha/sankey-card.yaml):
   netwerken → Internet → categorieën. Volgt de datumkiezer.

Zet de Sankey op volle breedte (tab **Layout**). Pas netwerknamen en categorieën
aan naar wat er bij jou binnenkomt. Wil je geen datumkiezer, vervang dan in de
Sankey `energy_date_selection: true` door `time_period_from: "now/d"`.

Plak card-YAML niet in de *Raw configuration editor*; die verwacht het hele dashboard.

Trends per apparaat: zie [`ha/trend-cards.yaml`](https://github.com/hbvdh/ha-sophos-traffic/blob/main/ha/trend-cards.yaml)
(staafgrafiek per dag, laatste internetcontact, sessies, geblokkeerde pogingen).
Deze cards gebruiken de HACS-card **auto-entities** en vullen zichzelf op basis
van het profiel: een nieuw apparaat in de app-config komt vanzelf in de juiste card.

## Opslag en opruiming

- App: alleen `state.json` (overschreven, groeit niet). Stdout gaat naar de
  HA OS-journal (eigen limieten). Elke 15 min één regel met statistieken.
- Max. aantal categorieën is begrensd (`max_categories`).
- HA: sensoren vallen onder je recorder; long-term statistics zijn één rij per
  uur per sensor.

## Bekende beperkingen

- Bytes per categorie tellen pas mee bij het **afsluiten** van een sessie; lange
  verbindingen (streams, RMM-agents) ijlen na. Het WAN-totaal is wel realtime;
  het verschil is in de card de restpost.
- De restpost bevat ook inkomend verkeer (port forwards), verkeer van de firewall
  zelf en protocol-overhead.
- Versleuteld verkeer dat Sophos niet herkent, komt als *QUIC* of *SSL (niet herkend)*.
- UDP-syslog: sessies die afsluiten terwijl de app herstart, gaan verloren.
- Geweigerde pogingen tellen alleen als de firewallregel logt. QUIC-rejects zonder
  logging tellen dus niet mee.

## Overstappen van 0.1.x met SNMP-package

Had je het WAN-totaal via `/config/packages/sophos_traffic.yaml`: verwijder dat
bestand en de secret `sophos_snmp_community`, herstart HA en verwijder daarna de
oude entities `sensor.sophos_wan_download` / `_upload` (Settings → Entities).
De nieuwe WAN-sensoren heten `sensor.sophos_traffic_wan_*`.
