# Changelog

## 0.4.3
- `negeer_ntp` (standaard aan): tijdsynchronisatie (UDP 123) van benoemde
  apparaten telt niet als internetcontact; geen melding en geen update van
  *laatste internetcontact*.

## 0.4.2
- Elk benoemd apparaat is een eigen HA-device (gekoppeld aan *Sophos Traffic*),
  zodat namen kort zijn: "S-HB-NAS03 download" in plaats van
  "Sophos Traffic Apparaat S-HB-NAS03 download". Entity-ID's blijven gelijk.
- Trend-cards: grafieken via het gewone auto-entities-filter op `profiel`
  (statistics-graph werkt niet met een template-filter).

## 0.4.1
- Apparaatsensoren krijgen attributen `naam`, `profiel` en `mac`.
- Trend-cards (`ha/trend-cards.yaml`) vullen zichzelf via auto-entities: een nieuw
  apparaat verschijnt automatisch in de card die bij zijn profiel hoort.

## 0.4.0
- Benoemde apparaten (`devices`: MAC, naam, profiel `lokaal`/`internet`/`geblokkeerd`).
  Per apparaat sensoren voor download, upload, sessies naar internet,
  geblokkeerde pogingen en laatste internetcontact.
- Event-entity `event.sophos_traffic_melding`: vuurt bij internetcontact van een
  `lokaal`-apparaat, met categorie, bestemming, poort en land. Maximaal één keer
  per apparaat per `melding_interval` minuten.
- `meld_software_update`: firmware-/software-updates van lokale apparaten wel of
  niet melden.
- Geweigerde regels naar internet worden per benoemd apparaat geteld (niet opgeslagen).
- Apparaten die uit de lijst verdwijnen, worden ook uit HA verwijderd.
- Voorbeelden: automation voor de melding en trend-cards.

## 0.3.0
- Tellers per netwerk: bytes per inkomende firewall-interface (`in_interface`,
  bijv. VLAN's), als sensoren `Netwerk <interface> download/upload`.
- WAN-sensoren direct beschikbaar na een start (laatste SNMP-meting wordt bij
  het verbinden met MQTT meteen verstuurd).
- `snmp_host` accepteert `host:poort`.
- Sankey-voorbeeld: netwerken → Internet → categorieën, met datumkiezer.

## 0.2.0
- WAN-totaal via SNMP zit nu in de app zelf (`snmp_host`, `snmp_community`,
  `snmp_interface`, `snmp_interval`). Het YAML-package in HA is niet meer nodig.
- Interface op naam (bijv. `Port11`); ifIndex wordt zelf opgezocht en opnieuw
  bepaald als het verandert.
- SNMP probeert zelf opnieuw na een storing; de WAN-sensoren gaan tussentijds
  op *unavailable*.
- Nieuwe sensoren `sensor.sophos_traffic_wan_download` / `_upload`.
- Sankey-voorbeeldcard bijgewerkt (Pulseway, QUIC/SSL, restpost).

## 0.1.4
- `app_overrides`: Sophos `app_name` naar eigen categorie. Standaard worden
  *QUIC* en *Secure Socket Layer Protocol* uit *Infrastructure* gehaald, zodat
  niet-herkend verkeer apart zichtbaar is.

## 0.1.3
- `dst_overrides`: bestemmings-IP of -subnet naar eigen categorie (bijv. Pulseway).

## 0.1.2
- Debug-log toont bij genegeerde regels alleen de relevante velden.

## 0.1.1
- Parser ondersteunt ook *Standard syslog protocol* (`key=value` zonder quotes).
- Debug-modus logt maximaal 5 genegeerde regels per 15 minuten.

## 0.1.0
- Eerste versie: syslog → tellers per Sophos app-categorie → MQTT discovery.
