# Changelog

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
