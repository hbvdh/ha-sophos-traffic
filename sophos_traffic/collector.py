#!/usr/bin/env python3
"""Sophos Traffic Collector.

Ontvangt Sophos Firewall (SFOS) syslog via UDP, telt per afgesloten
LAN->WAN-sessie de bytes op per app_category en publiceert de tellers
via MQTT discovery naar Home Assistant.

Ontwerp: er worden GEEN logregels opgeslagen. Op schijf staat alleen
/data/state.json met de tellerstanden (een paar KB, wordt overschreven).
"""

import ipaddress
import json
import logging
import os
import re
import signal
import socket
import threading
import time

import devices
import snmp

VERSION = "0.4.3"
OPTIONS_FILE = os.environ.get("OPTIONS_FILE", "/data/options.json")

LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "5514"))
STATE_FILE = os.environ.get("STATE_FILE", "/data/state.json")
NET_STATE_FILE = os.path.join(os.path.dirname(STATE_FILE) or ".", "state_net.json")
DEV_STATE_FILE = os.path.join(os.path.dirname(STATE_FILE) or ".", "state_dev.json")
FIREWALL_IP = os.environ.get("FIREWALL_IP", "").strip()
if FIREWALL_IP.lower() in ("null", "none"):
    FIREWALL_IP = ""
FLUSH_INTERVAL = int(os.environ.get("FLUSH_INTERVAL", "30"))
MAX_CATEGORIES = int(os.environ.get("MAX_CATEGORIES", "60"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "info").upper()

MQTT_HOST = os.environ.get("MQTT_HOST", "core-mosquitto")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USER = os.environ.get("MQTT_USER") or None
MQTT_PASS = os.environ.get("MQTT_PASS") or None

DISCOVERY_PREFIX = "homeassistant"
BASE_TOPIC = "sophos_traffic"
AVAIL_TOPIC = f"{BASE_TOPIC}/status"
DEVICE_ID = "sophos_traffic"

UNCATEGORIZED = "Uncategorized"
OVERFLOW = "Other categories"
NET_PREFIX = "Netwerk "
NET_OVERFLOW = "Netwerk overig"
MAX_NETWORKS = 20
TOTAL_SLUG = "total"
WAN_SLUG = "wan"
WAN_AVAIL_TOPIC = f"{BASE_TOPIC}/{WAN_SLUG}/status"
EVENT_TOPIC = f"{BASE_TOPIC}/melding"
DEV_KINDS = {
    # kind: (label, extra discovery-config)
    "rx": ("download", {"unit_of_measurement": "B", "device_class": "data_size",
                         "state_class": "total_increasing", "icon": "mdi:download-network"}),
    "tx": ("upload", {"unit_of_measurement": "B", "device_class": "data_size",
                       "state_class": "total_increasing", "icon": "mdi:upload-network"}),
    "sessions": ("sessies", {"unit_of_measurement": "sessies",
                             "state_class": "total_increasing", "icon": "mdi:swap-horizontal"}),
    "blocked": ("geblokkeerd", {"unit_of_measurement": "pogingen",
                                "state_class": "total_increasing", "icon": "mdi:shield-off"}),
    "last_contact": ("laatste internetcontact", {"device_class": "timestamp",
                                                 "icon": "mdi:clock-alert-outline"}),
}

STATS_LOG_INTERVAL = 900  # samenvatting in de log elke 15 minuten

# key="value" (Device standard format) én key=value (Standard syslog protocol)
KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s"]+))')
DEBUG_SAMPLES = 5  # max. aantal genegeerde regels per 15 min in debug-log

log = logging.getLogger("sophos_traffic")


# --------------------------------------------------------------------------
# Parsen en filteren
# --------------------------------------------------------------------------

def parse(line):
    """Sophos key="value" paren naar dict."""
    return {k: (q if q or not u else u) for k, q, u in KV_RE.findall(line)}


def classify(fields):
    """Geeft (categorie, rx, tx, interface) terug voor relevante sessies, anders None.

    Relevant = toegestane, afgesloten sessie van een interne zone naar WAN.
    rx = bytes_received (download), tx = bytes_sent (upload), gezien vanaf
    de client.
    """
    if fields.get("log_type") != "Firewall":
        return None
    if fields.get("log_subtype") != "Allowed":
        return None
    if fields.get("con_event") != "Stop":
        return None
    if fields.get("dst_zone_type") != "WAN":
        return None
    if fields.get("src_zone_type", "") in ("", "WAN", "Local"):
        return None
    try:
        rx = int(fields.get("bytes_received", "0") or 0)
        tx = int(fields.get("bytes_sent", "0") or 0)
    except ValueError:
        return None
    if rx < 0 or tx < 0 or (rx == 0 and tx == 0):
        return None
    category = category_for(fields)
    interface = fields.get("in_interface", "").strip() or "onbekend"
    return category, rx, tx, interface


def category_for(fields):
    """Categorie van een sessie: dst_overrides, dan app_overrides, dan Sophos."""
    return (override_for(fields.get("dst_ip", ""))
            or APP_OVERRIDES.get(fields.get("app_name", "").strip().lower())
            or fields.get("app_category", "").strip()
            or UNCATEGORIZED)


# --------------------------------------------------------------------------
# App-overrides (app_overrides uit /data/options.json)
# --------------------------------------------------------------------------

APP_OVERRIDES = {}  # app_name (lowercase) -> categorie


def load_app_overrides(path=OPTIONS_FILE):
    """Leest app_overrides: [{app: "QUIC", category: "QUIC (niet herkend)"}]."""
    result = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            items = json.load(fh).get("app_overrides", []) or []
    except FileNotFoundError:
        return result
    except (ValueError, AttributeError) as err:
        log.warning("options.json onleesbaar (%s), geen app-overrides", err)
        return result
    for item in items:
        try:
            app = str(item["app"]).strip()
            cat = str(item["category"]).strip()
            if not app or not cat:
                raise ValueError("lege app of categorie")
        except (KeyError, ValueError, TypeError) as err:
            log.warning("Ongeldige app-override %s: %s", item, err)
            continue
        result[app.lower()] = cat
        log.info("App-override: %s -> %s", app, cat)
    return result


# --------------------------------------------------------------------------
# Bestemmingsoverrides (dst_overrides uit /data/options.json)
# --------------------------------------------------------------------------

OVERRIDES = []  # lijst van (ip_network, categorie)


def load_overrides(path=OPTIONS_FILE):
    """Leest dst_overrides: [{ip: "1.2.3.4" of "1.2.3.0/24", category: "Naam"}]."""
    result = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            items = json.load(fh).get("dst_overrides", []) or []
    except FileNotFoundError:
        return result
    except (ValueError, AttributeError) as err:
        log.warning("options.json onleesbaar (%s), geen overrides", err)
        return result
    for item in items:
        try:
            net = ipaddress.ip_network(str(item["ip"]).strip(), strict=False)
            cat = str(item["category"]).strip()
            if not cat:
                raise ValueError("lege categorie")
        except (KeyError, ValueError, TypeError) as err:
            log.warning("Ongeldige override %s: %s", item, err)
            continue
        result.append((net, cat))
        log.info("Override: %s -> %s", net, cat)
    return result


def override_for(dst_ip):
    if not OVERRIDES or not dst_ip:
        return None
    try:
        addr = ipaddress.ip_address(dst_ip)
    except ValueError:
        return None
    for net, cat in OVERRIDES:
        if addr in net:
            return cat
    return None


def slugify(name):
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return slug or "unknown"


# --------------------------------------------------------------------------
# Tellers + persistentie
# --------------------------------------------------------------------------

class Counters:
    def __init__(self, path, max_categories, overflow=OVERFLOW):
        self.path = path
        self.max_categories = max_categories
        self.overflow = overflow
        self.lock = threading.Lock()
        # slug -> {"name": str, "rx": int, "tx": int}
        self.data = {}
        self.dirty = False
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            for slug, entry in raw.get("categories", {}).items():
                self.data[slug] = {
                    "name": str(entry["name"]),
                    "rx": int(entry["rx"]),
                    "tx": int(entry["tx"]),
                }
            log.info("Tellerstanden geladen: %d categorieën", len(self.data))
        except FileNotFoundError:
            log.info("Geen statusbestand, start met lege tellers")
        except (ValueError, KeyError, TypeError) as err:
            log.warning("Statusbestand onleesbaar (%s), start met lege tellers", err)

    def save(self):
        with self.lock:
            if not self.dirty:
                return
            payload = {"version": VERSION, "saved": int(time.time()),
                       "categories": self.data}
            self.dirty = False
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, separators=(",", ":"))
            os.replace(tmp, self.path)  # atomisch, bestand groeit nooit
        except OSError as err:
            log.error("Kon status niet opslaan: %s", err)
            with self.lock:
                self.dirty = True

    def add(self, category, rx, tx):
        """Telt op; geeft (slug, naam, is_new) terug."""
        slug = slugify(category)
        with self.lock:
            is_new = slug not in self.data
            if is_new and len(self.data) >= self.max_categories:
                slug = slugify(self.overflow)
                category = self.overflow
                is_new = slug not in self.data
            if is_new:
                self.data[slug] = {"name": category, "rx": 0, "tx": 0}
            self.data[slug]["rx"] += rx
            self.data[slug]["tx"] += tx
            self.dirty = True
            return slug, self.data[slug]["name"], is_new

    def snapshot(self):
        with self.lock:
            return {k: dict(v) for k, v in self.data.items()}


# --------------------------------------------------------------------------
# MQTT
# --------------------------------------------------------------------------

class Publisher:
    def __init__(self, counters, net_counters=None, dev=None):
        import paho.mqtt.client as mqtt

        self.counters = counters
        self.net_counters = net_counters
        self.dev = dev
        self.wan_enabled = False
        self.last_wan = None  # (rx, tx) van de laatste geslaagde SNMP-meting
        self.connected = threading.Event()
        try:
            self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                                      client_id=DEVICE_ID)
        except AttributeError:  # paho-mqtt 1.x
            self.client = mqtt.Client(client_id=DEVICE_ID)
        if MQTT_USER:
            self.client.username_pw_set(MQTT_USER, MQTT_PASS)
        self.client.will_set(AVAIL_TOPIC, "offline", qos=1, retain=True)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.reconnect_delay_set(min_delay=1, max_delay=60)

    def start(self):
        self.client.connect_async(MQTT_HOST, MQTT_PORT, keepalive=60)
        self.client.loop_start()

    def stop(self):
        try:
            self.client.publish(AVAIL_TOPIC, "offline", qos=1, retain=True)
            time.sleep(0.5)
            self.client.disconnect()
        finally:
            self.client.loop_stop()

    def _on_connect(self, client, userdata, flags, reason_code, *args):
        if str(reason_code) not in ("0", "Success"):
            log.error("MQTT verbinding geweigerd: %s", reason_code)
            return
        log.info("Verbonden met MQTT %s:%s", MQTT_HOST, MQTT_PORT)
        self.connected.set()
        client.publish(AVAIL_TOPIC, "online", qos=1, retain=True)
        self.publish_discovery_all()
        if self.wan_enabled:
            self.publish_wan_discovery()
            if self.last_wan:
                self.publish_wan(*self.last_wan)
        self.publish_states()

    def _on_disconnect(self, client, userdata, *args):
        self.connected.clear()
        log.warning("MQTT verbinding verbroken, opnieuw verbinden…")

    @staticmethod
    def _device():
        return {
            "identifiers": [DEVICE_ID],
            "name": "Sophos Traffic",
            "manufacturer": "hbvdh",
            "model": "Sophos syslog collector",
            "sw_version": VERSION,
        }

    def _discovery(self, slug, name, direction):
        label = "download" if direction == "rx" else "upload"
        uid = f"{DEVICE_ID}_{slug}_{label}"
        config = {
            "name": f"{name} {label}",
            "unique_id": uid,
            "state_topic": f"{BASE_TOPIC}/{slug}/{direction}",
            "availability_topic": AVAIL_TOPIC,
            "unit_of_measurement": "B",
            "device_class": "data_size",
            "state_class": "total_increasing",
            "icon": "mdi:download-network" if direction == "rx" else "mdi:upload-network",
            "device": self._device(),
        }
        topic = f"{DISCOVERY_PREFIX}/sensor/{DEVICE_ID}/{slug}_{label}/config"
        self.client.publish(topic, json.dumps(config), qos=1, retain=True)

    def publish_discovery(self, slug, name):
        if not self.connected.is_set():
            return
        self._discovery(slug, name, "rx")
        self._discovery(slug, name, "tx")

    def publish_discovery_all(self):
        self._discovery(TOTAL_SLUG, "Total", "rx")
        self._discovery(TOTAL_SLUG, "Total", "tx")
        for slug, entry in self.counters.snapshot().items():
            self.publish_discovery(slug, entry["name"])
        if self.net_counters:
            for slug, entry in self.net_counters.snapshot().items():
                self.publish_discovery(slug, entry["name"])
        if self.dev is not None:
            self.publish_device_discovery()

    # ---- WAN-tellers via SNMP ----

    def publish_wan_discovery(self):
        for direction, label in (("rx", "download"), ("tx", "upload")):
            config = {
                "name": f"WAN {label}",
                "unique_id": f"{DEVICE_ID}_{WAN_SLUG}_{label}",
                "state_topic": f"{BASE_TOPIC}/{WAN_SLUG}/{direction}",
                "availability": [{"topic": AVAIL_TOPIC},
                                 {"topic": WAN_AVAIL_TOPIC}],
                "availability_mode": "all",
                "unit_of_measurement": "B",
                "device_class": "data_size",
                "state_class": "total_increasing",
                "icon": "mdi:wan",
                "device": self._device(),
            }
            topic = f"{DISCOVERY_PREFIX}/sensor/{DEVICE_ID}/{WAN_SLUG}_{label}/config"
            self.client.publish(topic, json.dumps(config), qos=1, retain=True)

    def publish_wan(self, rx, tx):
        self.last_wan = (rx, tx)
        if not self.connected.is_set():
            return
        self.client.publish(f"{BASE_TOPIC}/{WAN_SLUG}/rx", rx, retain=True)
        self.client.publish(f"{BASE_TOPIC}/{WAN_SLUG}/tx", tx, retain=True)
        self.client.publish(WAN_AVAIL_TOPIC, "online", qos=1, retain=True)

    def wan_unavailable(self):
        if self.connected.is_set():
            self.client.publish(WAN_AVAIL_TOPIC, "offline", qos=1, retain=True)

    def publish_states(self):
        if not self.connected.is_set():
            return
        snap = self.counters.snapshot()
        total_rx = total_tx = 0
        for slug, entry in snap.items():
            total_rx += entry["rx"]
            total_tx += entry["tx"]
            self.client.publish(f"{BASE_TOPIC}/{slug}/rx", entry["rx"], retain=True)
            self.client.publish(f"{BASE_TOPIC}/{slug}/tx", entry["tx"], retain=True)
        self.client.publish(f"{BASE_TOPIC}/{TOTAL_SLUG}/rx", total_rx, retain=True)
        self.client.publish(f"{BASE_TOPIC}/{TOTAL_SLUG}/tx", total_tx, retain=True)
        if self.net_counters:
            for slug, entry in self.net_counters.snapshot().items():
                self.client.publish(f"{BASE_TOPIC}/{slug}/rx", entry["rx"], retain=True)
                self.client.publish(f"{BASE_TOPIC}/{slug}/tx", entry["tx"], retain=True)
        if self.dev is not None:
            for mac, entry in self.dev.snapshot().items():
                base = f"{BASE_TOPIC}/dev/{mac.replace(':', '')}"
                for kind in DEV_KINDS:
                    value = entry.get(kind)
                    self.client.publish(f"{base}/{kind}",
                                        "None" if value is None else value, retain=True)

    # ---- benoemde apparaten en meldingen ----

    @staticmethod
    def _dev_config_topic(mac, kind):
        return f"{DISCOVERY_PREFIX}/sensor/{DEVICE_ID}/dev_{mac.replace(':', '')}_{kind}/config"

    def publish_device_discovery(self):
        for mac, entry in self.dev.snapshot().items():
            key = mac.replace(":", "")
            for kind, (label, extra) in DEV_KINDS.items():
                config = {
                    "name": label,
                    "unique_id": f"{DEVICE_ID}_dev_{key}_{kind}",
                    "state_topic": f"{BASE_TOPIC}/dev/{key}/{kind}",
                    "json_attributes_topic": f"{BASE_TOPIC}/dev/{key}/attr",
                    "availability_topic": AVAIL_TOPIC,
                    # elk benoemd apparaat is een eigen HA-device, gekoppeld aan
                    # Sophos Traffic; friendly name wordt "<naam> <label>"
                    "device": {
                        "identifiers": [f"{DEVICE_ID}_dev_{key}"],
                        "name": entry["name"],
                        "manufacturer": "Sophos Traffic",
                        "model": f"Profiel {entry['profile']}",
                        # bewust geen "connections" (MAC): HA zou het device dan
                        # samenvoegen met bv. het Shelly-device en de naam overnemen
                        "via_device": DEVICE_ID,
                    },
                }
                config.update(extra)
                self.client.publish(self._dev_config_topic(mac, kind),
                                    json.dumps(config), qos=1, retain=True)
            attrs = {"naam": entry["name"], "profiel": entry["profile"], "mac": mac}
            self.client.publish(f"{BASE_TOPIC}/dev/{key}/attr", json.dumps(attrs),
                                qos=1, retain=True)
        for mac, name in self.dev.removed:
            log.info("Apparaat %s (%s) niet meer in de lijst, entities verwijderd", name, mac)
            for kind in DEV_KINDS:
                self.client.publish(self._dev_config_topic(mac, kind), "", qos=1, retain=True)
            self.client.publish(f"{BASE_TOPIC}/dev/{mac.replace(':', '')}/attr", "",
                                qos=1, retain=True)
        config = {
            "name": "Melding",
            "unique_id": f"{DEVICE_ID}_melding",
            "state_topic": EVENT_TOPIC,
            "event_types": ["internetcontact"],
            "availability_topic": AVAIL_TOPIC,
            "icon": "mdi:alert-network",
            "device": self._device(),
        }
        self.client.publish(f"{DISCOVERY_PREFIX}/event/{DEVICE_ID}/melding/config",
                            json.dumps(config), qos=1, retain=True)

    def publish_event(self, payload):
        if self.connected.is_set():
            self.client.publish(EVENT_TOPIC, json.dumps(payload), qos=1, retain=False)


# --------------------------------------------------------------------------
# SNMP-poller (WAN-totaal)
# --------------------------------------------------------------------------

def load_snmp_config(path=OPTIONS_FILE):
    """Geeft dict met host/community/interface/interval, of None als SNMP uit staat."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            opts = json.load(fh)
    except (FileNotFoundError, ValueError):
        return None

    def opt(key, default=""):
        value = opts.get(key)
        return default if value in (None, "", "null") else value

    community = str(opt("snmp_community")).strip()
    interface = str(opt("snmp_interface")).strip()
    if not community or not interface:
        log.info("SNMP uit (snmp_community of snmp_interface niet ingesteld)")
        return None
    host = str(opt("snmp_host", FIREWALL_IP)).strip()
    if not host:
        log.warning("SNMP uit: geen snmp_host en geen firewall_ip ingesteld")
        return None
    port = 161
    if host.count(":") == 1:  # host:poort
        host, _, port_s = host.partition(":")
        try:
            port = int(port_s)
        except ValueError:
            log.warning("Ongeldige poort in snmp_host, gebruik 161")
    try:
        interval = max(10, min(600, int(opt("snmp_interval", 60))))
    except (TypeError, ValueError):
        interval = 60
    return {"host": host, "port": port, "community": community,
            "interface": interface, "interval": interval}


class SnmpPoller(threading.Thread):
    """Leest periodiek ifHCIn/OutOctets van de WAN-interface uit."""

    def __init__(self, cfg, publisher):
        super().__init__(name="snmp", daemon=True)
        self.cfg = cfg
        self.publisher = publisher
        self.client = snmp.SnmpClient(cfg["host"], cfg["community"],
                                      port=cfg.get("port", 161))
        self.stop_event = threading.Event()
        self.ifindex = None
        self.healthy = None  # None = nog onbekend

    def _resolve(self):
        name = self.cfg["interface"]
        if name.isdigit():
            return int(name)
        return self.client.find_ifindex(name)

    def poll_once(self):
        if self.ifindex is None:
            self.ifindex = self._resolve()
            log.info("SNMP: %s op %s = ifIndex %d",
                     self.cfg["interface"], self.cfg["host"], self.ifindex)
        try:
            rx = self.client.get(snmp.IF_HC_IN_OCTETS + (self.ifindex,))
            tx = self.client.get(snmp.IF_HC_OUT_OCTETS + (self.ifindex,))
        except snmp.SnmpError as err:
            if "noSuch" in str(err):
                self.ifindex = None  # interface hernummerd: opnieuw opzoeken
            raise
        if not isinstance(rx, int) or not isinstance(tx, int):
            raise snmp.SnmpError("onverwacht type voor interfaceteller")
        return rx, tx

    def run(self):
        while not self.stop_event.is_set():
            try:
                rx, tx = self.poll_once()
                self.publisher.publish_wan(rx, tx)
                if self.healthy is not True:
                    log.info("SNMP: WAN-tellers worden uitgelezen (elke %d s)",
                             self.cfg["interval"])
                self.healthy = True
            except (OSError, snmp.SnmpError) as err:
                if self.healthy is not False:
                    log.warning("SNMP mislukt (%s), blijft opnieuw proberen", err)
                self.publisher.wan_unavailable()
                self.healthy = False
            self.stop_event.wait(self.cfg["interval"])

    def stop(self):
        self.stop_event.set()


# --------------------------------------------------------------------------
# Hoofdlus
# --------------------------------------------------------------------------

def main():
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if FIREWALL_IP:
        log.info("Alleen syslog van %s wordt verwerkt", FIREWALL_IP)
    else:
        log.warning("firewall_ip niet ingesteld: syslog van elk adres wordt verwerkt")

    global OVERRIDES, APP_OVERRIDES
    OVERRIDES = load_overrides()
    APP_OVERRIDES = load_app_overrides()
    counters = Counters(STATE_FILE, MAX_CATEGORIES)
    net_counters = Counters(NET_STATE_FILE, MAX_NETWORKS, overflow=NET_OVERFLOW)
    dev_config, melden_updates, interval_min = devices.load_device_config(OPTIONS_FILE)
    negeer_ntp = devices.load_negeer_ntp(OPTIONS_FILE)
    dev = devices.Devices(DEV_STATE_FILE, dev_config, melden_updates, interval_min,
                          negeer_ntp)
    if dev_config:
        log.info("%d apparaten, melding max. 1x per %d min per apparaat, "
                 "software-updates %s, NTP %s", len(dev_config), interval_min,
                 "melden" if melden_updates else "niet melden",
                 "genegeerd" if negeer_ntp else "geteld")
    publisher = Publisher(counters, net_counters, dev)
    snmp_cfg = load_snmp_config()
    publisher.wan_enabled = snmp_cfg is not None
    publisher.start()
    poller = None
    if snmp_cfg:
        poller = SnmpPoller(snmp_cfg, publisher)
        poller.start()

    running = {"value": True}

    def _stop(signum, _frame):
        log.info("Signaal %s ontvangen, afsluiten…", signum)
        running["value"] = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    sock.settimeout(1.0)
    log.info("Luistert op UDP %d", LISTEN_PORT)

    stats = {"datagrams": 0, "counted": 0, "ignored": 0, "foreign": 0}
    next_flush = time.monotonic() + FLUSH_INTERVAL
    next_stats = time.monotonic() + STATS_LOG_INTERVAL

    while running["value"]:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            data, addr = None, None
        except OSError as err:
            if running["value"]:
                log.error("Socketfout: %s", err)
            data, addr = None, None

        if data:
            stats["datagrams"] += 1
            if FIREWALL_IP and addr[0] != FIREWALL_IP:
                stats["foreign"] += 1
            else:
                text = data.decode("utf-8", errors="replace")
                for line in text.splitlines():
                    fields = parse(line)
                    result = classify(fields)
                    if dev_config:
                        alert = dev.handle(fields, result[0] if result else category_for(fields))
                        if alert:
                            log.info("Melding: %s -> %s (%s, %s %s)", alert["apparaat"],
                                     alert["bestemming"], alert["categorie"],
                                     alert["land"], alert["poort"])
                            publisher.publish_event(alert)
                    if result is None:
                        stats["ignored"] += 1
                        if stats["ignored"] <= DEBUG_SAMPLES:
                            f = fields
                            log.debug(
                                "Genegeerd: rule=%s subtype=%s event=%s zones=%s->%s "
                                "if=%s->%s app=%s/%s bytes=%s/%s",
                                f.get("fw_rule_name"), f.get("log_subtype"),
                                f.get("con_event"), f.get("src_zone_type"),
                                f.get("dst_zone_type"), f.get("in_interface"),
                                f.get("out_interface"), f.get("app_name"),
                                f.get("app_category"), f.get("bytes_received"),
                                f.get("bytes_sent"))
                        continue
                    category, rx, tx, interface = result
                    stats["counted"] += 1
                    slug, name, is_new = counters.add(category, rx, tx)
                    if is_new:
                        log.info("Nieuwe categorie: %s", name)
                        publisher.publish_discovery(slug, name)
                    slug, name, is_new = net_counters.add(NET_PREFIX + interface, rx, tx)
                    if is_new:
                        log.info("Nieuw netwerk: %s", name)
                        publisher.publish_discovery(slug, name)
                    log.debug("%s via %s +%d/%d bytes", category, interface, rx, tx)

        now = time.monotonic()
        if now >= next_flush:
            publisher.publish_states()
            counters.save()
            net_counters.save()
            dev.save()
            next_flush = now + FLUSH_INTERVAL
        if now >= next_stats:
            log.info("Laatste 15 min: %d datagrammen, %d geteld, %d genegeerd, %d van ander adres",
                     stats["datagrams"], stats["counted"], stats["ignored"], stats["foreign"])
            stats = dict.fromkeys(stats, 0)
            next_stats = now + STATS_LOG_INTERVAL

    if poller:
        poller.stop()
    publisher.publish_states()
    counters.save()
    net_counters.save()
    dev.save()
    publisher.stop()
    sock.close()
    log.info("Gestopt")


if __name__ == "__main__":
    main()
