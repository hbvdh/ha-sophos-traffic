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

VERSION = "0.1.3"
OPTIONS_FILE = os.environ.get("OPTIONS_FILE", "/data/options.json")

LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "5514"))
STATE_FILE = os.environ.get("STATE_FILE", "/data/state.json")
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
TOTAL_SLUG = "total"

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
    """Geeft (categorie, rx, tx) terug voor relevante sessies, anders None.

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
    category = override_for(fields.get("dst_ip", "")) \
        or fields.get("app_category", "").strip() or UNCATEGORIZED
    return category, rx, tx


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
    def __init__(self, path, max_categories):
        self.path = path
        self.max_categories = max_categories
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
        """Telt op; geeft True terug als dit een nieuwe categorie is."""
        slug = slugify(category)
        with self.lock:
            is_new = slug not in self.data
            if is_new and len(self.data) >= self.max_categories:
                slug = slugify(OVERFLOW)
                category = OVERFLOW
                is_new = slug not in self.data
            if is_new:
                self.data[slug] = {"name": category, "rx": 0, "tx": 0}
            self.data[slug]["rx"] += rx
            self.data[slug]["tx"] += tx
            self.dirty = True
            return is_new

    def snapshot(self):
        with self.lock:
            return {k: dict(v) for k, v in self.data.items()}


# --------------------------------------------------------------------------
# MQTT
# --------------------------------------------------------------------------

class Publisher:
    def __init__(self, counters):
        import paho.mqtt.client as mqtt

        self.counters = counters
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

    global OVERRIDES
    OVERRIDES = load_overrides()
    counters = Counters(STATE_FILE, MAX_CATEGORIES)
    publisher = Publisher(counters)
    publisher.start()

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
                    result = classify(parse(line))
                    if result is None:
                        stats["ignored"] += 1
                        if stats["ignored"] <= DEBUG_SAMPLES:
                            f = parse(line)
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
                    category, rx, tx = result
                    stats["counted"] += 1
                    if counters.add(category, rx, tx):
                        log.info("Nieuwe categorie: %s", category)
                        snap = counters.snapshot()
                        slug = slugify(category)
                        if slug not in snap:  # overloop naar "Other categories"
                            slug = slugify(OVERFLOW)
                        publisher.publish_discovery(slug, snap[slug]["name"])
                    log.debug("%s +%d/%d bytes", category, rx, tx)

        now = time.monotonic()
        if now >= next_flush:
            publisher.publish_states()
            counters.save()
            next_flush = now + FLUSH_INTERVAL
        if now >= next_stats:
            log.info("Laatste 15 min: %d datagrammen, %d geteld, %d genegeerd, %d van ander adres",
                     stats["datagrams"], stats["counted"], stats["ignored"], stats["foreign"])
            stats = dict.fromkeys(stats, 0)
            next_stats = now + STATS_LOG_INTERVAL

    publisher.publish_states()
    counters.save()
    publisher.stop()
    sock.close()
    log.info("Gestopt")


if __name__ == "__main__":
    main()
