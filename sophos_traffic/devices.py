"""Benoemde apparaten: herkenning op MAC, tellers per apparaat en meldingen.

Profielen:
  lokaal       mag internet, hoort het niet te gebruiken -> melding bij contact
  internet     normaal internetgebruik -> alleen tellers/trends
  geblokkeerd  staat dicht in de firewall -> alleen teller geblokkeerde pogingen
"""

import ipaddress
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone

log = logging.getLogger("sophos_traffic")

PROFILES = ("lokaal", "internet", "geblokkeerd")
MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.IGNORECASE)
SOFTWARE_UPDATE = "software update"


def norm_mac(mac):
    mac = (mac or "").strip().lower().replace("-", ":")
    return mac if MAC_RE.match(mac) else ""


def is_internet(dst_ip):
    try:
        return ipaddress.ip_address(dst_ip).is_global
    except ValueError:
        return False


def load_device_config(path):
    """Leest devices, meld_software_update en melding_interval uit options.json."""
    devices, melden_updates, interval_min = {}, True, 60
    try:
        with open(path, "r", encoding="utf-8") as fh:
            opts = json.load(fh)
    except FileNotFoundError:
        return devices, melden_updates, interval_min
    except ValueError as err:
        log.warning("options.json onleesbaar (%s), geen apparaten", err)
        return devices, melden_updates, interval_min
    if isinstance(opts.get("meld_software_update"), bool):
        melden_updates = opts["meld_software_update"]
    try:
        interval_min = max(1, min(1440, int(opts.get("melding_interval", 60))))
    except (TypeError, ValueError):
        pass
    for item in opts.get("devices", []) or []:
        try:
            mac = norm_mac(item["mac"])
            name = str(item["name"]).strip()
            profile = str(item.get("profile", "internet")).strip().lower()
            if not mac:
                raise ValueError("ongeldig MAC-adres")
            if not name:
                raise ValueError("lege naam")
            if profile not in PROFILES:
                raise ValueError(f"onbekend profiel '{profile}'")
        except (KeyError, ValueError, TypeError) as err:
            log.warning("Ongeldig apparaat %s: %s", item, err)
            continue
        if mac in devices:
            log.warning("MAC %s staat dubbel in de apparatenlijst, eerste telt", mac)
            continue
        devices[mac] = {"name": name, "profile": profile}
        log.info("Apparaat: %s (%s) profiel %s", name, mac, profile)
    return devices, melden_updates, interval_min


class Devices:
    """Tellers per benoemd apparaat, met persistentie in een klein JSON-bestand."""

    def __init__(self, path, config, melden_updates=True, interval_min=60):
        self.path = path
        self.config = config            # mac -> {name, profile}
        self.melden_updates = melden_updates
        self.interval = interval_min * 60
        self.lock = threading.Lock()
        self.data = {}                  # mac -> tellers
        self.removed = []               # (mac, name) uit de config verdwenen
        self.last_alert = {}            # mac -> monotonic tijd
        self.dirty = False
        self._load()
        for mac, cfg in config.items():
            entry = self.data.setdefault(mac, self._empty())
            entry["name"] = cfg["name"]
            entry["profile"] = cfg["profile"]
        for mac in [m for m in self.data if m not in config]:
            self.removed.append((mac, self.data.pop(mac)["name"]))
            self.dirty = True

    @staticmethod
    def _empty():
        return {"name": "", "profile": "internet", "rx": 0, "tx": 0,
                "sessions": 0, "blocked": 0, "last_contact": None}

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh).get("devices", {})
            for mac, entry in raw.items():
                base = self._empty()
                base.update({k: entry[k] for k in base if k in entry})
                self.data[mac] = base
        except FileNotFoundError:
            pass
        except (ValueError, AttributeError, TypeError) as err:
            log.warning("Apparatenstatus onleesbaar (%s), begint opnieuw", err)

    def save(self):
        with self.lock:
            if not self.dirty:
                return
            payload = {"saved": int(time.time()), "devices": self.data}
            self.dirty = False
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, separators=(",", ":"))
            os.replace(tmp, self.path)
        except OSError as err:
            log.error("Kon apparatenstatus niet opslaan: %s", err)
            with self.lock:
                self.dirty = True

    def snapshot(self):
        with self.lock:
            return {k: dict(v) for k, v in self.data.items()}

    # ---- verwerking van één logregel ----

    def handle(self, fields, category):
        """Verwerkt een firewallregel. Geeft een melding (dict) terug of None.

        category: de uiteindelijke categorie (na overrides) of None.
        """
        mac = norm_mac(fields.get("src_mac"))
        if not mac or mac not in self.config:
            return None
        if fields.get("log_type") != "Firewall":
            return None
        to_internet = (fields.get("dst_zone_type") == "WAN"
                       or is_internet(fields.get("dst_ip", "")))
        if not to_internet:
            return None
        subtype = fields.get("log_subtype")
        now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

        with self.lock:
            entry = self.data[mac]
            if subtype == "Denied":
                entry["blocked"] += 1
                self.dirty = True
                return None
            if subtype != "Allowed":
                return None
            event = fields.get("con_event")
            if event == "Stop":
                try:
                    rx = max(0, int(fields.get("bytes_received", 0) or 0))
                    tx = max(0, int(fields.get("bytes_sent", 0) or 0))
                except ValueError:
                    rx = tx = 0
                entry["rx"] += rx
                entry["tx"] += tx
                entry["sessions"] += 1
            elif event != "Start":
                return None
            entry["last_contact"] = now_iso
            self.dirty = True
            profile = entry["profile"]
            name = entry["name"]

        if profile != "lokaal":
            return None
        sophos_cat = fields.get("app_category", "").strip().lower()
        if not self.melden_updates and (
                sophos_cat == SOFTWARE_UPDATE
                or (category or "").strip().lower() == SOFTWARE_UPDATE):
            return None
        now = time.monotonic()
        if now - self.last_alert.get(mac, -1e12) < self.interval:
            return None
        self.last_alert[mac] = now
        return {
            "event_type": "internetcontact",
            "apparaat": name,
            "mac": mac,
            "categorie": category or fields.get("app_category") or "onbekend",
            "app": fields.get("app_name") or "",
            "bestemming": fields.get("dst_ip", ""),
            "poort": fields.get("dst_port", ""),
            "land": fields.get("dst_country", ""),
            "netwerk": fields.get("in_interface", ""),
            "tijd": now_iso,
        }
