"""Minimale SNMPv2c-client (GET / GETNEXT) zonder externe afhankelijkheden.

Genoeg om 64-bit interfacetellers (IF-MIB ifHCInOctets/ifHCOutOctets) uit te
lezen en een interface op naam (ifName) op te zoeken.
"""

import random
import socket

IF_NAME = (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1)
IF_HC_IN_OCTETS = (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6)
IF_HC_OUT_OCTETS = (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10)

TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_COUNTER32 = 0x41
TAG_GAUGE32 = 0x42
TAG_TIMETICKS = 0x43
TAG_COUNTER64 = 0x46
PDU_GET = 0xA0
PDU_GETNEXT = 0xA1
PDU_RESPONSE = 0xA2
EXCEPTIONS = {0x80: "noSuchObject", 0x81: "noSuchInstance", 0x82: "endOfMibView"}
UNSIGNED = (TAG_COUNTER32, TAG_GAUGE32, TAG_TIMETICKS, TAG_COUNTER64)


class SnmpError(Exception):
    """Protocolfout, foutstatus van de agent of onverwacht antwoord."""


# ---------------------------------------------------------------- BER encode

def _len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag, value):
    return bytes([tag]) + _len(len(value)) + value


def _int(n):
    size = max(1, (n.bit_length() + 8) // 8)
    return _tlv(TAG_INTEGER, n.to_bytes(size, "big", signed=True))


def _oid(oid):
    if len(oid) < 2:
        raise ValueError("OID te kort")
    out = bytearray([40 * oid[0] + oid[1]])
    for part in oid[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        out.extend(reversed(chunk))
    return _tlv(TAG_OID, bytes(out))


def build_request(community, pdu_tag, request_id, oid):
    varbind = _tlv(TAG_SEQUENCE, _oid(oid) + _tlv(TAG_NULL, b""))
    pdu = _tlv(pdu_tag, _int(request_id) + _int(0) + _int(0)
               + _tlv(TAG_SEQUENCE, varbind))
    return _tlv(TAG_SEQUENCE, _int(1) + _tlv(TAG_OCTET_STRING, community.encode())
                + pdu)


# ---------------------------------------------------------------- BER decode

def _read(data, pos):
    if pos + 2 > len(data):
        raise SnmpError("afgekapt antwoord")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise SnmpError("ongeldige lengte")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise SnmpError("afgekapt antwoord")
    return tag, data[pos:end], end


def _decode_oid(raw):
    if not raw:
        raise SnmpError("lege OID")
    oid = [raw[0] // 40, raw[0] % 40]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            oid.append(value)
            value = 0
    return tuple(oid)


def _decode_value(tag, raw):
    if tag == TAG_INTEGER:
        return int.from_bytes(raw, "big", signed=True)
    if tag in UNSIGNED:
        return int.from_bytes(raw, "big", signed=False)
    if tag == TAG_OCTET_STRING:
        return raw.decode("utf-8", errors="replace")
    if tag == TAG_OID:
        return _decode_oid(raw)
    if tag in EXCEPTIONS:
        return None
    return raw


def parse_response(data, request_id):
    """Geeft (oid, tag, waarde) van de eerste varbind terug."""
    tag, msg, _ = _read(data, 0)
    if tag != TAG_SEQUENCE:
        raise SnmpError("geen SNMP-bericht")
    _, _, pos = _read(msg, 0)            # version
    _, _, pos = _read(msg, pos)          # community
    tag, pdu, _ = _read(msg, pos)
    if tag != PDU_RESPONSE:
        raise SnmpError(f"onverwacht PDU-type 0x{tag:02x}")
    _, rid, pos = _read(pdu, 0)
    if int.from_bytes(rid, "big", signed=True) != request_id:
        raise SnmpError("request-id komt niet overeen")
    _, status, pos = _read(pdu, pos)
    _, _, pos = _read(pdu, pos)          # error-index
    status = int.from_bytes(status, "big", signed=True)
    if status:
        raise SnmpError(f"agent gaf foutstatus {status}")
    _, varbinds, _ = _read(pdu, pos)
    _, varbind, _ = _read(varbinds, 0)
    _, oid_raw, pos = _read(varbind, 0)
    vtag, vraw, _ = _read(varbind, pos)
    return _decode_oid(oid_raw), vtag, _decode_value(vtag, vraw)


# ---------------------------------------------------------------- client

class SnmpClient:
    def __init__(self, host, community, port=161, timeout=2.0, retries=1):
        self.addr = (host, port)
        self.community = community
        self.timeout = timeout
        self.retries = retries

    def _request(self, pdu_tag, oid):
        last_err = None
        for _ in range(self.retries + 1):
            rid = random.randint(1, 0x7FFFFFFF)
            packet = build_request(self.community, pdu_tag, rid, oid)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                try:
                    sock.sendto(packet, self.addr)
                    while True:
                        data, _ = sock.recvfrom(65535)
                        try:
                            return parse_response(data, rid)
                        except SnmpError as err:
                            if "request-id" in str(err):
                                continue  # oud antwoord, blijf wachten
                            raise
                except socket.timeout as err:
                    last_err = err
        raise SnmpError(f"geen antwoord van {self.addr[0]}") from last_err

    def get(self, oid):
        """Waarde van precies deze OID; SnmpError als die niet bestaat."""
        roid, tag, value = self._request(PDU_GET, oid)
        if tag in EXCEPTIONS:
            raise SnmpError(f"{EXCEPTIONS[tag]} voor {'.'.join(map(str, oid))}")
        return value

    def walk(self, base, limit=1000):
        """Geeft (oid, waarde) voor alle OIDs onder base (GETNEXT-reeks)."""
        oid = base
        for _ in range(limit):
            oid, tag, value = self._request(PDU_GETNEXT, oid)
            if tag in EXCEPTIONS or oid[:len(base)] != base:
                return
            yield oid, value

    def find_ifindex(self, name):
        """ifIndex van de interface met deze ifName (hoofdletterongevoelig)."""
        wanted = name.strip().lower()
        for oid, value in self.walk(IF_NAME):
            if isinstance(value, str) and value.strip().lower() == wanted:
                return oid[-1]
        raise SnmpError(f"interface '{name}' niet gevonden in ifName")
