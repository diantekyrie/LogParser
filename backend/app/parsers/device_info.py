"""Parser for device/build facts: the plain-text preamble at the very top
of the bugreport (no delimiter of its own -- see PREAMBLE in
section_extractor.py) plus the `SYSTEM PROPERTIES (getprop)` dump.

Every field is optional and reported as unknown, never guessed, if a given
bugreport (different OS version/vendor) doesn't print it.
"""
from __future__ import annotations

import re

from app.parsers.base import DeviceInfo
from app.parsers.section_extractor import Section

PREAMBLE_FIELD_RES = {
    "build_id": re.compile(r"^Build:\s*(.+)$"),
    "build_fingerprint": re.compile(r"^Build fingerprint:\s*'?([^']*)'?$"),
    "bootloader": re.compile(r"^Bootloader:\s*(.+)$"),
    "radio": re.compile(r"^Radio:\s*(.+)$"),
    "network": re.compile(r"^Network:\s*(.+)$"),
    "kernel": re.compile(r"^Kernel:\s*(.+)$"),
    "uptime": re.compile(r"^Uptime:\s*(.+)$"),
}
SERIALNO_RE = re.compile(r'^androidboot\.serialno\s*=\s*"([^"]*)"')

PROP_LINE_RE = re.compile(r"^\[([\w.]+)\]:\s*\[(.*)\]\s*$")

PROP_FIELD_MAP = {
    "ro.product.manufacturer": "manufacturer",
    "ro.product.model": "model",
    "ro.build.version.release": "android_release",
    "ro.build.version.sdk": "sdk_version",
    "ro.build.version.security_patch": "security_patch",
    "ro.product.cpu.abi": "cpu_abi",
    "ro.hardware": "hardware",
    "ro.build.type": "build_type",
    "persist.sys.timezone": "timezone",
    "ro.crypto.state": "crypto_state",
    "ro.debuggable": "debuggable",
    "ro.boot.verifiedbootstate": "verified_boot_state",
}


def parse_device_info(preamble: Section | None, system_properties: Section | None) -> DeviceInfo:
    info = DeviceInfo()

    if preamble is not None:
        for line in preamble.lines:
            m = SERIALNO_RE.match(line.strip())
            if m:
                info.serial = m.group(1)
                continue
            for field_name, rx in PREAMBLE_FIELD_RES.items():
                m = rx.match(line)
                if m:
                    setattr(info, field_name, m.group(1).strip())

    if system_properties is not None:
        for line in system_properties.lines:
            m = PROP_LINE_RE.match(line)
            if not m:
                continue
            key, value = m.group(1), m.group(2)
            field_name = PROP_FIELD_MAP.get(key)
            if not field_name:
                continue
            if field_name == "sdk_version":
                info.sdk_version = int(value) if value.isdigit() else None
            elif field_name == "debuggable":
                info.debuggable = value == "1"
            else:
                setattr(info, field_name, value or None)

    return info
