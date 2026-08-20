"""Parser for `DUMP OF SERVICE companiondevice` -- the CDM service's own
current-state snapshot of every companion-device association, not inferred
from scattered log lines. This is a materially different (and stronger)
kind of evidence than cdm_pairing.py's log-line events: it's the service
reporting its own live state at the moment the bugreport was taken, so it
can directly answer "is this device currently paired/connected" instead of
requiring that to be reconstructed from a sequence of log messages.

Verified against a real capture (a Pixel phone paired with a Pixel Watch):

    Companion Device Associations:
      Association{mId=1, mUserId=0, mPackageName='com.google.android.apps.wear.companion',
      mDeviceMacAddress=64:9d:38:bc:d5:eb, mDisplayName='Pixel Watch 5 35WD',
      mDeviceProfile='android.app.role.COMPANION_DEVICE_WATCH', mSelfManaged=false,
      mAssociatedDevice=AssociatedDevice { device = XX:XX:XX:XX:D5:EB },
      mNotifyOnDeviceNearby=true, mRevoked=false, mPending=false, mTrusted=false,
      mTimeApprovedMs=Thu Jun 25 10:08:12 PDT 2026, mLastTimeConnectedMs=None, ...}
    Companion Device Present:
      Connected Bluetooth Devices:
        id=1, addr=64:9D:38:BC:D5:EB, pkg=u0/com.google.android.apps.wear.companion

Every real Association{...} entry seen so far is printed on a single line,
so this is a per-line regex extraction, not a brace parser -- the
mAssociatedDevice sub-object's own nested braces are never a problem because
each field is pulled independently by name, not by brace-matching.

Two real bugs found against a second real fixture, both fixed here:

1. mDisplayName is free text the user set on their own device (e.g. via
   Bluetooth device naming) and can itself contain an apostrophe --
   "mDisplayName='Diante's Pixel Buds 2a'" broke a naive `'([^']*)'`
   match, which stopped at the FIRST embedded apostrophe. Anchored to the
   next known field instead (", mDeviceProfile=") so the whole name is
   captured regardless of internal quotes.

2. `Association{...}` also appears in at least two OTHER places in this
   section that are not currently-active associations: a "Last Removed
   Association:" entry (revoked, historical), and a duplicate
   `associationInfoCache=Association{...}` deep inside this same
   section's "SyncService state" internals. Both would be wrongly
   reported as live associations by a plain substring/regex scan of every
   line. Only lines between the "Companion Device Associations:" heading
   and the next unindented (top-level) heading are considered.
"""
from __future__ import annotations

import re

from app.parsers.base import CompanionDeviceAssociation, SourceRef
from app.parsers.section_extractor import Section

ASSOCIATION_LINE_RE = re.compile(r"\bAssociation\{")
ASSOCIATIONS_HEADING = "Companion Device Associations:"

MID_RE = re.compile(r"\bmId=(\d+)")
PKG_RE = re.compile(r"\bmPackageName='([^']*)'")
MAC_RE = re.compile(r"\bmDeviceMacAddress=([0-9A-Fa-f:]+)")
# Anchored to the next field name, not a bare closing quote -- mDisplayName
# is free text that can itself contain an apostrophe (see module docstring).
DISPLAY_RE = re.compile(r"\bmDisplayName='(.*?)', mDeviceProfile=")
PROFILE_RE = re.compile(r"\bmDeviceProfile='([^']*)'")
SELF_MANAGED_RE = re.compile(r"\bmSelfManaged=(true|false)")
REVOKED_RE = re.compile(r"\bmRevoked=(true|false)")
PENDING_RE = re.compile(r"\bmPending=(true|false)")
TRUSTED_RE = re.compile(r"\bmTrusted=(true|false)")
TIME_APPROVED_RE = re.compile(r"\bmTimeApprovedMs=([^,]*),")
LAST_CONNECTED_RE = re.compile(r"\bmLastTimeConnectedMs=([^,]*),")

# "Connected Bluetooth Devices:" list under "Companion Device Present:" --
# cross-referenced against each association's mac address to set
# currently_connected. Only Bluetooth-transport presence is captured here;
# "Nearby BLE Devices"/"Self-Reported Devices" use a different, less
# reliably-shaped line format and are near-always "<empty>" in practice.
CONNECTED_BT_DEVICE_RE = re.compile(r"^\s*id=\d+, addr=(?P<mac>[0-9A-Fa-f:]+), pkg=")


def _bool_or_none(m: re.Match | None) -> bool | None:
    return None if m is None else m.group(1) == "true"


def _str_or_none(regex: re.Pattern, raw: str) -> str | None:
    m = regex.search(raw)
    return m.group(1) if m else None


def parse_companion_device_associations(section: Section) -> list[CompanionDeviceAssociation]:
    connected_macs: set[str] = set()
    for raw in section.lines:
        cm = CONNECTED_BT_DEVICE_RE.match(raw)
        if cm:
            connected_macs.add(cm.group("mac").upper())

    out: list[CompanionDeviceAssociation] = []
    in_associations_block = False
    for i, raw in enumerate(section.lines):
        if raw.strip() == ASSOCIATIONS_HEADING:
            in_associations_block = True
            continue
        if not in_associations_block:
            continue
        if raw and not raw[0].isspace():
            # An unindented line is the next top-level heading (e.g. "Last
            # Removed Association:", "Companion Device Present:") -- the
            # currently-active associations list has ended.
            in_associations_block = False
            continue
        if not ASSOCIATION_LINE_RE.search(raw):
            continue
        id_m = MID_RE.search(raw)
        if not id_m:
            continue

        abs_line = section.line_start + i
        mac_m = MAC_RE.search(raw)
        mac = mac_m.group(1).lower() if mac_m else None

        out.append(CompanionDeviceAssociation(
            association_id=int(id_m.group(1)),
            mac_address=mac,
            display_name=_str_or_none(DISPLAY_RE, raw),
            package_name=_str_or_none(PKG_RE, raw),
            device_profile=_str_or_none(PROFILE_RE, raw),
            self_managed=_bool_or_none(SELF_MANAGED_RE.search(raw)),
            revoked=_bool_or_none(REVOKED_RE.search(raw)),
            pending=_bool_or_none(PENDING_RE.search(raw)),
            trusted=_bool_or_none(TRUSTED_RE.search(raw)),
            time_approved=_str_or_none(TIME_APPROVED_RE, raw),
            last_time_connected=_str_or_none(LAST_CONNECTED_RE, raw),
            currently_connected=(mac.upper() in connected_macs) if mac else None,
            source_ref=SourceRef("companiondevice", abs_line, abs_line),
        ))

    return out
