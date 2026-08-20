"""Parser for Companion Device Manager (CDM) / Fast Pair device-pairing
events in the system log -- the actual Bluetooth discovery/association/
secure-channel handshake flow for Wear OS watch pairing and Fast Pair
headphone pairing. Verified against a real pairing session (a Pixel phone
pairing with a Pixel Watch 5):

    I CDM_CompanionDeviceDiscoveryService: onDeviceFound() (BT) 64:9d:38:bc:d5:eb 'Pixel Watch 5 35WD' - New device.
    D CDM_CompanionDeviceManagerService: associate() request=AssociationRequest { singleDevice = true, deviceFilters = [BluetoothDeviceFilter{mNamePattern=null, mAddress='64:9D:38:BC:D5:EB', ...
    I CDM_CompanionDeviceActivity: onAssociationApproved() macAddress=64:9d:38:bc:d5:eb
    I CDM_AssociationStore: Adding new association=[Association{mId=1, mUserId=0, mPackageName='com.google.android.apps.wear.companion', mDeviceMacAddress=64:9d:38:bc:d5:eb, mDisplayName='Pixel Watch 5 35WD', mDeviceProfile='android.app.role.COMPANION_DEVICE_WATCH', ...
    I CDM_DevicePresenceProcessor: onBluetoothCompanionDeviceConnected: associationId( 1 )
    I CDM_BluetoothDeviceProcessor: Device connected: 64:9D:38:BC:D5:EB on transport 1
    D CDM_SecureChannel: Ukey2 Handshake completed successfully
    D CDM_CompanionTransport: Secure connection established.
    W CDM_SecureChannel: Detected a Ukey2 handshake role collision. Negotiating a role.
    I ActivityTaskManager: START ... cmp=com.google.android.gms/.nearby.discovery.fastpair.HalfSheetActivity ...

Well-known milestones are decoded by name; any other W/E-level line from a
CDM_* tag is still captured as kind="anomaly" -- real failure message text
can't be fully enumerated in advance, but the log level reliably flags
something worth a human's attention.
"""
from __future__ import annotations

import re

from app.parsers.base import CdmPairingEvent, SourceRef
from app.parsers.section_extractor import Section

LOG_LINE_RE = re.compile(
    r"^(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\s+\d+ "
    r"(?P<level>[VDIWE]) (?P<tag>\S+): (?P<rest>.*)$"
)

FAST_PAIR_ACTIVITY_RE = re.compile(
    r"cmp=com\.google\.android\.gms/\.nearby\.discovery\.fastpair\.\S+"
)

DEVICE_FOUND_RE = re.compile(
    r"onDeviceFound\(\) \(BT\) (?P<mac>[0-9a-fA-F:]{17}) '(?P<name>[^']*)'"
)
ASSOCIATION_REQUESTED_RE = re.compile(r"mAddress='(?P<mac>[0-9a-fA-F:]{17})'")
ASSOCIATION_APPROVED_RE = re.compile(r"onAssociationApproved\(\) macAddress=(?P<mac>[0-9a-fA-F:]{17})")
ASSOCIATION_STORE_RE = re.compile(
    r"(?P<verb>Adding new|Updating) association=\[Association\{mId=(?P<id>\d+), "
    r"mUserId=\d+, mPackageName='(?P<pkg>[^']*)', mDeviceMacAddress=(?P<mac>[0-9a-fA-F:null]+), "
    r"mDisplayName='(?P<name>[^']*)'"
)
PRESENCE_CONNECTED_RE = re.compile(r"onBluetoothCompanionDeviceConnected: associationId\(\s*(?P<id>\d+)\s*\)")
BT_CONNECTED_RE = re.compile(r"Device connected: (?P<mac>[0-9a-fA-F:]{17}) on transport")
SECURE_CHANNEL_OK_RE = re.compile(r"(Ukey2 Handshake completed successfully|Secure connection established)")
PROVIDER_LOOKUP_FAILED_RE = re.compile(r"Failed to find provider info for (?P<mac>[0-9a-fA-F:]{17})")

CDM_TAG_RE = re.compile(r"^CDM_")


def parse_cdm_pairing_events(section: Section) -> list[CdmPairingEvent]:
    out: list[CdmPairingEvent] = []

    for i, raw in enumerate(section.lines):
        m = LOG_LINE_RE.match(raw)
        if not m:
            continue
        ts, level, tag, rest = m.group("ts"), m.group("level"), m.group("tag"), m.group("rest")
        abs_line = section.line_start + i
        ref = SourceRef(section.name, abs_line, abs_line)
        is_cdm = bool(CDM_TAG_RE.match(tag))

        if not is_cdm:
            if FAST_PAIR_ACTIVITY_RE.search(rest):
                out.append(CdmPairingEvent(
                    timestamp=ts, level=level, tag=tag, kind="fast_pair_ui_opened",
                    mac_address=None, display_name=None, package_name=None,
                    association_id=None, detail=rest, source_ref=ref,
                ))
                continue
            pf = PROVIDER_LOOKUP_FAILED_RE.search(rest)
            if pf:
                out.append(CdmPairingEvent(
                    timestamp=ts, level=level, tag=tag, kind="provider_lookup_failed",
                    mac_address=pf.group("mac").lower(), display_name=None, package_name=None,
                    association_id=None, detail=rest, source_ref=ref,
                ))
            continue

        dm = DEVICE_FOUND_RE.search(rest)
        if dm:
            out.append(CdmPairingEvent(
                timestamp=ts, level=level, tag=tag, kind="device_found",
                mac_address=dm.group("mac").lower(), display_name=dm.group("name"),
                package_name=None, association_id=None, detail=rest, source_ref=ref,
            ))
            continue

        am = ASSOCIATION_APPROVED_RE.search(rest)
        if am:
            out.append(CdmPairingEvent(
                timestamp=ts, level=level, tag=tag, kind="association_approved",
                mac_address=am.group("mac").lower(), display_name=None,
                package_name=None, association_id=None, detail=rest, source_ref=ref,
            ))
            continue

        sm = ASSOCIATION_STORE_RE.search(rest)
        if sm:
            mac = sm.group("mac").lower()
            out.append(CdmPairingEvent(
                timestamp=ts, level=level, tag=tag,
                kind="association_added" if sm.group("verb") == "Adding new" else "association_updated",
                mac_address=None if mac == "null" else mac, display_name=sm.group("name"),
                package_name=sm.group("pkg"), association_id=int(sm.group("id")),
                detail=rest, source_ref=ref,
            ))
            continue

        pm = PRESENCE_CONNECTED_RE.search(rest)
        if pm:
            out.append(CdmPairingEvent(
                timestamp=ts, level=level, tag=tag, kind="device_presence_connected",
                mac_address=None, display_name=None, package_name=None,
                association_id=int(pm.group("id")), detail=rest, source_ref=ref,
            ))
            continue

        bm = BT_CONNECTED_RE.search(rest)
        if bm:
            out.append(CdmPairingEvent(
                timestamp=ts, level=level, tag=tag, kind="bt_device_connected",
                mac_address=bm.group("mac").lower(), display_name=None,
                package_name=None, association_id=None, detail=rest, source_ref=ref,
            ))
            continue

        if SECURE_CHANNEL_OK_RE.search(rest):
            out.append(CdmPairingEvent(
                timestamp=ts, level=level, tag=tag, kind="secure_channel_established",
                mac_address=None, display_name=None, package_name=None,
                association_id=None, detail=rest, source_ref=ref,
            ))
            continue

        if ASSOCIATION_REQUESTED_RE.search(rest) and "associate()" in rest:
            am2 = ASSOCIATION_REQUESTED_RE.search(rest)
            out.append(CdmPairingEvent(
                timestamp=ts, level=level, tag=tag, kind="association_requested",
                mac_address=am2.group("mac").lower(), display_name=None,
                package_name=None, association_id=None, detail=rest, source_ref=ref,
            ))
            continue

        if level in ("W", "E"):
            out.append(CdmPairingEvent(
                timestamp=ts, level=level, tag=tag, kind="anomaly",
                mac_address=None, display_name=None, package_name=None,
                association_id=None, detail=rest, source_ref=ref,
            ))

    return out
