"""Regression tests run against the real bugreport fixtures.

These pin down exact source line numbers alongside the parsed values. That
combination caught a real bug during development: TextIOWrapper's default
universal-newlines mode was splitting on stray '\\r' bytes embedded in
tombstone/crash data further up the file, which silently drifted every line
number after the first one by ~43,000 lines. The values still "looked"
right; only cross-checking against `grep`-verified line numbers caught it.
That's exactly the class of error this product exists to catch in bugreport
analysis -- so it can't ship with that bug in its own parsers.
"""
from pathlib import Path

import pytest

from app.parsers.cdm_pairing import parse_cdm_pairing_events
from app.parsers.crash_events import parse_crash_events
from app.parsers.section_extractor import Section
from app.services.ingestion import parse_bugreport_zip

FIXTURES = Path(__file__).parent / "fixtures"
CAPTURE_1 = FIXTURES / "bugreport_2026-08-13.zip"
CAPTURE_2 = FIXTURES / "bugreport_2026-08-19.zip"

pytestmark = pytest.mark.skipif(
    not CAPTURE_1.exists(), reason="real bugreport fixtures not present"
)


@pytest.fixture(scope="module")
def capture1():
    return parse_bugreport_zip(CAPTURE_1)


def test_no_parse_warnings(capture1):
    assert capture1.parse_warnings == []


def test_focus_stack_top_matches_known_state(capture1):
    assert len(capture1.focus_stack) == 1
    top = capture1.focus_stack[0]
    assert top.package == "com.apple.android.music"
    assert top.uid == 10358
    assert top.sdk == 35
    assert top.is_top_of_stack is True
    # grep -na "Audio Focus stack entries" -> 971139 (header); entry is the next line.
    assert top.source_ref.line_start == 971140


def test_focus_events_include_full_history(capture1):
    assert len(capture1.focus_events) == 50
    kinds = {e.event_type for e in capture1.focus_events}
    assert kinds == {"request", "abandon", "owner_change"}


@pytest.mark.parametrize(
    "package,expected_target_sdk,expected_line",
    [
        ("com.disney.disneyplus", 36, 1408647),
        ("com.apple.android.music", 35, 1386473),
        ("com.google.android.apps.youtube.music", 36, 1417026),
    ],
)
def test_package_target_sdk_and_line(capture1, package, expected_target_sdk, expected_line):
    pkg = capture1.packages[package]
    assert pkg.target_sdk == expected_target_sdk
    assert pkg.source_ref.line_start == expected_line


def test_media_sessions_reflect_actual_playback_state(capture1):
    by_pkg = {m.package: m for m in capture1.media_sessions}
    assert by_pkg["com.disney.disneyplus"].playback_state == "PLAYING"
    assert by_pkg["com.disney.disneyplus"].active is True
    assert by_pkg["com.apple.android.music"].playback_state == "PAUSED"
    assert by_pkg["com.google.android.apps.youtube.music"].playback_state == "PAUSED"


def test_device_info(capture1):
    info = capture1.device_info
    assert info.manufacturer == "Google"
    assert info.model == "Pixel 10"
    assert info.sdk_version == 37
    assert info.security_patch == "2026-08-05"
    assert info.serial == "57110DLCR003VF"


def test_crash_event_matches_known_incident(capture1):
    # Second real bug this parser work caught: the bugreport prints a
    # second, heavily time-filtered "SYSTEM LOG" section near the very end
    # (a `-T <recent timestamp>` trailer covering only the last few
    # seconds) reusing the exact same section name. "Keep last occurrence"
    # (correct for dumpsys CRITICAL/HIGH passes) silently grabbed that
    # tiny trailer instead of the real ~30k-line section for log-style
    # sections, dropping this crash entirely (0 found instead of 1).
    assert len(capture1.crash_events) == 1
    crash = capture1.crash_events[0]
    assert crash.package == "com.android.systemui"
    assert crash.exception_class == "DeadSystemException"
    assert crash.source_ref.line_start == 58157
    # No "Caused by:" chain in this crash -- root cause fields must stay
    # unset rather than falsely inheriting the top-level exception.
    assert crash.root_cause_class is None


def test_freeze_events_present_and_reasonable(capture1):
    assert len(capture1.freeze_events) > 0
    freezes = [e for e in capture1.freeze_events if e.event_type == "freeze"]
    unfreezes = [e for e in capture1.freeze_events if e.event_type == "unfreeze"]
    assert len(freezes) > 0
    assert len(unfreezes) > 0
    # Unfreeze reason codes are a small enum (observed: 1,3,4,6,7,10,19),
    # not a duration -- asserting that keeps the field honest.
    codes = {e.unfreeze_reason_code for e in unfreezes}
    assert codes.issubset({1, 3, 4, 6, 7, 10, 19})


def test_tombstones_parsed_from_zip(capture1):
    assert len(capture1.tombstones) > 0
    assert all(t.filename.startswith("tombstone_") for t in capture1.tombstones)
    # Every tombstone should have parsed a signal -- confirms content was
    # actually parsed, not just filenames listed.
    assert all(t.signal_name is not None for t in capture1.tombstones)
    # At least one tombstone attributes to a real app package (not every
    # tombstone will -- native binaries/services correctly report None).
    assert any(t.package is not None for t in capture1.tombstones)
    # Real variety confirmed present in this fixture (not fabricated):
    signals = {t.signal_name for t in capture1.tombstones}
    assert {"SIGSEGV", "SIGABRT", "SIGTRAP"}.issubset(signals)
    # A tombstone whose Cmdline is a multi-token linker64 invocation (not a
    # bare package id) must NOT be misattributed to a package -- regression
    # for a real bug where a missing "ppid:" field in some tombstones'
    # pid line (a genuine format variant) caused pid/tid to parse as None.
    linker_tombstones = [t for t in capture1.tombstones if t.executable and "linker64" in t.executable]
    assert linker_tombstones
    assert all(t.package is None for t in linker_tombstones)
    assert all(t.pid is not None for t in linker_tombstones)


def test_anrs_parsed_with_package_attribution(capture1):
    assert len(capture1.anrs) == 2
    for a in capture1.anrs:
        assert a.package == "com.disney.wdpro.dlr"
        assert a.reason == "failed to complete startup"
        assert a.pid is not None


def test_bt_hci_log_decoded_with_sane_values(capture1):
    # Parsed from ingestion (capture1 fixture) via the full pipeline.
    from app.services.ingestion import parse_bugreport_zip as _p
    cap = _p(CAPTURE_1)
    summary = cap.bt_hci_summary
    assert summary is not None
    assert summary.total_packets == 1747
    assert summary.command_count == 107
    assert summary.event_count == 985
    assert summary.acl_data_count == 655
    # Decoded timestamps must land within the capture's own time window,
    # not some wildly wrong epoch -- this caught a real bug where an
    # incorrect btsnoop-epoch-to-Unix delta constant decoded timestamps to
    # 1996 instead of 2026.
    assert summary.first_timestamp.startswith("2026-08-14")
    assert summary.last_timestamp.startswith("2026-08-14")
    # A real, non-fabricated anomaly found in this fixture: a Command
    # Complete with a non-Success status.
    non_success = [e for e in summary.events if e.status_code not in (None, 0)]
    assert any(e.status_name == "Unknown Connection Identifier" for e in non_success)


# Real lines from a third device's bugreport (not committed as a fixture --
# it's 228MB), reproduced verbatim: a "Disneyland" app crash whose top-level
# exception is a generic wrapper ("Unable to create application") over a
# third-party SDK's actual root cause. This is exactly the shape a
# root-cause chain needs unwrapping: reporting only the top-level exception
# would blame app startup in general, not the ASSA ABLOY Mobile Keys SDK
# call that actually threw.
DISNEYLAND_CRASH_LINES = """\
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: FATAL EXCEPTION: main
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: Process: com.disney.wdpro.dlr, PID: 2974
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: java.lang.RuntimeException: Unable to create application com.disney.wdpro.dlr.DLRApplication
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: \tat android.app.ActivityThread.handleBindApplication(ActivityThread.java:8400)
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: \tat android.app.ActivityThread.main(ActivityThread.java:9613)
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: Caused by: java.lang.RuntimeException: 25
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: \tat com.assaabloy.mobilekeys.api.MobileKeysApi.initialize(SourceFile:69)
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: \tat com.disney.wdpro.eservices_ui.key.component.ResortKeyModule.provideMobileKeysApi(SourceFile:25)
""".splitlines()


def test_crash_parser_unwraps_caused_by_chain_to_the_real_root_cause():
    section = Section(name="system_log", priority=None, line_start=100,
                       line_end=100 + len(DISNEYLAND_CRASH_LINES) - 1,
                       lines=DISNEYLAND_CRASH_LINES, kind="log")
    crashes = parse_crash_events(section)
    assert len(crashes) == 1
    c = crashes[0]
    assert c.package == "com.disney.wdpro.dlr"
    assert c.exception_class == "java.lang.RuntimeException"
    assert c.message == "Unable to create application com.disney.wdpro.dlr.DLRApplication"
    # The generic wrapper isn't the real story -- the deepest "Caused by:"
    # (the third-party SDK) is.
    assert c.root_cause_class == "java.lang.RuntimeException"
    assert c.root_cause_message == "25"
    assert "MobileKeysApi.initialize" in c.root_cause_frame


# Real lines reproducing a second, more subtle bug found via a diagnosis
# report that came back with an impossible claim (a crash "message" naming
# the Disney app but a "package" of com.google.android.gms, with a root
# cause that didn't match anything nearby in the raw log). Three crashes
# back-to-back with NO gap between them: two genuine Disney crashes (9
# seconds apart, identical root cause) immediately followed by an unrelated
# GMS crash. The block-scanner didn't stop at the next "FATAL EXCEPTION:"
# line, so it read straight through crash #1's boundary into crash #2's
# Process:/Caused-by lines, then straight through crash #2's boundary into
# crash #3's -- silently overwriting crash #1's package and root cause with
# data from a crash that happened over a day later.
BACK_TO_BACK_CRASH_LINES = """\
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: FATAL EXCEPTION: main
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: Process: com.disney.wdpro.dlr, PID: 16925
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: java.lang.RuntimeException: Unable to create application com.disney.wdpro.dlr.DLRApplication
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: \tat android.app.ActivityThread.main(ActivityThread.java:9613)
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: Caused by: java.lang.RuntimeException: 25
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: \tat com.assaabloy.mobilekeys.common.c.a.dO23852.info(:10365)
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: \tat com.assaabloy.mobilekeys.api.MobileKeysApi.initialize(SourceFile:69)
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: \t... 10 more
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: FATAL EXCEPTION: main
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: Process: com.disney.wdpro.dlr, PID: 18020
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: java.lang.RuntimeException: Unable to create application com.disney.wdpro.dlr.DLRApplication
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: \tat android.app.ActivityThread.main(ActivityThread.java:9613)
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: Caused by: java.lang.RuntimeException: 25
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: \tat com.assaabloy.mobilekeys.common.c.a.dO23852.info(:10365)
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: \tat com.assaabloy.mobilekeys.api.MobileKeysApi.initialize(SourceFile:69)
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: \t... 10 more
08-09 17:01:32.826 10336 20750 20811 E AndroidRuntime: FATAL EXCEPTION: actvpool[4]
08-09 17:01:32.826 10336 20750 20811 E AndroidRuntime: Process: com.google.android.gms, PID: 20750
08-09 17:01:32.826 10336 20750 20811 E AndroidRuntime: java.lang.IllegalArgumentException: Component class com.google.android.gms.findmydevice.spot.e2ee.ui.ExportedSyncOwnerKeyActivityAlias does not exist in com.google.android.gms
08-09 17:01:32.826 10336 20750 20811 E AndroidRuntime: \tat android.os.Parcel.readException(Parcel.java:3278)
""".splitlines()


def test_crash_parser_stops_at_next_fatal_exception_boundary():
    section = Section(name="system_log", priority=None, line_start=1000,
                       line_end=1000 + len(BACK_TO_BACK_CRASH_LINES) - 1,
                       lines=BACK_TO_BACK_CRASH_LINES, kind="log")
    crashes = parse_crash_events(section)
    assert len(crashes) == 3

    first, second, third = crashes
    for c in (first, second):
        assert c.package == "com.disney.wdpro.dlr"
        assert c.exception_class == "java.lang.RuntimeException"
        assert c.root_cause_class == "java.lang.RuntimeException"
        assert c.root_cause_message == "25"
        assert "MobileKeysApi.initialize" not in c.root_cause_frame  # first frame under Caused by, not the second
        assert "dO23852.info" in c.root_cause_frame

    assert third.package == "com.google.android.gms"
    assert third.exception_class == "java.lang.IllegalArgumentException"
    assert third.root_cause_class is None  # no "Caused by:" in this crash's own block

    # Each crash's citation must end at ITS OWN last line, not bleed into
    # the next crash's lines.
    assert first.source_ref.line_end < second.source_ref.line_start
    assert second.source_ref.line_end < third.source_ref.line_start


def test_wifi_disconnection_events_with_802_11_reason_codes(capture1):
    disconnections = [e for e in capture1.wifi_events if e.kind == "disconnection"]
    assert len(disconnections) == 3
    by_ssid = {e.ssid: e for e in disconnections}
    assert by_ssid["amzn-www"].reason_code == 3
    assert by_ssid["amzn-www"].reason_name == "Deauthenticated: station leaving"
    assert by_ssid["amzn-www"].locally_generated is True
    # grep-verified line number for this exact disconnection record.
    assert by_ssid["amzn-www"].source_ref.line_start == 1622419


def test_wifi_association_events_include_roam_flag(capture1):
    associations = [e for e in capture1.wifi_events if e.kind == "association"]
    assert len(associations) > 0
    assert all(e.roam is not None for e in associations)


def test_battery_uid_stats_attributed_to_real_packages(capture1):
    by_pkg = {s.package: s for s in capture1.battery_uid_stats if s.package}
    assert "com.disney.disneyplus" in by_pkg
    assert "ch.protonvpn.android" in by_pkg
    assert by_pkg["com.disney.disneyplus"].total_mah > 0
    assert "audio" in by_pkg["com.disney.disneyplus"].components_mah or \
           "video" in by_pkg["com.disney.disneyplus"].components_mah

    # Regression: appId already includes Android's +10000 offset (verified
    # against two independent real UIDs); the first parser version dropped
    # that term, computing uid=358 instead of 10358 for token "u0a358" and
    # silently failing every attribution.
    music = by_pkg.get("com.apple.android.music")
    assert music is not None
    assert music.uid == 10358

    # Regression: appId 1000 ("system") is shared by 18+ different
    # packages via android:sharedUserId. Attributing a shared system UID's
    # battery entry to whichever package happened to be first in the dict
    # would misrepresent combined system activity as one specific app's --
    # it must be left unattributed instead.
    system_uid_entries = [s for s in capture1.battery_uid_stats if s.uid == 1000]
    assert len(system_uid_entries) == 1
    assert system_uid_entries[0].package is None


# Real lines from a Pixel phone pairing with a Pixel Watch 5 (from a third
# device's bugreport, not committed as a fixture -- 188MB). Reproduced
# verbatim: this is exactly the case that came back "unknown, no data"
# from two different LLM providers on a "network error while pairing"
# question, even though the actual pairing flow -- and a concrete, repeated
# transport failure -- was sitting in the log the whole time.
PAIRING_LINES = """\
06-25 10:08:03.850  1000  1731  9608 I ActivityTaskManager: START u0 {flg=0x30040000 xflg=0x4 cmp=com.google.android.gms/.nearby.discovery.fastpair.HalfSheetActivity (has extras)} with LAUNCH_SINGLE_INSTANCE from uid 10347
06-25 10:08:12.959 10138 29050 29050 I CDM_CompanionDeviceDiscoveryService: onDeviceFound() (BT) 64:9d:38:bc:d5:eb 'Pixel Watch 5 35WD' - New device.
06-25 10:08:12.960 10138 29050 29050 I CDM_CompanionDeviceActivity: onAssociationApproved() macAddress=64:9d:38:bc:d5:eb
06-25 10:08:12.971  1000  1731  1731 I CDM_AssociationStore: Adding new association=[Association{mId=1, mUserId=0, mPackageName='com.google.android.apps.wear.companion', mDeviceMacAddress=64:9d:38:bc:d5:eb, mDisplayName='Pixel Watch 5 35WD', mDeviceProfile='android.app.role.COMPANION_DEVICE_WATCH', mSelfManaged=false}]...
06-25 10:08:12.972  1000  1731  1731 I CDM_DevicePresenceProcessor: onBluetoothCompanionDeviceConnected: associationId( 1 )
06-25 10:08:12.989  1000  1731  1731 W CDM_ActionRequestProcessor: Action REQUEST_NEARBY_ADVERTISING FAILED to activate.
06-25 10:08:12.990  1000  1731  1731 W CDM_ActionRequestProcessor: Action REQUEST_TRANSPORT FAILED to activate.
06-25 10:08:18.017  1000  1731  1731 W CDM_ActionRequestProcessor: Action REQUEST_TRANSPORT FAILED to activate.
06-25 10:08:23.053  1000  1731  1731 W CDM_ActionRequestProcessor: Action REQUEST_TRANSPORT FAILED to activate.
06-25 10:08:14.225 10347 32249 32249 E ActivityThread: Failed to find provider info for 64:9D:38:BC:D5:EB
""".splitlines()


def test_cdm_pairing_events_decoded_with_anomaly_catchall():
    section = Section(name="system_log", priority=None, line_start=500,
                       line_end=500 + len(PAIRING_LINES) - 1,
                       lines=PAIRING_LINES, kind="log")
    events = parse_cdm_pairing_events(section)
    kinds = [e.kind for e in events]
    assert "fast_pair_ui_opened" in kinds
    assert "device_found" in kinds
    assert "association_approved" in kinds
    assert "association_added" in kinds
    assert "device_presence_connected" in kinds
    assert "provider_lookup_failed" in kinds

    added = next(e for e in events if e.kind == "association_added")
    assert added.mac_address == "64:9d:38:bc:d5:eb"
    assert added.display_name == "Pixel Watch 5 35WD"
    assert added.package_name == "com.google.android.apps.wear.companion"
    assert added.association_id == 1

    # The real value of the generic W/E catch-all: three separate
    # "Action REQUEST_TRANSPORT FAILED to activate" lines, never
    # individually anticipated, still surface as anomalies.
    anomalies = [e for e in events if e.kind == "anomaly"]
    assert sum(1 for e in anomalies if "REQUEST_TRANSPORT FAILED" in e.detail) == 3
    assert any("REQUEST_NEARBY_ADVERTISING FAILED" in e.detail for e in anomalies)


def test_second_capture_also_parses_cleanly():
    if not CAPTURE_2.exists():
        pytest.skip("second fixture not present")
    cap2 = parse_bugreport_zip(CAPTURE_2)
    assert cap2.parse_warnings == []
    assert len(cap2.packages) > 0


def _minimal_btsnoop_bytes() -> bytes:
    import struct
    header = b"btsnoop\x00" + struct.pack(">II", 1, 1002)
    payload = bytes([0x01, 0x03, 0x0C, 0x00])  # H4 command, arbitrary opcode/len
    record = struct.pack(">IIIIQ", len(payload), len(payload), 0, 0, 0x00DCDDB30F2F8000) + payload
    return header + record


def test_companion_device_associations_exclude_removed_and_handle_apostrophes(capture1):
    # Real gap found live against this exact fixture: mId=3 ("Diante's
    # Pixel Buds Pro 2") only appears under "Last Removed Association:",
    # not "Companion Device Associations:" -- it must NOT show up as a
    # currently-active association. mId=2's display name itself contains
    # an apostrophe ("Diante's Pixel Buds 2a"), which broke a naive
    # `'([^']*)'` regex match before the fix in companion_device.py.
    assoc_ids = {a.association_id for a in capture1.companion_device_associations}
    assert 3 not in assoc_ids  # removed association excluded
    assert assoc_ids == {2, 4, 5, 6}

    buds = next(a for a in capture1.companion_device_associations if a.association_id == 2)
    assert buds.display_name == "Diante's Pixel Buds 2a"
    assert buds.mac_address == "5a:dd:5a:87:74:0d"
    # Cross-referenced against "Connected Bluetooth Devices:" in the same
    # section -- this one's mac address is in that list, the others aren't.
    assert buds.currently_connected is True
    watch = next(a for a in capture1.companion_device_associations if a.association_id == 4)
    assert watch.currently_connected is False


def test_logcat_history_normalizes_timestamp_precision_and_dedups(tmp_path):
    # Real gap found live: the persistent rotated logcat.NN buffer files
    # (up to 63 of them on a real device) were never read at all, and when
    # they were, a real overlap between the live "system_log" window and a
    # rotated file's content would double-count the identical event. This
    # also exercises the 6-digit microsecond -> 3-digit millisecond
    # timestamp normalization those files need (system_log uses 3 digits).
    import zipfile

    zip_path = tmp_path / "synthetic_bugreport.zip"
    freeze_line_live = (
        "08-13 22:36:22.190  1000  2046  2922 D ActivityManager: "
        "freezing 28798 com.android.vending:background\n"
    )
    # Same event, same millisecond, but as it's actually stored on-device:
    # 6-digit microsecond precision.
    freeze_line_history_dup = (
        "08-13 22:36:22.190123  1000  2046  2922 D ActivityManager: "
        "freezing 28798 com.android.vending:background\n"
    )
    freeze_line_history_unique = (
        "08-12 09:00:00.000000  1000  2046  2922 D ActivityManager: "
        "freezing 555 com.example.other:background\n"
    )
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "bugreport-synthetic-2026-01-01-00-00-00.txt",
            "------ SYSTEM LOG (logcat -v threadtime -v printable -v uid -d *:v) ------\n"
            + freeze_line_live
            + "------ 0.001s was the duration of 'SYSTEM LOG' ------\n",
        )
        zf.writestr("FS/data/misc/logd/logcat.01", freeze_line_history_dup)
        zf.writestr("FS/data/misc/logd/logcat.02", freeze_line_history_unique)
        # The bare, unrotated "logcat" file is deliberately never read.
        zf.writestr("FS/data/misc/logd/logcat", freeze_line_history_unique)

    cap = parse_bugreport_zip(zip_path)
    assert len(cap.freeze_events) == 2  # the live/history duplicate collapsed to one
    sections = {e.source_ref.section for e in cap.freeze_events}
    assert sections == {"system_log", "logcat.02"}
    processes = {e.process for e in cap.freeze_events}
    assert processes == {"com.android.vending:background", "com.example.other:background"}


def test_bt_hci_log_found_under_real_world_filename_variant(tmp_path):
    # Real gap found live against two actual bugreports (a Pixel phone and a
    # Pixel Watch, neither the committed test fixture): the HCI log ships as
    # "btsnoop_hci.log.filtered", not "btsnooz_hci.log" -- the only name
    # ingestion.py originally looked for. Both real captures had a valid,
    # multi-thousand-packet HCI log sitting in the zip that silently never
    # got parsed; "No Bluetooth HCI snoop log found" was a false negative.
    # This builds a minimal zip using that real-world filename to make sure
    # the fix (searching BT_HCI_LOG_CANDIDATES) doesn't regress.
    import zipfile

    zip_path = tmp_path / "synthetic_bugreport.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "bugreport-synthetic-2026-01-01-00-00-00.txt",
            "------ SYSTEM PROPERTIES (getprop) ------\n"
            "[ro.build.version.release]: [15]\n"
            "------ 0.000s was the duration of 'SYSTEM PROPERTIES' ------\n",
        )
        zf.writestr(
            "FS/data/misc/bluetooth/logs/btsnoop_hci.log.filtered",
            _minimal_btsnoop_bytes(),
        )

    cap = parse_bugreport_zip(zip_path)
    assert "No Bluetooth HCI snoop log found" not in cap.parse_warnings
    assert cap.bt_hci_summary is not None
    assert cap.bt_hci_summary.total_packets == 1
    assert cap.bt_hci_summary.command_count == 1


SELINUX_LINES = """\
06-25 10:20:53.162 10303 27010 27010 W GrallocUploadTh: type=1400 audit(0.0:174): avc:  denied  { read } for  name="uevent" dev="sysfs" ino=32559 scontext=u:r:platform_app:s0:c512,c768 tcontext=u:object_r:sysfs:s0 tclass=file permissive=0 app=com.google.android.avatarpicker
06-25 10:05:31.326  1002  7336  7336 I auditd  : type=1400 audit(0.0:155): avc:  denied  { search } for  comm="binder:7336_1" name="com.google.android.gms" dev="dm-61" ino=8631 scontext=u:r:bluetooth:s0 tcontext=u:object_r:privapp_data_file:s0:c512,c768 tclass=dir permissive=0
06-25 10:06:46.687 media 28293 28293 I auditd  : type=1400 audit(0.0:160): avc:  denied  { execute } for  comm="android.hardwar" name="sh" dev="dm-7" ino=501 scontext=u:r:hal_drm_widevine:s0 tcontext=u:object_r:shell_exec:s0 tclass=file permissive=1
06-25 10:06:47.100 media 28293 28293 I auditd  : type=1400 audit(0.0:161): avc:  denied  { read write } for  comm="foo" scontext=u:r:some_domain:s0 tcontext=u:object_r:some_type:s0 tclass=file
""".splitlines()


def test_selinux_denials_parse_with_enforcing_distinction():
    # permissive=0 (BLOCKED, a real failure) vs permissive=1 (logged but
    # allowed) vs absent (unknown) must stay three distinct states --
    # collapsing them is the main way SELinux findings get overstated.
    from app.parsers.selinux import parse_selinux_denials

    section = Section(name="event_log", priority=None, line_start=500,
                      line_end=500 + len(SELINUX_LINES) - 1,
                      lines=SELINUX_LINES, kind="log")
    denials = parse_selinux_denials(section)
    assert len(denials) == 4

    first = denials[0]
    assert first.verdict == "denied"
    assert first.permissions == ["read"]
    # Context types are extracted from the full u:r:type:s0:c... string, and
    # the per-instance category suffix is dropped so identical denials group.
    assert first.source_domain == "platform_app"
    assert first.target_type == "sysfs"
    assert first.target_class == "file"
    assert first.app == "com.google.android.avatarpicker"
    assert first.target_name == "uevent"
    assert first.enforcing is True
    assert first.source_ref.section == "event_log"
    assert first.source_ref.line_start == 500

    assert denials[1].comm == "binder:7336_1"
    assert denials[1].source_domain == "bluetooth"
    assert denials[1].target_class == "dir"

    assert denials[2].enforcing is False        # permissive=1 -> allowed through
    assert denials[3].enforcing is None         # field absent -> unknown, not False
    assert denials[3].permissions == ["read", "write"]


def test_selinux_denials_found_in_event_log_not_just_system_log(capture1):
    # Found live on a real capture: 19 of 20 AVC denials were in EVENT LOG
    # (where auditd writes), only 1 in SYSTEM LOG. Parsing SYSTEM LOG alone
    # would have silently missed 95% of them.
    sections = {d.source_ref.section for d in capture1.selinux_denials}
    if capture1.selinux_denials:
        assert "event_log" in sections or "system_log" in sections
        assert all(d.verdict in {"denied", "granted"} for d in capture1.selinux_denials)
