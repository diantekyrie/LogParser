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


def test_second_capture_also_parses_cleanly():
    if not CAPTURE_2.exists():
        pytest.skip("second fixture not present")
    cap2 = parse_bugreport_zip(CAPTURE_2)
    assert cap2.parse_warnings == []
    assert len(cap2.packages) > 0
