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


def test_native_crash_files_from_zip_listing(capture1):
    assert len(capture1.native_crash_files) > 0
    assert all(f.filename.startswith("tombstone_") for f in capture1.native_crash_files)


def test_second_capture_also_parses_cleanly():
    if not CAPTURE_2.exists():
        pytest.skip("second fixture not present")
    cap2 = parse_bugreport_zip(CAPTURE_2)
    assert cap2.parse_warnings == []
    assert len(cap2.packages) > 0
