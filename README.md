# groundtruth

Device log diagnosis SaaS — MVP. Ingests Android bugreports and returns a
root-cause diagnosis built on **deterministic parsers as ground truth**,
with an LLM reasoning layer on top that narrates already-verified facts
instead of doing retrieval over raw text.

See the original build brief for the full product thesis and the specific
gaps in the incumbent (logcat.ai) this is meant to close.

## Architecture

```
backend/
  app/
    parsers/         deterministic parsers -- the primary technical moat
      section_extractor.py   streams the (100-250MB) flattened bugreport
                              txt out of its zip, slices out only the
                              sections we have parsers for. Handles both
                              bugreport delimiter styles: `DUMP OF SERVICE
                              ... / --------- was the duration of dumpsys`
                              (dumpsys output) and `------ NAME (...) ------
                              / ------ ... was the duration of 'NAME' ------`
                              (captured logcat buffers, getprop, iptables),
                              plus the undelimited plain-text preamble at
                              the top of the file.
      audio_focus.py         DUMP OF SERVICE audio -> MediaFocusControl
                              focus stack + full request/abandon/owner
                              event history
      package_info.py        DUMP OF SERVICE package -> per-package
                              versionCode/minSdk/targetSdk
      media_session.py       DUMP OF SERVICE media_session -> live
                              PlaybackState per app (state, position, active)
      foreground_service.py  DUMP OF SERVICE activity -> ServiceRecord /
                              infoAllowStartForeground (targetSdk at
                              bind/start time, calling package, proc state)
      freeze_events.py       SYSTEM LOG -> ActivityManager process
                              freeze/unfreeze events (cached-process
                              freezer state transitions)
      crash_events.py        SYSTEM LOG -> Java `FATAL EXCEPTION` crashes,
                              including unwrapping the `Caused by:` chain
                              to find the actual root cause under a generic
                              top-level wrapper exception
      device_info.py         plain-text preamble + SYSTEM PROPERTIES
                              (getprop) -> manufacturer/model/build/
                              security patch/kernel/serial/etc.
      tombstone.py            parses tombstone file CONTENT (not just the
                              filename) from FS/data/tombstones/ --
                              signal/code/fault addr, top backtrace frame,
                              and package attribution derived from Cmdline
                              (null, not guessed, for native binaries)
      anr.py                  parses ANR trace files from FS/data/anr/ --
                              the `Subject:` header line alone gives pid,
                              package, and failure reason
      bt_hci.py                parses the on-device Bluetooth HCI snoop log
                              (FS/data/misc/bluetooth/logs/btsnooz_hci.log)
                              -- real binary `btsnoop` framing (verified
                              byte-for-byte against the actual file, not
                              assumed from the misleading "btsnooz"
                              filename), decoding connection/disconnection/
                              command complete/status events with HCI
                              status-code names from the Bluetooth Core Spec
      wifi.py                 DUMP OF SERVICE wifi -> WifiController/
                              ClientModeImpl state machine log: Wi-Fi
                              disconnection events with IEEE 802.11 reason
                              codes, BSSID association/roam events
    services/
      ingestion.py       wires zip -> sections -> parsers -> ParsedCapture;
                          also reads and parses tombstone/ANR files and the
                          Bluetooth HCI log directly from the zip's own
                          file listing (separate files, not text inside the
                          flattened bugreport txt)
      persistence.py     ParsedCapture -> DB rows (facts, not raw blobs)
      correlation.py     multi-capture history queries for one device
      verification.py    independently verifies every app named in a
                          question before any narrative is built --
                          focus stack, media session, targetSdk, its own
                          crash events, freeze/unfreeze counts, its own
                          ANRs and native crashes (tombstones)
      reasoning.py        assembles verified facts + computed confidence
                          into a bundle, hands it to the selected LLM
                          provider to narrate. Crash-shaped questions
                          (crash/ANR/fatal/tombstone) get device-wide
                          crash/ANR/native-crash evidence even when no
                          app is named.
      summary.py          assembles one capture's dashboard payload:
                          device info, fact counts, top freeze/unfreeze
                          offenders, crash/ANR/tombstone tables, Bluetooth
                          HCI summary, a merged chronological timeline --
                          all reads of already-persisted rows
    llm/                LLMClient interface with four selectable
                         providers (see "LLM providers" below); every
                         implementation only narrates an already-verified
                         fact bundle, none of them see raw bugreport text
    api/                FastAPI routes: upload, list, capture summary,
                         llm provider list, diagnose
  tests/
    fixtures/           real bugreports (not committed -- see .gitignore)
    test_parsers_fixtures.py   parser-level regression tests, pinned to
                                exact source line numbers
    test_end_to_end.py         full pipeline: parse -> persist -> verify
                                -> correlate -> diagnose -> summary

frontend/               React + Vite dashboard: device info panel, stat
                         cards (crashes/freezes/packages/etc.), crash and
                         media-session tables with source citations, a
                         merged event timeline, and an Ask panel with a
                         per-question LLM provider dropdown
```

## Upload formats

The local dashboard accepts four upload types:

| Extension | Current support |
|---|---|
| `.zip` | Full Android bugreport ZIP ingestion, including flattened bugreport text plus ZIP-contained tombstones, ANRs, and Bluetooth HCI log files. |
| `.txt` | Direct flattened Android bugreport text ingestion. ZIP-only companion files are not available, so tombstones/ANRs/HCI files are reported as unavailable. |
| `.pcap`, `.pcapng` | Classic libpcap and pcapng container parsing: packet count, byte totals, time range, link type, truncated packet count, and malformed record count. Protocol-level packet decoding is not implemented yet. |
| `.btt` | Accepted as an Ellisys artifact. If the bytes are actually `btsnoop`/HCI, they are parsed by the existing Bluetooth HCI parser; otherwise the upload is kept as a capture with an explicit warning that native Ellisys `.btt` decoding needs a sample/spec or an Ellisys export to btsnoop/pcap. |

Uploads can also be grouped into a named bug folder/investigation so one
local investigation can contain multiple supporting files, such as a
bugreport ZIP, a raw text log, a packet capture, and an Ellisys artifact.
The dashboard file picker accepts multiple files at once and uploads each
as a separate capture under the same bug folder.

## Why parsers, not RAG

The section extractor streams the giant flattened bugreport text once and
only buffers the sections we have parsers for. Within those sections,
values are pulled by exact-format regex, not chunk/embedding retrieval --
so a plain-text section like the audio focus stack (which a retrieval-based
tool can silently miss on a long, low-natural-language-signal section) is
never "not found." Every fact carries a `SourceRef` (section + line
range), so every claim in a report can point back at exact lines.

Real parser bugs this discipline caught during development (each pinned as
a regression test against real fixture data, not synthetic data that's too
clean to expose them):

1. Python's default universal-newlines text mode splits on bare `\r` bytes
   embedded in tombstone/crash data elsewhere in the bugreport, which
   silently drifted every subsequent line number by ~43,000 lines while the
   *parsed values* still looked plausible.
2. A bugreport can print a second, heavily time-filtered "SYSTEM LOG"
   section near the very end (a `-T <recent timestamp>` trailer covering
   only the last few seconds), reusing the exact same section name as the
   real, complete one earlier in the file. "Keep last occurrence" (correct
   for a dumpsys CRITICAL/HIGH pass followed by the full dump) silently
   grabbed that tiny trailer instead for this log-style section, dropping
   real crash data entirely.
3. The crash parser's block-scanner, when unwrapping a `Caused by:` chain,
   didn't stop at the next `FATAL EXCEPTION:` header -- so two crashes
   back-to-back with no gap (a real, repeatable case: an app crashing twice
   within 10 seconds) caused the scanner to read straight through the
   boundary into a later, unrelated crash's data and silently overwrite the
   first crash's package and root cause with the wrong crash's fields.
4. Some tombstones omit `ppid:` from the pid/tid header line entirely (a
   real format variant, not malformed data) -- a regex that required it
   silently failed to extract pid/tid for those tombstones.
5. The Bluetooth HCI log's binary framing was initially assumed from the
   file's misleading name ("btsnooz", suggesting AOSP's compressed
   bugreport-inline variant) rather than verified. The first byte-offset
   guess produced identical, clearly-wrong values for both TX and RX
   packets; decoding was only trusted once independently verified against
   the real bytes: H4 type-byte distribution, decoded HCI event codes/
   statuses were all self-consistent with known Bluetooth Core Spec
   semantics, and decoded timestamps landed within minutes of the
   bugreport's own capture time (an earlier epoch-delta constant decoded
   them to 1996).

## Independent verification

`verification.py` extracts every app the question names (literal package
IDs, or exact-segment brand-word matches like "YouTube Music" ->
`com.google.android.apps.youtube.music`) and pulls each one's own parsed
state -- focus stack membership, MediaSession playback state, latest focus
event, targetSdk, its own crash events, freeze/unfreeze counts -- before any
diagnosis narrative is built. The user's framing of "app X caused app Y's
problem" is never taken as fact for either app.

Crash-shaped questions (containing crash/crashed/ANR/fatal/tombstone) also
get device-wide crash evidence attached regardless of whether an app was
named, so "was there a crash?" doesn't come back "unknown" just because the
question didn't name an app.

## Confidence

`reasoning.score_confidence()` labels a claim HIGH/MEDIUM/LOW/UNCONFIRMED
based on how many independent structured facts back it and how many
captures in the device's history were checked -- never from how assertively
something reads. Every fact bundle sent to the LLM carries this computed
label explicitly, including device-wide crash evidence; the system prompt
instructs the model to carry it forward verbatim, but the label itself is
always computed in code, never left for the model to infer or invent (a
real gap found via live A/B testing: GPT-4.1 assigned "HIGH confidence" to
device-wide crash evidence that had no confidence field at all when the
field was originally omitted and left to prompt instructions alone).

## Multi-capture correlation

Captures are associated with a `Device` (by a label you choose, e.g. a
serial number) rather than treated as disposable uploads. Any question
containing trigger words like "never", "across", "history", "week"
triggers `correlation.package_history_across_device()`, which checks a
claim (e.g. "has this app ever requested audio focus") against every
capture on file for the device and reports how many captures backed the
answer -- not just whichever file is in the current request.

## LLM providers

Selectable per-question via a dropdown in the frontend's Ask panel, or via
the `provider` field on `POST /captures/{id}/diagnose`:

| id | Model | Requires |
|---|---|---|
| `anthropic` | Claude (Sonnet by default) | `ANTHROPIC_API_KEY` |
| `openai` | GPT (gpt-4.1 by default, `OPENAI_MODEL` to override) | `OPENAI_API_KEY` |
| `openai-codex` | Codex-family (gpt-5.3-codex by default, `OPENAI_CODEX_MODEL` to override) | `OPENAI_API_KEY` |
| `stub` | No LLM -- deterministically echoes the fact bundle | nothing |

`GET /api/llm/providers` reports which are actually usable given the
current environment, so the dropdown never offers one that will just error.
Omitting `provider` falls back to auto-detection (Anthropic, then OpenAI,
then stub).

Codex-family models use OpenAI's `responses` endpoint, not
`chat.completions` -- they 404 on the latter ("Use the v1/responses endpoint
instead"), confirmed live against the real API rather than assumed.

If narration fails for any reason (bad/missing key, quota, wrong
model/endpoint), the request still returns `200` with the full verified
fact bundle intact and `report: null` / `llm_error: "<the actual error>"` --
narration is a convenience layer on top of the independently-verified
facts, never a single point of failure for them.

## Running it

Backend:

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Put API keys in `backend/.env` (gitignored, loaded automatically):

```
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-proj-...
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Tests (uses the real bugreport fixtures in `backend/tests/fixtures/` if
present; parser tests are skipped otherwise):

```bash
cd backend
pytest -q
```

## Bluetooth / Wi-Fi: what's decoded vs. not

`bt_hci.py` decodes the diagnostically load-bearing HCI event types per-record
(Connection Complete, Disconnection Complete, Command Complete, Command
Status, LE Connection Complete), with HCI status/reason codes named from the
Bluetooth Core Spec. Everything else is counted by event code
(`event_code_counts`) without per-record decoding -- this is HCI-framing-level
visibility (connections, disconnects, command failures), not a full L2CAP/
profile-level protocol dissector.

`wifi.py` decodes `DUMP OF SERVICE wifi`'s WifiController/ClientModeImpl
state-machine transition log: disconnection events with their IEEE 802.11
reason code (named from the spec, e.g. "Deauthenticated: station leaving"),
and BSSID association/roam events. The state machine log has dozens of other
event types (AP capability updates, screen state, scan requests, ...) not
decoded here since they carry no connectivity-failure signal.

## Explicitly out of scope for this MVP

- Team accounts, SSO, billing tiers.
- Full Bluetooth L2CAP/profile-level protocol decoding beyond core HCI
  framing (see above).
- Wi-Fi driver-level logs (wpa_supplicant.log, kernel driver traces) --
  `wifi.py` covers the framework-level `dumpsys wifi` state machine log,
  which is where connect/disconnect/roam events actually live in a
  bugreport; no driver-level log file was found in the bugreports tested
  against to build a lower-level parser against.
