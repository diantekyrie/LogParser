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
                              dumpsys sections we have parsers for
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
    services/
      ingestion.py      wires zip -> sections -> parsers -> ParsedCapture
      persistence.py    ParsedCapture -> DB rows (facts, not raw blobs)
      correlation.py    multi-capture history queries for one device
      verification.py   independently verifies every app named in a
                         question before any narrative is built
      reasoning.py       assembles verified facts + confidence into a
                         bundle, hands it to the LLM layer to narrate
    llm/                LLMClient interface; StubLLMClient (default) or
                         AnthropicClient (if ANTHROPIC_API_KEY is set) --
                         either way the LLM only narrates a fact bundle,
                         it never sees raw bugreport text
    api/                FastAPI routes: upload, list, diagnose
  tests/
    fixtures/           real bugreports (not committed -- see .gitignore)
    test_parsers_fixtures.py   parser-level regression tests, pinned to
                                exact source line numbers
    test_end_to_end.py         full pipeline: parse -> persist -> verify
                                -> correlate -> diagnose

frontend/               minimal React + Vite UI: upload, ask a question,
                         see each named app's independently verified state
                         with confidence + source citations, then the
                         narrated report
```

## Why parsers, not RAG

The section extractor streams the giant flattened bugreport text once and
only buffers the sections we have parsers for. Within those sections,
values are pulled by exact-format regex, not chunk/embedding retrieval --
so a plain-text section like the audio focus stack (which a retrieval-based
tool can silently miss on a long, low-natural-language-signal section) is
never "not found." Every fact carries a `SourceRef` (section + line
range), so every claim in a report can point back at exact lines.

A parser bug this exact process caught during development: Python's default
universal-newlines text mode splits on bare `\r` bytes embedded in
tombstone/crash data elsewhere in the bugreport, which silently drifted
every subsequent line number by ~43,000 lines while the *parsed values*
still looked plausible. It was only caught by cross-checking parsed line
numbers against `grep`-verified ones on a real fixture -- see
`app/parsers/section_extractor.py` and `tests/test_parsers_fixtures.py`.
That's the whole reason parser correctness gets pinned against real
fixtures with real line numbers, not synthetic data that's too clean to
expose this kind of bug.

## Independent verification

`verification.py` extracts every app the question names (literal package
IDs, or exact-segment brand-word matches like "YouTube Music" ->
`com.google.android.apps.youtube.music`) and pulls each one's own parsed
state -- focus stack membership, MediaSession playback state, latest focus
event, targetSdk -- before any diagnosis narrative is built. The user's
framing of "app X caused app Y's problem" is never taken as fact for either
app.

## Confidence

`reasoning.score_confidence()` labels a claim HIGH/MEDIUM/LOW/UNCONFIRMED
based on how many independent structured facts back it and how many
captures in the device's history were checked -- never from how assertively
something reads. The LLM system prompt is instructed to carry these labels
forward verbatim, never upgrade them, and cite source lines for every claim.

## Multi-capture correlation

Captures are associated with a `Device` (by a label you choose, e.g. a
serial number) rather than treated as disposable uploads. Any question
containing trigger words like "never", "across", "history", "week"
triggers `correlation.package_history_across_device()`, which checks a
claim (e.g. "has this app ever requested audio focus") against every
capture on file for the device and reports how many captures backed the
answer -- not just whichever file is in the current request.

## Running it

Backend:

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
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

To enable the real LLM narration layer instead of the deterministic stub,
set `ANTHROPIC_API_KEY` before starting the backend.

## Explicitly out of scope for this MVP

- Bluetooth HCI snoop / Wi-Fi driver log parsing (the underserved wedge --
  build once this pipeline and architecture are proven).
- Team accounts, SSO, billing tiers.
- UI polish beyond functional.
