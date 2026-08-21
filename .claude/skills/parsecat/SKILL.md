---
name: parsecat
description: Analyze Android bugreports, logcat dumps, and packet captures with ParseCat. Use when the user wants to diagnose a device problem from a bugreport (.zip/.txt) or capture (.pcap/.pcapng) — scanning for crashes, ANRs, Wi-Fi disconnects, SELinux denials, Bluetooth/pairing failures, battery drain, or process kills — or asks to upload, scan, or ask questions about a capture file. Also use for correlating two devices (e.g. a phone and a watch that were pairing).
---

# ParseCat

ParseCat parses Android bugreports into structured, source-cited facts and
narrates them. Findings come from deterministic parsers; only the prose
summary is LLM-generated.

## Before anything else: check the server

ParseCat runs as a local HTTP API. Nothing works without it.

```bash
curl -s "${PARSECAT_URL:-http://127.0.0.1:8000}/api/health"
```

Expect `{"status":"ok"}`. If it fails, tell the user the backend isn't
running and how to start it — do not attempt to work around it:

```bash
cd <parsecat>/backend && python -m uvicorn app.main:app --port 8000
```

Use `$PARSECAT_URL` if set, else `http://127.0.0.1:8000`. All paths below
are relative to that base.

## Choosing Scan vs Ask

This is the main judgment call. Get it right before spending a request.

**Scan** (`POST /api/captures/{id}/scan`) — for "what's wrong with this
device?", a first look at an unfamiliar capture, or any open-ended
triage. It checks every evidence category unconditionally and returns
findings ranked by severity. **Prefer this when the user hasn't named a
specific symptom.**

**Ask** (`POST /api/captures/{id}/diagnose`) — for a specific question
("did YouTube Music lose audio focus?", "why did Wi-Fi drop at 3pm?").
Cheaper and more focused, but it only gathers evidence categories whose
keywords appear in the question.

Cost matters here and the difference is large: a scan sends roughly
14,000 tokens to the LLM; a targeted ask sends a few hundred. Don't scan
repeatedly when one question would do, and don't ask five separate
questions when one scan covers them.

## Workflow

### 1. Upload a capture

```bash
curl -s -X POST "$BASE/api/captures" \
  -F "device_label=<name>" \
  -F "file=@<path>;type=application/zip"
```

Accepts `.zip`, `.txt`, `.pcap`, `.pcapng`. Bugreport zips are often
100–300 MB and take several seconds — say so rather than letting it look
hung. Returns `capture_id`, which everything else needs.

`device_label` groups captures: same label = same physical device, and
device-wide evidence is then checked across all of them. Add
`-F "investigation_label=<name>"` to also group captures from *different*
devices into one investigation (see step 4).

Check `parse_warnings` in the response and surface anything non-empty.

### 2. Scan

```bash
curl -s -X POST "$BASE/api/captures/{id}/scan" -F "provider=anthropic"
```

Returns `bundle.ranked_findings` (deterministic) and `report` (LLM prose).

Read findings from `ranked_findings`, not by re-reading the prose. Each
has: `severity` (CRITICAL/HIGH/MEDIUM/LOW), `category`, `title`,
`detail`, `confidence`, `occurrences`, `first_timestamp`/`last_timestamp`,
`capture_id`, and `source` (section + line numbers).

### 3. Ask a specific question

```bash
curl -s -X POST "$BASE/api/captures/{id}/diagnose" \
  -F "question=<question>" -F "provider=anthropic"
```

For a follow-up that references the previous answer ("should I worry
about that?"), pass prior turns so it has context:

```bash
-F 'history=[{"question":"...","report":"..."}]'
```

Important: a follow-up still gathers evidence from its OWN wording. A
vague follow-up gathers nothing and will correctly answer "unknown" —
so keep the relevant noun in it ("should I worry about that Wi-Fi
disconnect?", not "should I worry about that?").

### 4. Correlate two devices

Upload each device under its own `device_label` but a shared
`investigation_label`, then:

```bash
curl -s -X POST "$BASE/api/investigations/{label}/diagnose" \
  -F "question=<question>" -F "provider=anthropic"
```

This is the case a single-device tool can't answer — e.g. a phone and a
watch that failed to pair. Every fact stays tagged with which device it
came from.

### 5. Dashboard data (no LLM, no tokens)

- `GET /api/captures/{id}/summary` — one capture's parsed facts
- `GET /api/devices/{label}/summary` — merged across all its captures
- `GET /api/investigations/{label}/summary` — merged across an investigation
- `GET /api/devices` · `GET /api/investigations` — what's already loaded

Use these when the user wants counts or tables rather than narrative.

## Providers

`GET /api/llm/providers` lists what's usable. Pass `provider=` as
`anthropic`, `openai`, `openai-codex`, or `stub`.

**`stub` costs nothing and calls no LLM** — it returns the full verified
fact bundle with no prose. Use it when the user only needs the findings,
is iterating, or is worried about token spend. Findings are identical;
only the narration is missing.

If narration fails, the response still returns `200` with the facts
intact and `llm_error` set. Report the facts and mention narration failed
— don't treat it as a total failure.

## Reporting results faithfully

ParseCat is built so that every claim traces to a log line. Preserve that
when you summarize:

- **Carry confidence labels verbatim.** LOW means one uncorroborated fact
  from a single capture. Never upgrade it because a finding sounds
  serious.
- **Severity is about event type, not proven impact.** A HIGH finding
  deserves attention first; it does not mean it caused the user's
  symptom. Don't assert a causal chain between findings unless the data
  states one.
- **Keep the distinctions the parsers preserve.** SELinux `enforcing:
  true` = actually blocked; `false` = logged but allowed (not a current
  failure). A process `kill` has a reason; a `died` doesn't mean the
  system killed it. Flattening these overstates the findings.
- **Cite section and line numbers** when you quote a finding.
- **Absence of findings ≠ healthy device.** It means nothing was found in
  the categories ParseCat parses. Say it that way.

## What ParseCat does not do

Don't offer these:

- **Apple sysdiagnose / iOS** — unsupported. Different format entirely.
- **Modem traces (QXDM/Shannon), CAN bus, embedded Linux** — not parsed.
- **`.btt` Ellisys captures** — deliberately unsupported; they need
  Ellisys's own software.
- **Deep packet inspection beyond 802.11/Ethernet basics** — if `tshark`
  isn't installed server-side, packet analysis falls back to a narrower
  hand-rolled parser that does not decode deauth reason codes or detect
  TCP retransmissions. Each result's `note` says which backend ran; don't
  claim facts the backend didn't produce.
