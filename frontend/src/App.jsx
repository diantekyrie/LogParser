import { useEffect, useState, useCallback, useRef } from "react";

const SEVERITY_COLOR = { critical: "var(--red)", warning: "var(--amber)", info: "var(--blue)" };
const CONFIDENCE_COLOR = { HIGH: "var(--green)", MEDIUM: "var(--amber)", LOW: "var(--orange)", UNCONFIRMED: "var(--muted)" };

async function api(path, opts) {
  const res = await fetch(`/api${path}`, opts);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function SourceTag({ source }) {
  if (!source) return null;
  return (
    <span className="src">
      {source.section}:{source.line_start}
      {source.line_end !== source.line_start ? `-${source.line_end}` : ""}
    </span>
  );
}

function StatCard({ label, value, tone }) {
  return (
    <div className={`stat stat-${tone || "default"}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function DeviceInfoPanel({ info }) {
  if (!info) return <p className="muted">No device info parsed for this capture.</p>;
  const rows = [
    ["Manufacturer", info.manufacturer], ["Model", info.model],
    ["Android", info.android_release ? `Android ${info.android_release} (SDK ${info.sdk_version})` : null],
    ["Build", info.build_id], ["Security patch", info.security_patch],
    ["CPU", info.cpu_abi], ["Bootloader", info.bootloader], ["Hardware", info.hardware],
    ["Build type", info.build_type], ["Serial", info.serial],
    ["Uptime", info.uptime], ["Timezone", info.timezone],
    ["Encryption", info.crypto_state], ["Verified boot", info.verified_boot_state],
    ["Debuggable", info.debuggable === null ? null : String(info.debuggable)],
    ["Network", info.network], ["Radio", info.radio],
  ].filter(([, v]) => v);
  return (
    <div className="device-grid">
      {rows.map(([k, v]) => (
        <div className="device-row" key={k}>
          <span className="device-key">{k}</span>
          <span className="device-val">{v}</span>
        </div>
      ))}
    </div>
  );
}

function Timeline({ events }) {
  if (!events || events.length === 0) return <p className="muted">No timestamped events parsed.</p>;
  return (
    <div className="timeline">
      {events.map((e, i) => (
        <div className="timeline-row" key={i}>
          <span className="timeline-dot" style={{ background: SEVERITY_COLOR[e.severity] || "var(--muted)" }} />
          <span className="timeline-ts">{e.timestamp}</span>
          <span className="timeline-label">{e.label}</span>
          <SourceTag source={e.source} />
        </div>
      ))}
    </div>
  );
}

function ClaimCard({ claim }) {
  const s = claim.verified_state;
  return (
    <div className="claim-card">
      <div className="claim-header">
        <strong>{claim.package}</strong>
        <span className="badge" style={{ background: CONFIDENCE_COLOR[claim.confidence] }}>{claim.confidence}</span>
        <span className="muted small">({claim.matched_how})</span>
      </div>
      <p className="muted small">{claim.corroboration}</p>
      <table className="fact-table">
        <tbody>
          <tr><td>Top of audio focus stack</td><td>{String(s.is_top_of_audio_focus_stack)}</td><td></td></tr>
          <tr>
            <td>MediaSession state</td>
            <td>{s.media_session_playback_state ?? "unknown"}{s.media_session_active !== null ? ` (active=${s.media_session_active})` : ""}</td>
            <td><SourceTag source={s.media_session_source} /></td>
          </tr>
          <tr>
            <td>Latest audio focus event</td>
            <td>{s.latest_focus_event ? `${s.latest_focus_event.event_type} @ ${s.latest_focus_event.timestamp}` : "none"}</td>
            <td><SourceTag source={s.latest_focus_event?.source} /></td>
          </tr>
          <tr><td>targetSdk</td><td>{s.target_sdk ?? "unknown"}</td><td><SourceTag source={s.target_sdk_source} /></td></tr>
        </tbody>
      </table>
      {claim.cross_capture_history && (
        <div className="history">
          Checked across {claim.cross_capture_history.captures_checked} capture(s). Ever requested audio focus:{" "}
          {String(claim.cross_capture_history.ever_requested_audio_focus)} ({claim.cross_capture_history.focus_request_count_all_captures} total).
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [devices, setDevices] = useState([]);
  const [deviceLabel, setDeviceLabel] = useState("");
  const [captures, setCaptures] = useState([]);
  const [selectedCaptureId, setSelectedCaptureId] = useState(null);
  const [summary, setSummary] = useState(null);
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [question, setQuestion] = useState("");
  const [diagnosis, setDiagnosis] = useState(null);
  const [diagnosing, setDiagnosing] = useState(false);
  const [providers, setProviders] = useState([]);
  const [provider, setProvider] = useState("");

  const refreshDevices = useCallback(() => {
    api("/devices").then(setDevices).catch(() => {});
  }, []);

  useEffect(() => { refreshDevices(); }, [refreshDevices]);

  useEffect(() => {
    api("/llm/providers").then((ps) => {
      setProviders(ps);
      const firstAvailable = ps.find((p) => p.available);
      if (firstAvailable) setProvider(firstAvailable.id);
    }).catch(() => {});
  }, []);

  // Every keystroke in the device-label field can fire a lookup; requests
  // don't resolve in the order they were sent (a stale, still-typing label
  // like "demo-devic" can 404 and land AFTER the final "demo-device" one
  // resolves, silently stomping the correct state with an error). Both
  // request kinds are tagged with a monotonic id and a resolved response is
  // applied only if it's still the most recent request of its kind.
  const captureLookupSeq = useRef(0);
  const summarySeq = useRef(0);

  const loadCaptures = useCallback((label) => {
    if (!label) { setCaptures([]); return; }
    const seq = ++captureLookupSeq.current;
    api(`/devices/${encodeURIComponent(label)}/captures`)
      .then((cs) => {
        if (seq !== captureLookupSeq.current) return; // superseded by a later keystroke
        setCaptures(cs);
        setError(null);
        if (cs.length > 0) selectCapture(cs[cs.length - 1].id);
      })
      .catch(() => {
        if (seq !== captureLookupSeq.current) return;
        setCaptures([]);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function selectCapture(id) {
    setSelectedCaptureId(id);
    setDiagnosis(null);
    const seq = ++summarySeq.current;
    api(`/captures/${id}/summary`)
      .then((s) => {
        if (seq !== summarySeq.current) return;
        setSummary(s);
        setError(null);
      })
      .catch((e) => {
        if (seq !== summarySeq.current) return;
        setError(String(e));
      });
  }

  async function handleUpload(e) {
    e.preventDefault();
    if (!file || !deviceLabel) return;
    setBusy(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("device_label", deviceLabel);
      form.append("file", file);
      const data = await api("/captures", { method: "POST", body: form });
      refreshDevices();
      loadCaptures(deviceLabel);
      selectCapture(data.capture_id);
      setFile(null);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleDiagnose(e) {
    e.preventDefault();
    if (!selectedCaptureId || !question) return;
    setDiagnosing(true);
    setError(null);
    setDiagnosis(null);
    try {
      const form = new FormData();
      form.append("question", question);
      if (provider) form.append("provider", provider);
      const data = await api(`/captures/${selectedCaptureId}/diagnose`, { method: "POST", body: form });
      setDiagnosis(data);
    } catch (err) {
      setError(String(err));
    } finally {
      setDiagnosing(false);
    }
  }

  const c = summary?.counts;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">groundtruth</div>
        <div className="tagline">Device log diagnosis, backed by parsed facts, not vibes.</div>
      </header>

      <div className="layout">
        <aside className="sidebar">
          <section className="panel">
            <h2>Device</h2>
            <label>
              Device identifier
              <input
                type="text" list="known-devices" placeholder="e.g. frankel-pixel"
                value={deviceLabel}
                onChange={(e) => { setDeviceLabel(e.target.value); loadCaptures(e.target.value); }}
              />
              <datalist id="known-devices">
                {devices.map((d) => <option key={d.id} value={d.label} />)}
              </datalist>
            </label>
            <label>
              Bugreport .zip
              <input type="file" accept=".zip" onChange={(e) => setFile(e.target.files[0])} />
            </label>
            <button onClick={handleUpload} disabled={busy || !file || !deviceLabel}>
              {busy ? "Parsing…" : "Upload & parse"}
            </button>
          </section>

          <section className="panel">
            <h2>Captures for this device</h2>
            {captures.length === 0 && <p className="muted small">None yet.</p>}
            <ul className="capture-list">
              {captures.map((cap) => (
                <li
                  key={cap.id}
                  className={cap.id === selectedCaptureId ? "active" : ""}
                  onClick={() => selectCapture(cap.id)}
                >
                  <div className="cap-name">#{cap.id} {cap.original_filename}</div>
                  <div className="cap-date muted small">{cap.ingested_at}</div>
                </li>
              ))}
            </ul>
          </section>
        </aside>

        <main className="main">
          {error && <div className="error">{error}</div>}

          {!summary && <div className="panel"><p className="muted">Upload a bugreport or pick a capture to see parsed facts.</p></div>}

          {summary && (
            <>
              <section className="panel">
                <h2>Device information</h2>
                <DeviceInfoPanel info={summary.device_info} />
              </section>

              <section className="panel">
                <h2>Parsed facts (capture #{summary.capture_id})</h2>
                {summary.parse_warnings.length > 0 && (
                  <ul className="warnings">{summary.parse_warnings.map((w) => <li key={w}>⚠ {w}</li>)}</ul>
                )}
                <div className="stat-grid">
                  <StatCard label="Java crashes" value={c.java_crashes} tone={c.java_crashes > 0 ? "critical" : "ok"} />
                  <StatCard label="Native crashes (tombstones)" value={c.native_crashes} tone={c.native_crashes > 0 ? "warning" : "ok"} />
                  <StatCard label="ANRs" value={c.anrs} tone={c.anrs > 0 ? "critical" : "ok"} />
                  <StatCard label="Wi-Fi disconnections" value={c.wifi_disconnections} tone="default" />
                  <StatCard label="Freeze events" value={c.freeze_events} tone="default" />
                  <StatCard label="Unfreeze events" value={c.unfreeze_events} tone="default" />
                  <StatCard label="Packages" value={c.packages} tone="default" />
                  <StatCard label="Foreground services" value={c.foreground_services} tone="default" />
                  <StatCard label="Media sessions" value={c.media_sessions} tone="default" />
                  <StatCard label="Focus stack entries" value={c.focus_stack_entries} tone="default" />
                </div>
              </section>

              {summary.crash_events.length > 0 && (
                <section className="panel">
                  <h2>Java crashes</h2>
                  <table className="fact-table">
                    <thead><tr><th>Time</th><th>Package</th><th>Exception</th><th>Message</th><th>Root cause</th><th>Cite</th></tr></thead>
                    <tbody>
                      {summary.crash_events.map((cr, i) => (
                        <tr key={i}>
                          <td>{cr.timestamp}</td><td>{cr.package}</td><td>{cr.exception_class}</td>
                          <td className="small">{cr.message}</td>
                          <td className="small">
                            {cr.root_cause_class ? (
                              <>
                                <strong>{cr.root_cause_class}</strong>{cr.root_cause_message ? `: ${cr.root_cause_message}` : ""}
                                {cr.root_cause_frame && <div className="muted">{cr.root_cause_frame}</div>}
                              </>
                            ) : <span className="muted">none</span>}
                          </td>
                          <td><SourceTag source={cr.source} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </section>
              )}

              {summary.anrs.length > 0 && (
                <section className="panel">
                  <h2>ANRs</h2>
                  <table className="fact-table">
                    <thead><tr><th>Time</th><th>Package</th><th>Reason</th><th>PID</th></tr></thead>
                    <tbody>
                      {summary.anrs.map((a, i) => (
                        <tr key={i}>
                          <td>{a.timestamp}</td><td>{a.package ?? <span className="muted">unattributed</span>}</td>
                          <td className="small">{a.reason}</td><td>{a.pid}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </section>
              )}

              {summary.tombstones.length > 0 && (
                <section className="panel">
                  <h2>Native crashes (tombstones)</h2>
                  <table className="fact-table">
                    <thead><tr><th>Time</th><th>Package / executable</th><th>Signal</th><th>Top frame</th></tr></thead>
                    <tbody>
                      {summary.tombstones.map((t, i) => (
                        <tr key={i}>
                          <td className="small">{t.timestamp ?? t.modified_at}</td>
                          <td>{t.package ?? <span className="muted">{t.executable ?? "unattributed"}</span>}</td>
                          <td>{t.signal_name}{t.signal_code ? ` (${t.signal_code})` : ""}</td>
                          <td className="small">{t.top_frame}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </section>
              )}

              {summary.bt_hci_summary && (
                <section className="panel">
                  <h2>Bluetooth HCI log</h2>
                  <div className="stat-grid">
                    <StatCard label="Total packets" value={summary.bt_hci_summary.total_packets} tone="default" />
                    <StatCard label="Commands" value={summary.bt_hci_summary.command_count} tone="default" />
                    <StatCard label="Events" value={summary.bt_hci_summary.event_count} tone="default" />
                    <StatCard label="ACL data" value={summary.bt_hci_summary.acl_data_count} tone="default" />
                  </div>
                  <p className="muted small">
                    {summary.bt_hci_summary.first_timestamp} &ndash; {summary.bt_hci_summary.last_timestamp}
                  </p>
                  {summary.bt_hci_summary.notable_events.length > 0 && (
                    <>
                      <h3>Notable events (disconnects &amp; non-success statuses)</h3>
                      <table className="fact-table">
                        <thead><tr><th>Time</th><th>Kind</th><th>Status</th><th>Reason</th><th>Handle</th></tr></thead>
                        <tbody>
                          {summary.bt_hci_summary.notable_events.map((e, i) => (
                            <tr key={i}>
                              <td className="small">{e.timestamp}</td><td>{e.kind.replace(/_/g, " ")}</td>
                              <td className={e.status_name !== "Success" ? "warn-text" : ""}>{e.status_name}</td>
                              <td>{e.reason_name ?? ""}</td><td>{e.handle ?? ""}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </>
                  )}
                </section>
              )}

              {summary.top_battery_consumers.length > 0 && (
                <section className="panel">
                  <h2>Top battery consumers</h2>
                  <p className="muted small">Estimated mAh per app/UID for this capture. Package is unattributed (not guessed) for shared system UIDs.</p>
                  <table className="fact-table">
                    <thead><tr><th>App / UID</th><th>Total (mAh)</th><th>Breakdown</th><th>Cite</th></tr></thead>
                    <tbody>
                      {summary.top_battery_consumers.map((b, i) => (
                        <tr key={i}>
                          <td>{b.package ?? <span className="muted">{b.uid_token} (unattributed)</span>}</td>
                          <td>{b.total_mah.toFixed(2)}</td>
                          <td className="small">
                            {Object.entries(b.components_mah).map(([k, v]) => `${k}=${v.toFixed(2)}`).join(", ")}
                          </td>
                          <td><SourceTag source={b.source} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </section>
              )}

              {summary.wifi_events.filter((w) => w.kind === "disconnection").length > 0 && (
                <section className="panel">
                  <h2>Wi-Fi disconnections</h2>
                  <table className="fact-table">
                    <thead><tr><th>Time</th><th>SSID</th><th>Reason</th><th>Locally initiated</th><th>Cite</th></tr></thead>
                    <tbody>
                      {summary.wifi_events.filter((w) => w.kind === "disconnection").map((w, i) => (
                        <tr key={i}>
                          <td className="small">{w.timestamp}</td><td>{w.ssid}</td>
                          <td className={!w.locally_generated ? "warn-text" : ""}>{w.reason_name}</td>
                          <td>{String(w.locally_generated)}</td>
                          <td><SourceTag source={w.source} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </section>
              )}

              {summary.top_freeze_offenders.length > 0 && (
                <section className="panel">
                  <h2>Top freeze/unfreeze offenders</h2>
                  <table className="fact-table">
                    <thead><tr><th>Package</th><th>Freezes</th><th>Unfreezes</th></tr></thead>
                    <tbody>
                      {summary.top_freeze_offenders.map((o) => (
                        <tr key={o.package}><td>{o.package}</td><td>{o.freezes}</td><td>{o.unfreezes}</td></tr>
                      ))}
                    </tbody>
                  </table>
                </section>
              )}

              <section className="panel">
                <h2>Media sessions</h2>
                {summary.media_sessions.length === 0 ? <p className="muted small">No media sessions parsed.</p> : (
                  <table className="fact-table">
                    <thead><tr><th>Package</th><th>State</th><th>Active</th><th>Position (ms)</th><th>Cite</th></tr></thead>
                    <tbody>
                      {summary.media_sessions.map((m, i) => (
                        <tr key={i}>
                          <td>{m.package}</td><td>{m.playback_state ?? "unknown"}</td>
                          <td>{String(m.active)}</td><td>{m.position_ms}</td>
                          <td><SourceTag source={m.source} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </section>

              <section className="panel">
                <h2>Event timeline</h2>
                <Timeline events={summary.timeline} />
              </section>

              <section className="panel">
                <h2>Ask</h2>
                <p className="muted small">Named apps are independently verified against parsed facts; the question's framing is not taken as fact.</p>
                <form onSubmit={handleDiagnose}>
                  <textarea
                    rows={3}
                    placeholder="e.g. Was there a crash on this device? Did com.apple.android.music hold audio focus?"
                    value={question}
                    onChange={(e) => setQuestion(e.target.value)}
                  />
                  <div className="ask-row">
                    <label className="inline-label">
                      Narrated by
                      <select value={provider} onChange={(e) => setProvider(e.target.value)}>
                        {providers.map((p) => (
                          <option key={p.id} value={p.id} disabled={!p.available}>
                            {p.label}{!p.available ? " (no key set)" : ""}
                          </option>
                        ))}
                      </select>
                    </label>
                    <button type="submit" disabled={diagnosing || !question}>
                      {diagnosing ? "Diagnosing…" : "Diagnose across this device"}
                    </button>
                  </div>
                </form>
              </section>

              {diagnosis && (
                <section className="panel">
                  <h2>Diagnosis</h2>
                  {diagnosis.bundle.claims.length === 0 && (
                    <p className="muted">No app named in the question matched a known package — nothing to verify.</p>
                  )}
                  {diagnosis.bundle.claims.map((cl) => <ClaimCard key={cl.package} claim={cl} />)}
                  <h3>Report {diagnosis.provider && <span className="muted small">— narrated by {providers.find((p) => p.id === diagnosis.provider)?.label || diagnosis.provider}</span>}</h3>
                  {diagnosis.report ? (
                    <pre className="report">{diagnosis.report}</pre>
                  ) : (
                    <div className="error">LLM narration failed (facts above are unaffected): {diagnosis.llm_error}</div>
                  )}
                </section>
              )}
            </>
          )}
        </main>
      </div>

      <style>{`
        :root {
          --bg: #0b0f17; --panel: #121826; --panel-border: #232c3d;
          --text: #e6e9ef; --muted: #7c8798; --accent: #ff8a3d; --accent-dark: #d96f26;
          --green: #2fbf71; --amber: #d9a72f; --red: #e5484d; --orange: #e5843d; --blue: #4a9eff;
        }
        * { box-sizing: border-box; }
        body { margin: 0; background: var(--bg); }
        .app { min-height: 100vh; background: var(--bg); color: var(--text); font-family: -apple-system, system-ui, sans-serif; }
        .topbar { padding: 20px 28px; border-bottom: 1px solid var(--panel-border); display: flex; align-items: baseline; gap: 14px; }
        .brand { font-size: 22px; font-weight: 800; color: var(--accent); letter-spacing: -0.5px; }
        .tagline { color: var(--muted); font-size: 13px; }
        .layout { display: grid; grid-template-columns: 300px 1fr; gap: 20px; padding: 20px 28px; align-items: start; }
        .sidebar { display: flex; flex-direction: column; gap: 16px; position: sticky; top: 20px; }
        .main { display: flex; flex-direction: column; gap: 16px; min-width: 0; }
        .panel { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 10px; padding: 16px 18px; }
        .panel h2 { margin: 0 0 12px; font-size: 14px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--accent); }
        .panel h3 { margin: 16px 0 8px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
        label { display: block; margin-bottom: 12px; font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
        input[type=text], textarea, input[type=file] {
          display: block; width: 100%; margin-top: 6px; padding: 9px 10px; font: inherit; font-size: 14px;
          background: #0e1420; color: var(--text); border: 1px solid var(--panel-border); border-radius: 6px;
        }
        textarea { resize: vertical; }
        select {
          padding: 8px 10px; font: inherit; font-size: 13px; background: #0e1420; color: var(--text);
          border: 1px solid var(--panel-border); border-radius: 6px; margin-top: 4px;
        }
        .ask-row { display: flex; align-items: flex-end; gap: 16px; margin-top: 4px; }
        .inline-label { margin-bottom: 0; flex: 0 0 auto; }
        .inline-label select { display: block; }
        button {
          padding: 9px 18px; border-radius: 6px; border: none; background: var(--accent); color: #1a0e05;
          cursor: pointer; font-weight: 700; font-size: 13px;
        }
        button:hover:not(:disabled) { background: var(--accent-dark); }
        button:disabled { opacity: 0.4; cursor: not-allowed; }
        .error { color: var(--red); padding: 12px; border: 1px solid var(--red); border-radius: 6px; white-space: pre-wrap; font-size: 13px; }
        .muted { color: var(--muted); }
        .small { font-size: 12px; }
        .warnings { color: var(--amber); font-size: 13px; padding-left: 18px; margin: 0 0 12px; }

        .capture-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }
        .capture-list li { padding: 8px 10px; border-radius: 6px; cursor: pointer; border: 1px solid transparent; }
        .capture-list li:hover { background: #0e1420; }
        .capture-list li.active { border-color: var(--accent); background: #1a1408; }
        .cap-name { font-size: 13px; }

        .device-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 4px 24px; }
        .device-row { display: flex; justify-content: space-between; gap: 12px; padding: 4px 0; border-bottom: 1px dashed #1c2433; font-size: 13px; }
        .device-key { color: var(--muted); flex-shrink: 0; }
        .device-val { text-align: right; word-break: break-word; font-family: ui-monospace, monospace; font-size: 12px; }

        .stat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 10px; }
        .stat { background: #0e1420; border: 1px solid var(--panel-border); border-radius: 8px; padding: 12px; }
        .stat-value { font-size: 24px; font-weight: 800; }
        .stat-label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; margin-top: 2px; }
        .stat-critical .stat-value { color: var(--red); }
        .warn-text { color: var(--amber); font-weight: 600; }
        .stat-warning .stat-value { color: var(--amber); }
        .stat-ok .stat-value { color: var(--green); }

        .fact-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .fact-table th { text-align: left; color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; padding: 6px 8px; border-bottom: 1px solid var(--panel-border); }
        .fact-table td { padding: 6px 8px; border-top: 1px solid #1c2433; }
        .src { color: var(--blue); font-family: ui-monospace, monospace; font-size: 11px; white-space: nowrap; }

        .timeline { display: flex; flex-direction: column; gap: 2px; max-height: 340px; overflow-y: auto; }
        .timeline-row { display: grid; grid-template-columns: 10px 150px 1fr auto; align-items: center; gap: 10px; padding: 5px 4px; border-radius: 4px; font-size: 12px; }
        .timeline-row:hover { background: #0e1420; }
        .timeline-dot { width: 8px; height: 8px; border-radius: 50%; }
        .timeline-ts { color: var(--muted); font-family: ui-monospace, monospace; }

        .claim-card { border: 1px solid var(--panel-border); border-radius: 8px; padding: 12px; margin-bottom: 12px; background: #0e1420; }
        .claim-header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
        .badge { color: #10131a; font-size: 11px; font-weight: 800; padding: 2px 8px; border-radius: 10px; }
        .history { margin-top: 8px; font-size: 12px; background: #10151f; padding: 8px; border-radius: 6px; color: var(--muted); }
        .report { white-space: pre-wrap; background: #0e1420; padding: 12px; border-radius: 6px; font-size: 13px; max-height: 420px; overflow: auto; border: 1px solid var(--panel-border); }
      `}</style>
    </div>
  );
}
