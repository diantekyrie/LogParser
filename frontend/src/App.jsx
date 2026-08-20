import { useState } from "react";

const CONFIDENCE_COLOR = {
  HIGH: "#1a7f37",
  MEDIUM: "#9a6700",
  LOW: "#953800",
  UNCONFIRMED: "#6e7781",
};

function SourceLink({ source }) {
  if (!source) return null;
  return (
    <span className="source">
      {source.section}:{source.line_start}
      {source.line_end !== source.line_start ? `-${source.line_end}` : ""}
    </span>
  );
}

function ClaimCard({ claim }) {
  const s = claim.verified_state;
  const color = CONFIDENCE_COLOR[claim.confidence] || "#6e7771";
  return (
    <div className="claim-card">
      <div className="claim-header">
        <strong>{claim.package}</strong>
        <span className="badge" style={{ background: color }}>
          {claim.confidence}
        </span>
        <span className="matched-how">({claim.matched_how})</span>
      </div>
      <p className="corroboration">{claim.corroboration}</p>
      <table className="fact-table">
        <tbody>
          <tr>
            <td>Top of audio focus stack</td>
            <td>{String(s.is_top_of_audio_focus_stack)}</td>
            <td></td>
          </tr>
          <tr>
            <td>MediaSession state</td>
            <td>
              {s.media_session_playback_state ?? "unknown"}
              {s.media_session_active !== null ? ` (active=${s.media_session_active})` : ""}
            </td>
            <td><SourceLink source={s.media_session_source} /></td>
          </tr>
          <tr>
            <td>Latest audio focus event</td>
            <td>{s.latest_focus_event ? `${s.latest_focus_event.event_type} @ ${s.latest_focus_event.timestamp}` : "none"}</td>
            <td><SourceLink source={s.latest_focus_event?.source} /></td>
          </tr>
          <tr>
            <td>targetSdk</td>
            <td>{s.target_sdk ?? "unknown"}</td>
            <td><SourceLink source={s.target_sdk_source} /></td>
          </tr>
        </tbody>
      </table>
      {claim.cross_capture_history && (
        <div className="history">
          <em>Checked across {claim.cross_capture_history.captures_checked} capture(s) for this device.</em>{" "}
          Ever requested audio focus: {String(claim.cross_capture_history.ever_requested_audio_focus)}{" "}
          ({claim.cross_capture_history.focus_request_count_all_captures} request(s) total).
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [deviceLabel, setDeviceLabel] = useState("");
  const [file, setFile] = useState(null);
  const [uploadResult, setUploadResult] = useState(null);
  const [captureId, setCaptureId] = useState(null);
  const [question, setQuestion] = useState("");
  const [diagnosis, setDiagnosis] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function handleUpload(e) {
    e.preventDefault();
    if (!file || !deviceLabel) return;
    setBusy(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("device_label", deviceLabel);
      form.append("file", file);
      const res = await fetch("/api/captures", { method: "POST", body: form });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setUploadResult(data);
      setCaptureId(data.capture_id);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleDiagnose(e) {
    e.preventDefault();
    if (!captureId || !question) return;
    setBusy(true);
    setError(null);
    setDiagnosis(null);
    try {
      const form = new FormData();
      form.append("question", question);
      const res = await fetch(`/api/captures/${captureId}/diagnose`, { method: "POST", body: form });
      if (!res.ok) throw new Error(await res.text());
      setDiagnosis(await res.json());
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="app">
      <header>
        <h1>groundtruth</h1>
        <p className="tagline">Device log diagnosis, backed by parsed facts, not vibes.</p>
      </header>

      <section className="panel">
        <h2>1. Upload a bugreport</h2>
        <form onSubmit={handleUpload}>
          <label>
            Device label
            <input
              type="text"
              placeholder="e.g. frankel-pixel"
              value={deviceLabel}
              onChange={(e) => setDeviceLabel(e.target.value)}
            />
          </label>
          <label>
            Bugreport .zip
            <input type="file" accept=".zip" onChange={(e) => setFile(e.target.files[0])} />
          </label>
          <button type="submit" disabled={busy || !file || !deviceLabel}>
            {busy ? "Working…" : "Upload & parse"}
          </button>
        </form>
        {uploadResult && (
          <div className="upload-result">
            <p>Capture #{uploadResult.capture_id} for <strong>{uploadResult.device_label}</strong> parsed.</p>
            {uploadResult.parse_warnings.length > 0 && (
              <ul className="warnings">
                {uploadResult.parse_warnings.map((w) => <li key={w}>⚠ {w}</li>)}
              </ul>
            )}
            <ul className="fact-counts">
              {Object.entries(uploadResult.facts_found).map(([k, v]) => (
                <li key={k}>{k.replace(/_/g, " ")}: {v}</li>
              ))}
            </ul>
          </div>
        )}
      </section>

      <section className="panel">
        <h2>2. Ask a question</h2>
        <form onSubmit={handleDiagnose}>
          <label>
            Question (name the apps involved)
            <textarea
              rows={3}
              placeholder="e.g. Did YouTube Music fail to pause when Apple Music started playing? What's Disney+'s targetSdk?"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
            />
          </label>
          <button type="submit" disabled={busy || !captureId || !question}>
            {busy ? "Diagnosing…" : "Diagnose"}
          </button>
        </form>
      </section>

      {error && <div className="error">{error}</div>}

      {diagnosis && (
        <section className="panel">
          <h2>3. Verified facts</h2>
          <p className="sub">
            Every app named in the question was independently checked before any narrative was built.
            Confidence reflects how many structured facts corroborate each claim, not phrasing.
          </p>
          {diagnosis.bundle.claims.map((c) => (
            <ClaimCard key={c.package} claim={c} />
          ))}

          <h2>Report</h2>
          {diagnosis.report ? (
            <pre className="report">{diagnosis.report}</pre>
          ) : (
            <div className="error">
              LLM narration failed (verified facts above are unaffected): {diagnosis.llm_error}
            </div>
          )}
        </section>
      )}

      <style>{`
        * { box-sizing: border-box; }
        body { margin: 0; }
        .app { max-width: 900px; margin: 0 auto; padding: 24px; font-family: system-ui, sans-serif; color: #1a1a1a; }
        header { margin-bottom: 24px; }
        h1 { margin-bottom: 4px; }
        .tagline { color: #57606a; margin-top: 0; }
        .panel { border: 1px solid #d0d7de; border-radius: 8px; padding: 16px; margin-bottom: 20px; }
        label { display: block; margin-bottom: 12px; font-size: 14px; font-weight: 600; }
        input[type=text], textarea { display: block; width: 100%; margin-top: 4px; padding: 8px; font: inherit; border: 1px solid #d0d7de; border-radius: 6px; }
        button { padding: 8px 16px; border-radius: 6px; border: 1px solid #1a1a1a; background: #1a1a1a; color: white; cursor: pointer; font-weight: 600; }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        .error { color: #cf222e; padding: 12px; border: 1px solid #cf222e; border-radius: 6px; margin-bottom: 16px; white-space: pre-wrap; }
        .fact-counts, .warnings { padding-left: 20px; }
        .claim-card { border: 1px solid #d0d7de; border-radius: 6px; padding: 12px; margin-bottom: 12px; }
        .claim-header { display: flex; align-items: center; gap: 8px; }
        .badge { color: white; font-size: 12px; font-weight: 700; padding: 2px 8px; border-radius: 10px; }
        .matched-how { color: #57606a; font-size: 12px; }
        .corroboration { color: #57606a; font-size: 13px; }
        .fact-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .fact-table td { padding: 4px 8px; border-top: 1px solid #eee; }
        .source { color: #0969da; font-family: monospace; font-size: 12px; }
        .history { margin-top: 8px; font-size: 13px; background: #f6f8fa; padding: 8px; border-radius: 6px; }
        .report { white-space: pre-wrap; background: #f6f8fa; padding: 12px; border-radius: 6px; font-size: 13px; max-height: 400px; overflow: auto; }
        .sub { color: #57606a; font-size: 13px; }
      `}</style>
    </div>
  );
}
