import { AudioSpectrogram } from "./AudioSpectrogram";
import { FilterSettings } from "./FilterSettings";
import { useOpusSession } from "./useOpusSession";

export function OpusPage() {
  const session = useOpusSession();

  return (
    <section className="demo-card demo-card--opus">
      <div className="page-header">
        <div>
          <p className="page-kicker">Bidirectional audio</p>
          <h2>Opus Audio</h2>
        </div>
        <p className="page-copy">
          A single sendrecv transceiver carries microphone audio to Python and looped-back audio back to the browser.
        </p>
      </div>

      <div className={`status-row ${session.isReconnecting ? "status-row--warn" : ""}`}>
        <span className="status-label">Status</span>
        <span className="status-value">
          {session.status}
          {session.isReconnecting ? <span className="status-spinner">⟳</span> : null}
        </span>
      </div>

      <div className="signal-grid">
        <div className="signal-chip">
          <span className={`signal-dot ${session.isSendingAudio ? "is-active" : ""}`} />
          Sending: {session.isSendingAudio ? "Active" : "Inactive"}
        </div>
        <div className="signal-chip">
          <span className={`signal-dot ${session.isReceivingAudio ? "is-active" : ""}`} />
          Receiving: {session.isReceivingAudio ? "Active" : "Inactive"}
        </div>
        {session.isReconnecting ? (
          <div className="signal-chip signal-chip--warn">
            <span className="signal-dot signal-dot--warn" />
            Reconnecting (attempt {session.reconnectAttempt})
          </div>
        ) : null}
      </div>

      <div className="media-panel media-panel--audio">
        <audio ref={session.audioRef} controls autoPlay playsInline />
      </div>

      {session.filterPresetEntries.length > 0 ? (
        <section className="preset-panel">
          <div className="preset-panel__header">
            <label htmlFor="filter-select">Audio Filter</label>
            <span className="preset-description">{session.currentPresetDescription}</span>
          </div>

          <div className="preset-controls">
            <select
              id="filter-select"
              value={session.currentFilter}
              onChange={(event) => session.changeFilter(event.currentTarget.value)}
            >
              {session.filterPresetEntries.map(([key, preset]) => (
                <option key={key} value={key}>
                  {preset.name}
                </option>
              ))}
            </select>

            <label className="toggle-row toggle-row--inline">
              <input
                type="checkbox"
                checked={session.playFiltered}
                onChange={(event) => session.togglePlayFiltered(event.currentTarget.checked)}
              />
              <span>
                Play filtered audio
                <small>hear the filter effect</small>
              </span>
            </label>

            {session.vadActive ? <span className="vad-pill">Voice detected</span> : null}
          </div>
        </section>
      ) : null}

      <FilterSettings onApply={session.applyCustomFilters} />

      <section className="visualization">
        <div className="page-header page-header--compact">
          <div>
            <p className="page-kicker">Live analysis</p>
            <h3>Real-time Audio Spectrogram</h3>
          </div>
        </div>

        <AudioSpectrogram ref={session.spectrogramRef} threshold={0.6} height={300} width={700} />

        <div className="feature-grid">
          <div className="feature-chip">
            <span>RMS</span>
            <strong>{session.audioFeatures.rms.toFixed(3)}</strong>
          </div>
          <div className="feature-chip">
            <span>ZCR</span>
            <strong>{session.audioFeatures.zcr.toFixed(3)}</strong>
          </div>
          <div className="feature-chip">
            <span>Spectral centroid</span>
            <strong>{session.audioFeatures.spectral_centroid.toFixed(0)} Hz</strong>
          </div>
          {session.thresholdTriggered ? (
            <div className="feature-chip feature-chip--accent">
              <span>ML threshold</span>
              <strong>Triggered</strong>
            </div>
          ) : null}
        </div>
      </section>

      <div className="actions">
        <button type="button" onClick={session.stopMicrophone} disabled={!session.isSendingAudio || session.isReconnecting}>
          Stop Microphone
        </button>
        <button type="button" onClick={session.manualReconnect} disabled={session.isReconnecting}>
          Reconnect
        </button>
      </div>
    </section>
  );
}
