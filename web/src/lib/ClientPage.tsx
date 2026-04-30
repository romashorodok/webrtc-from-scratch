import { TraceOverlay } from "./TraceOverlay";
import { useClientSession } from "./useClientSession";

export function ClientPage() {
  const {
    clearCompletedTraces,
    clearFailedTraces,
    deleteTrace,
    setTraceRetentionSeconds,
    startNegotiation,
    status,
    successRetentionSeconds,
    summaries,
    traces,
    videoRef,
  } = useClientSession();

  return (
    <section className="demo-card">
      <div className="page-header">
        <div>
          <p className="page-kicker">Browser as client</p>
          <h2>Client Mode</h2>
        </div>
        <p className="page-copy">Browser receives the offer, answers it, and plays the remote video.</p>
      </div>

      <div className="status-row">
        <span className="status-label">Status</span>
        <span className="status-value">{status}</span>
      </div>

      <div className="media-panel">
        <video ref={videoRef} controls autoPlay playsInline muted={false} />
      </div>

      <div className="actions">
        <button type="button" onClick={startNegotiation}>
          Start / Negotiate
        </button>
      </div>

      <TraceOverlay
        traces={traces}
        onClearCompleted={clearCompletedTraces}
        onClearFailed={clearFailedTraces}
        onDeleteTrace={deleteTrace}
        onRetentionChange={setTraceRetentionSeconds}
        retentionSeconds={successRetentionSeconds}
        summaries={summaries}
      />
    </section>
  );
}
