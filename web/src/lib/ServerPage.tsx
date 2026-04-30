import { TraceOverlay } from "./TraceOverlay";
import { useServerSession } from "./useServerSession";

export function ServerPage() {
  const {
    clearCompletedTraces,
    clearFailedTraces,
    createOffer,
    deleteTrace,
    setTraceRetentionSeconds,
    status,
    successRetentionSeconds,
    summaries,
    traces,
    videoRef,
  } = useServerSession();

  return (
    <section className="demo-card">
      <div className="page-header">
        <div>
          <p className="page-kicker">Browser as server</p>
          <h2>Server Mode</h2>
        </div>
        <p className="page-copy">Browser creates the offer and the Python client returns the answer.</p>
      </div>

      <div className="status-row">
        <span className="status-label">Status</span>
        <span className="status-value">{status}</span>
      </div>

      <div className="media-panel">
        <video ref={videoRef} controls autoPlay playsInline muted={false} />
      </div>

      <div className="actions">
        <button type="button" onClick={createOffer}>
          Create Offer
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
