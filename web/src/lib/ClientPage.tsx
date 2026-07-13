import { TraceOverlay } from "./TraceOverlay";
import { useClientSession } from "./useClientSession";

export function ClientPage() {
  const {
    clearCompletedTraces,
    clearFailedTraces,
    deleteTask,
    startNegotiation,
    status,
    toasts,
    dismissToast,
    performanceEvents,
    groups,
    summaries,
    tasks,
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
      {toasts.length > 0 ? (
        <div className="toast-stack" aria-live="polite">
          {toasts.map((toast, index) => (
            <div className="toast toast--error" key={`${toast}-${index}`}>
              <span>{toast}</span>
              <button type="button" onClick={() => dismissToast(index)} aria-label="Dismiss error">
                ×
              </button>
            </div>
          ))}
        </div>
      ) : null}

      <div className="media-panel">
        <video ref={videoRef} controls autoPlay playsInline muted={false} />
      </div>

      <div className="actions">
        <button type="button" onClick={startNegotiation}>
          Start / Negotiate
        </button>
      </div>

      <TraceOverlay
        performanceEvents={performanceEvents}
        groups={groups}
        tasks={tasks}
        onClearCompleted={clearCompletedTraces}
        onClearFailed={clearFailedTraces}
        onDeleteTask={deleteTask}
        summaries={summaries}
      />
    </section>
  );
}
