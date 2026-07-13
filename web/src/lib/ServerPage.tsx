import { TraceOverlay } from "./TraceOverlay";
import { useServerSession } from "./useServerSession";

export function ServerPage() {
  const {
    clearCompletedTraces,
    clearFailedTraces,
    createOffer,
    deleteTask,
    status,
    toasts,
    dismissToast,
    performanceEvents,
    groups,
    summaries,
    tasks,
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
        <button type="button" onClick={createOffer}>
          Create Offer
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
