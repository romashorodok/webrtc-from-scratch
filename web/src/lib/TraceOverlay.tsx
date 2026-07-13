import { useState } from "react";
import type {
  GroupSnapshot, TraceCapture, TraceControl, TraceFacet, TraceMachine,
} from "./trace";
import { NormalizedTraceView } from "./TraceNormalizedView";

type TraceOverlayProps = {
  machinesById?: Map<string, TraceMachine>;
  controlsById?: Map<string, TraceControl>;
  groupsById?: Map<number, GroupSnapshot>;
  facetsById?: Map<string, TraceFacet>;
  capturesById?: Map<number, TraceCapture>;
  operationNamesById?: Map<number, string>;
  diagnostics?: Record<string, number>;
  topologyVersion?: number;
  valueVersion?: number;
  onRequestCapture?: (request: Record<string, unknown>) => void;
};

export function TraceOverlay(props: TraceOverlayProps) {
  const [open, setOpen] = useState(false);
  const count =
    (props.machinesById?.size ?? 0) + (props.controlsById?.size ?? 0) +
    (props.groupsById?.size ?? 0) + (props.facetsById?.size ?? 0) +
    (props.capturesById?.size ?? 0) + Object.keys(props.diagnostics ?? {}).length;

  return (
    <aside className={`trace-overlay ${open ? "is-open" : ""}`} aria-live="polite">
      <button type="button" className="trace-overlay__toggle" onClick={() => setOpen((value) => !value)}>
        Trace <span>{count}</span>
      </button>
      {open ? (
        <div className="trace-overlay__panel trace-overlay__panel--normalized">
          <header className="trace-overlay__header">
            <strong><span className="trace-overlay__live-dot is-live" />Runtime State</strong>
            <button type="button" onClick={() => setOpen(false)}>Close</button>
          </header>
          <NormalizedTraceView
            machinesById={props.machinesById ?? new Map()}
            controlsById={props.controlsById ?? new Map()}
            groupsById={props.groupsById ?? new Map()}
            facetsById={props.facetsById ?? new Map()}
            capturesById={props.capturesById ?? new Map()}
            operationNamesById={props.operationNamesById ?? new Map()}
            diagnostics={props.diagnostics ?? {}}
            topologyVersion={props.topologyVersion ?? 0}
            valueVersion={props.valueVersion ?? 0}
            onRequestCapture={props.onRequestCapture}
          />
        </div>
      ) : null}
    </aside>
  );
}
