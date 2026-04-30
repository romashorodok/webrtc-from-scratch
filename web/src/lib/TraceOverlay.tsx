import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as d3 from "d3";
import {
  formatTraceExport,
  restoreVisibleTraceParents,
  type TraceRecord,
  type TraceSummary,
} from "./trace";

type TraceDatum = {
  trace: TraceRecord;
  children: TraceDatum[];
};

type TraceOverlayProps = {
  traces: TraceRecord[];
  summaries?: TraceSummary[];
  retentionSeconds?: number;
  onClearCompleted?: () => void;
  onClearFailed?: () => void;
  onDeleteTrace?: (traceId: string) => void;
  onRetentionChange?: (seconds: number) => void;
};

const statusClass: Record<string, string> = {
  created: "trace-node--created",
  running: "trace-node--running",
  completed: "trace-node--completed",
  failed: "trace-node--failed",
  cancelled: "trace-node--cancelled",
};

const retentionOptions = [
  { label: "0m", seconds: 0 },
  { label: "1m", seconds: 60 },
  { label: "5m", seconds: 300 },
  { label: "15m", seconds: 900 },
  { label: "60m", seconds: 3600 },
];

const MAX_RENDERED_TRACES = 650;
const MAX_SIDE_ITEMS = 50;

function durationLabel(trace: TraceRecord) {
  const avgDuration = numberMetadata(trace, "avg_duration_ms");
  const callCount = numberMetadata(trace, "call_count");
  if (callCount > 1 && avgDuration != null) {
    return `${callCount} calls | avg ${Math.round(avgDuration)}ms`;
  }
  if (trace.duration_ms == null) {
    return trace.status === "running" ? "running" : "";
  }
  if (trace.duration_ms >= 1000) {
    return `${(trace.duration_ms / 1000).toFixed(1)}s`;
  }
  return `${Math.round(trace.duration_ms)}ms`;
}

function compactDuration(ms: number | null | undefined) {
  if (ms == null || !Number.isFinite(ms)) {
    return "-";
  }
  if (Math.abs(ms) >= 1000) {
    return `${(ms / 1000).toFixed(1)}s`;
  }
  return `${Math.round(ms)}ms`;
}

function deltaLabel(ms: number | null | undefined) {
  if (ms == null || !Number.isFinite(ms)) {
    return "new";
  }
  const prefix = ms > 0 ? "+" : "";
  return `${prefix}${compactDuration(ms)}`;
}

function numberMetadata(trace: TraceRecord, key: string) {
  const value = trace.metadata[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function isFailedTrace(trace: TraceRecord) {
  return trace.status === "failed" || Boolean(trace.error);
}

function isVirtualTrace(trace: TraceRecord) {
  return trace.trace_id.startsWith("ui-group:");
}

function isArchivedTrace(trace: TraceRecord) {
  return trace.metadata.archived_trace === true;
}

function archivedTracesForSummary(summary: TraceSummary | null | undefined) {
  if (!summary) {
    return [];
  }
  if (Array.isArray(summary.archived_traces) && summary.archived_traces.length > 0) {
    return summary.archived_traces;
  }
  return summary.deleted_trace ? [summary.deleted_trace] : [];
}

function statusForGroup(records: TraceRecord[]) {
  if (records.some((trace) => trace.status === "running")) {
    return "running";
  }
  if (records.some((trace) => trace.status === "cancelled")) {
    return "cancelled";
  }
  return "completed";
}

function groupTraceRecords(traces: TraceRecord[]) {
  const childParents = new Set(traces.map((trace) => trace.parent_id).filter(Boolean));
  const grouped = new Map<string, TraceRecord[]>();
  const output: TraceRecord[] = [];

  for (const trace of traces) {
    const isLeaf = !childParents.has(trace.trace_id);
    const isBackendGroup = trace.metadata.trace_group === true;
    if (!isLeaf || isBackendGroup || isFailedTrace(trace)) {
      output.push(trace);
      continue;
    }

    const key = [trace.parent_id ?? "root", trace.kind, trace.name, trace.status].join("|");
    const bucket = grouped.get(key) ?? [];
    bucket.push(trace);
    grouped.set(key, bucket);
  }

  for (const records of grouped.values()) {
    if (records.length === 1) {
      output.push(records[0]);
      continue;
    }

    const totalDuration = records.reduce((sum, trace) => sum + (trace.duration_ms ?? 0), 0);
    const groupedStatus = statusForGroup(records);
    output.push({
      ...records[0],
      trace_id: `ui-group:${records[0].parent_id ?? "root"}:${records[0].kind}:${records[0].name}:${records.length}`,
      name: records[0].name,
      status: groupedStatus,
      duration_ms: totalDuration,
      error: null,
      metadata: {
        ...records[0].metadata,
        ui_group: true,
        call_count: records.length,
        avg_duration_ms: totalDuration / records.length,
      },
      transitions: [
        {
          at: records[0].created_at,
          event: "grouped",
          status: groupedStatus,
          duration_ms: totalDuration,
        },
      ],
    });
  }

  return output.sort((a, b) => a.created_at - b.created_at);
}

function limitTraceRecords(traces: TraceRecord[], selectedTraceId: string | null) {
  if (traces.length <= MAX_RENDERED_TRACES) {
    return { hiddenCount: 0, records: traces };
  }

  const byId = new Map(traces.map((trace) => [trace.trace_id, trace]));
  const included = new Set<string>();

  const includeWithAncestors = (trace: TraceRecord | undefined) => {
    let current = trace;
    while (current && !included.has(current.trace_id) && included.size < MAX_RENDERED_TRACES) {
      included.add(current.trace_id);
      current = current.parent_id ? byId.get(current.parent_id) : undefined;
    }
  };

  for (const trace of traces) {
    if (trace.trace_id === selectedTraceId || isFailedTrace(trace) || trace.status === "running") {
      includeWithAncestors(trace);
    }
  }

  const newest = [...traces].sort((a, b) => b.created_at - a.created_at);
  for (const trace of newest) {
    if (included.size >= MAX_RENDERED_TRACES) {
      break;
    }
    includeWithAncestors(trace);
  }

  const records = traces.filter((trace) => included.has(trace.trace_id));
  return { hiddenCount: traces.length - records.length, records };
}

function buildTree(traces: TraceRecord[]) {
  const root: TraceDatum = {
    trace: {
      trace_id: "__root__",
      parent_id: null,
      name: "Runtime",
      kind: "root",
      peer_id: null,
      created_at: 0,
      started_at: null,
      ended_at: null,
      duration_ms: null,
      status: "running",
      error: null,
      metadata: {},
    },
    children: [],
  };

  const byId = new Map<string, TraceDatum>();
  for (const trace of traces) {
    byId.set(trace.trace_id, { trace, children: [] });
  }

  for (const trace of traces) {
    const node = byId.get(trace.trace_id);
    if (!node) {
      continue;
    }
    const parent = trace.parent_id ? byId.get(trace.parent_id) : null;
    (parent ?? root).children.push(node);
  }

  return root;
}

export function TraceOverlay({
  traces,
  summaries = [],
  retentionSeconds = 60,
  onClearCompleted,
  onClearFailed,
  onDeleteTrace,
  onRetentionChange,
}: TraceOverlayProps) {
  const [open, setOpen] = useState(true);
  const [groupedView, setGroupedView] = useState(true);
  const [selectedTraceId, setSelectedTraceId] = useState<string | null>(null);
  const [inspectedSummaryId, setInspectedSummaryId] = useState<string | null>(null);
  const [preferLiveWhenEmpty, setPreferLiveWhenEmpty] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [copyStatus, setCopyStatus] = useState<"Copy" | "Copied" | "Selected">("Copy");
  const overlayRef = useRef<HTMLElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const viewportRef = useRef<SVGGElement | null>(null);
  const exportTextRef = useRef<HTMLTextAreaElement | null>(null);
  const zoomRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const panelPositionRef = useRef({ x: 0, y: 0 });
  const panelFrameRef = useRef<number | null>(null);
  const pendingArchiveTraceIdRef = useRef<string | null>(null);
  const pendingArchiveTraceIdsRef = useRef<Set<string>>(new Set());
  const autoSelectedDeletedSummaryRef = useRef(false);
  const dragRef = useRef<{
    pointerId: number;
    startX: number;
    startY: number;
    originX: number;
    originY: number;
  } | null>(null);
  const runningCount = useMemo(
    () => traces.filter((trace) => trace.status === "running").length,
    [traces],
  );
  const failedTraceRecords = useMemo(
    () => traces.filter(isFailedTrace).sort((a, b) => b.created_at - a.created_at),
    [traces],
  );
  const failedTraceCount = failedTraceRecords.length;
  const failedTraces = useMemo(
    () => failedTraceRecords.slice(0, MAX_SIDE_ITEMS),
    [failedTraceRecords],
  );
  const restorableSummary = useMemo(
    () => summaries.find((summary) => archivedTracesForSummary(summary).length > 0) ?? null,
    [summaries],
  );
  const inspectedSummary = useMemo(() => {
    if (inspectedSummaryId) {
      return summaries.find((summary) => summary.summary_id === inspectedSummaryId) ?? null;
    }
    return traces.length === 0 && !preferLiveWhenEmpty ? restorableSummary : null;
  }, [inspectedSummaryId, preferLiveWhenEmpty, restorableSummary, summaries, traces.length]);
  const inspectedTraces = useMemo(
    () => archivedTracesForSummary(inspectedSummary),
    [inspectedSummary],
  );
  const repairedLiveTraces = useMemo(
    () => restoreVisibleTraceParents(traces, summaries),
    [summaries, traces],
  );
  const treeSourceTraces = inspectedSummary ? inspectedTraces : repairedLiveTraces;
  const groupedTraces = useMemo(
    () =>
      open
        ? groupedView
          ? groupTraceRecords(treeSourceTraces)
          : treeSourceTraces
        : [],
    [groupedView, open, treeSourceTraces],
  );
  const exportTraces = useMemo(
    () => groupTraceRecords(treeSourceTraces),
    [treeSourceTraces],
  );
  const limitedTraces = useMemo(
    () =>
      inspectedSummary
        ? { hiddenCount: 0, records: groupedTraces }
        : limitTraceRecords(groupedTraces, selectedTraceId),
    [groupedTraces, inspectedSummary, selectedTraceId],
  );
  const visibleTraces = limitedTraces.records;
  const selectedTrace = useMemo(
    () =>
      selectedTraceId
        ? visibleTraces.find((trace) => trace.trace_id === selectedTraceId) ??
          inspectedTraces.find((trace) => trace.trace_id === selectedTraceId) ??
          traces.find((trace) => trace.trace_id === selectedTraceId) ??
          null
        : null,
    [inspectedTraces, selectedTraceId, traces, visibleTraces],
  );
  const visibleSummaries = useMemo(
    () => summaries.slice(0, MAX_SIDE_ITEMS),
    [summaries],
  );
  const liveState = inspectedSummary
    ? "Deleted"
    : runningCount > 0
      ? "Live"
      : traces.length > 0
        ? "Idle"
        : "Waiting";
  const exportText = useMemo(
    () =>
      formatTraceExport(exportTraces, {
        compact: true,
        summary: inspectedSummary,
        view: inspectedSummary ? "deleted" : "live",
      }),
    [exportTraces, inspectedSummary],
  );

  useEffect(() => {
    if (inspectedSummaryId && !inspectedSummary) {
      autoSelectedDeletedSummaryRef.current = false;
      setInspectedSummaryId(null);
    }
  }, [inspectedSummary, inspectedSummaryId]);

  useEffect(() => {
    setCopyStatus("Copy");
  }, [exportOpen, exportText]);

  useEffect(() => {
    if (selectedTraceId && !selectedTrace) {
      setSelectedTraceId(null);
    }
  }, [selectedTrace, selectedTraceId]);

  const selectTrace = useCallback((traceId: string) => {
    setSelectedTraceId(traceId);
  }, []);

  const handleNodeKeyDown = useCallback(
    (event: React.KeyboardEvent<SVGGElement>, traceId: string) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectTrace(traceId);
      }
    },
    [selectTrace],
  );

  const layout = useMemo(() => {
    const root = d3.hierarchy(buildTree(visibleTraces), (datum: TraceDatum) => datum.children);
    const tree = d3.tree<TraceDatum>().nodeSize([34, 190]);
    const positioned = tree(root);
    const nodes = positioned
      .descendants()
      .filter((node) => node.data.trace.trace_id !== "__root__");
    const links = positioned
      .links()
      .filter((link) => link.target.data.trace.trace_id !== "__root__");
    const minX = Math.min(0, ...nodes.map((node) => node.x));
    const maxX = Math.max(220, ...nodes.map((node) => node.x));
    const maxY = Math.max(360, ...nodes.map((node) => node.y));

    return {
      links,
      nodes,
      viewBox: `${minX - 70} -34 ${maxY + 330} ${maxX - minX + 92}`,
    };
  }, [visibleTraces]);

  useEffect(() => {
    const svg = svgRef.current;
    if (!open || !svg) {
      return;
    }

    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.45, 3])
      .filter((event) => {
        if (event.type === "wheel") {
          return true;
        }
        const target = event.target as Element | null;
        return !target?.closest?.(".trace-node");
      })
      .on("zoom", (event) => {
        viewportRef.current?.setAttribute("transform", event.transform.toString());
      });

    const selection = d3.select(svg);
    selection.call(zoom);
    selection.on("dblclick.zoom", null);
    zoomRef.current = zoom;

    return () => {
      selection.on(".zoom", null);
      zoomRef.current = null;
    };
  }, [open]);

  const zoomBy = useCallback((factor: number) => {
    const svg = svgRef.current;
    const zoom = zoomRef.current;
    if (!svg || !zoom) {
      return;
    }
    d3.select(svg).call(zoom.scaleBy, factor);
  }, []);

  const resetZoom = useCallback(() => {
    const svg = svgRef.current;
    const zoom = zoomRef.current;
    if (!svg || !zoom) {
      return;
    }
    d3.select(svg).call(zoom.transform, d3.zoomIdentity);
  }, []);

  const showDeletedSummary = useCallback((summary: TraceSummary) => {
    const archivedTraces = archivedTracesForSummary(summary);
    if (archivedTraces.length === 0) {
      return;
    }
    autoSelectedDeletedSummaryRef.current = false;
    setPreferLiveWhenEmpty(false);
    setInspectedSummaryId(summary.summary_id);
    setSelectedTraceId(summary.deleted_trace_id);
    resetZoom();
  }, [resetZoom]);

  const showLiveTraces = useCallback(() => {
    autoSelectedDeletedSummaryRef.current = false;
    setPreferLiveWhenEmpty(true);
    setInspectedSummaryId(null);
    setSelectedTraceId(null);
    resetZoom();
  }, [resetZoom]);

  useEffect(() => {
    if (traces.length > 0) {
      setPreferLiveWhenEmpty(false);
      if (autoSelectedDeletedSummaryRef.current && inspectedSummaryId) {
        autoSelectedDeletedSummaryRef.current = false;
        setInspectedSummaryId(null);
        setSelectedTraceId(null);
      }
      return;
    }

    if (preferLiveWhenEmpty || inspectedSummaryId || !restorableSummary) {
      return;
    }

    setPreferLiveWhenEmpty(false);
    autoSelectedDeletedSummaryRef.current = true;
    setInspectedSummaryId(restorableSummary.summary_id);
    setSelectedTraceId(restorableSummary.deleted_trace_id);
    resetZoom();
  }, [inspectedSummaryId, preferLiveWhenEmpty, resetZoom, restorableSummary, traces.length]);

  const copyExport = useCallback(async () => {
    setCopyStatus("Copy");
    if (navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(exportText);
        setCopyStatus("Copied");
        return;
      } catch {
        // Fall back to selecting the text so the user can copy with the keyboard.
      }
    }

    const textarea = exportTextRef.current;
    if (!textarea) {
      return;
    }
    textarea.focus();
    textarea.select();
    try {
      document.execCommand("copy");
      setCopyStatus("Copied");
    } catch {
      setCopyStatus("Selected");
    }
  }, [exportText]);

  useEffect(() => {
    const liveTraceIds = new Set(traces.map((trace) => trace.trace_id));
    const pendingTraceIds = [
      pendingArchiveTraceIdRef.current,
      ...pendingArchiveTraceIdsRef.current,
    ].filter((traceId, index, traceIds): traceId is string => {
      return Boolean(traceId) && traceIds.indexOf(traceId) === index;
    });

    for (const traceId of pendingTraceIds) {
      if (!liveTraceIds.has(traceId)) {
        continue;
      }
      pendingArchiveTraceIdsRef.current.delete(traceId);
      if (pendingArchiveTraceIdRef.current === traceId) {
        pendingArchiveTraceIdRef.current = null;
      }
      if (autoSelectedDeletedSummaryRef.current && inspectedSummaryId) {
        autoSelectedDeletedSummaryRef.current = false;
        setInspectedSummaryId(null);
      }
    }

    const unresolvedPendingTraceIds = pendingTraceIds.filter((traceId) => !liveTraceIds.has(traceId));
    if (unresolvedPendingTraceIds.length === 0) {
      return;
    }

    for (const traceId of unresolvedPendingTraceIds) {
      const summary =
        summaries.find(
          (item) =>
            item.deleted_trace_id === traceId &&
            archivedTracesForSummary(item).some((trace) => trace.trace_id === traceId),
        ) ??
        summaries.find((item) => item.deleted_trace_ids?.includes(traceId)) ??
        summaries.find((item) =>
          archivedTracesForSummary(item).some((trace) => trace.trace_id === traceId),
        );

      if (!summary || archivedTracesForSummary(summary).length === 0) {
        continue;
      }

      pendingArchiveTraceIdsRef.current.delete(traceId);
      if (pendingArchiveTraceIdRef.current === traceId) {
        pendingArchiveTraceIdRef.current = null;
      }
      autoSelectedDeletedSummaryRef.current = true;
      setPreferLiveWhenEmpty(false);
      setInspectedSummaryId(summary.summary_id);
      setSelectedTraceId(traceId);
      resetZoom();
      return;
    }
  }, [inspectedSummaryId, resetZoom, summaries, traces]);

  const deleteTrace = useCallback(
    (traceId: string) => {
      if (pendingArchiveTraceIdsRef.current.has(traceId)) {
        return;
      }
      pendingArchiveTraceIdsRef.current.add(traceId);
      pendingArchiveTraceIdRef.current = traceId;
      setPreferLiveWhenEmpty(false);
      onDeleteTrace?.(traceId);
    },
    [onDeleteTrace],
  );

  const applyPanelPosition = useCallback(() => {
    panelFrameRef.current = null;
    const overlay = overlayRef.current;
    if (!overlay) {
      return;
    }
    const { x, y } = panelPositionRef.current;
    overlay.style.transform = `translate3d(${x}px, ${y}px, 0)`;
  }, []);

  const schedulePanelPosition = useCallback(
    (x: number, y: number) => {
      panelPositionRef.current = { x, y };
      if (panelFrameRef.current == null) {
        panelFrameRef.current = window.requestAnimationFrame(applyPanelPosition);
      }
    },
    [applyPanelPosition],
  );

  useEffect(
    () => () => {
      if (panelFrameRef.current != null) {
        window.cancelAnimationFrame(panelFrameRef.current);
      }
    },
    [],
  );

  const startDrag = (event: React.PointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) {
      return;
    }
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    dragRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      originX: panelPositionRef.current.x,
      originY: panelPositionRef.current.y,
    };
  };

  const drag = (event: React.PointerEvent<HTMLDivElement>) => {
    const current = dragRef.current;
    if (!current || current.pointerId !== event.pointerId) {
      return;
    }
    event.preventDefault();
    schedulePanelPosition(
      current.originX + event.clientX - current.startX,
      current.originY + event.clientY - current.startY,
    );
  };

  const stopDrag = (event: React.PointerEvent<HTMLDivElement>) => {
    const current = dragRef.current;
    if (!current || current.pointerId !== event.pointerId) {
      return;
    }
    dragRef.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  };

  return (
    <aside
      ref={overlayRef}
      className={`trace-overlay ${open ? "is-open" : ""}`}
      aria-live="polite"
    >
      <button
        type="button"
        className="trace-overlay__toggle"
        onClick={() => setOpen((value) => !value)}
      >
        Trace
        <span>{runningCount}</span>
      </button>

      {open ? (
        <div className="trace-overlay__panel">
          <div
            className="trace-overlay__header"
            onPointerDown={startDrag}
            onPointerMove={drag}
            onPointerUp={stopDrag}
            onPointerCancel={stopDrag}
          >
            <strong>
              <span className={`trace-overlay__live-dot ${runningCount > 0 ? "is-live" : ""}`} />
              Runtime Trace
              <em>{liveState}</em>
            </strong>
            <div className="trace-overlay__tools" onPointerDown={(event) => event.stopPropagation()}>
              {inspectedSummary ? (
                <button type="button" onClick={showLiveTraces} title="Return to live traces">
                  Live
                </button>
              ) : null}
              <button
                type="button"
                onClick={() => setGroupedView((value) => !value)}
                title={groupedView ? "Show individual traces" : "Group repeated traces"}
              >
                {groupedView ? "Raw" : "Grp"}
              </button>
              <button
                type="button"
                onClick={() => setExportOpen((value) => !value)}
                title="Export trace text"
              >
                Export
              </button>
              <button type="button" onClick={() => zoomBy(0.8)} title="Zoom out">
                -
              </button>
              <button type="button" onClick={resetZoom} title="Reset zoom">
                1:1
              </button>
              <button type="button" onClick={() => zoomBy(1.25)} title="Zoom in">
                +
              </button>
              <button type="button" onClick={onClearCompleted} title="Clear completed traces">
                Done
              </button>
              <button type="button" onClick={onClearFailed} title="Clear failed traces">
                Err
              </button>
              <select
                aria-label="Successful trace retention"
                value={retentionSeconds}
                onChange={(event) => onRetentionChange?.(Number(event.currentTarget.value))}
                title="Keep successful traces"
              >
                {retentionOptions.map((option) => (
                  <option key={option.seconds} value={option.seconds}>
                    {option.label}
                  </option>
                ))}
              </select>
              <span>{treeSourceTraces.length}</span>
            </div>
          </div>

          <div className="trace-overlay__body">
            <div className="trace-overlay__canvas">
              <svg ref={svgRef} viewBox={layout.viewBox} role="img" aria-label="Runtime trace tree">
                <g ref={viewportRef} className="trace-viewport">
                  <g className="trace-links">
                    {layout.links.map((link) => (
                      <path
                        key={`${link.source.data.trace.trace_id}-${link.target.data.trace.trace_id}`}
                        d={`M${link.source.y},${link.source.x}C${(link.source.y + link.target.y) / 2},${link.source.x} ${(link.source.y + link.target.y) / 2},${link.target.x} ${link.target.y},${link.target.x}`}
                      />
                    ))}
                  </g>

                  <g className="trace-nodes">
                    {layout.nodes.map((node) => {
                      const trace = node.data.trace;
                      const label = durationLabel(trace);
                      const selected = trace.trace_id === selectedTraceId;
                      return (
                        <g
                          key={trace.trace_id}
                          className={`trace-node ${selected ? "is-selected" : ""}`}
                          transform={`translate(${node.y},${node.x})`}
                          role="button"
                          tabIndex={0}
                          aria-label={`${trace.name} ${trace.status}`}
                          onClick={(event) => {
                            event.stopPropagation();
                            selectTrace(trace.trace_id);
                          }}
                          onKeyDown={(event) => handleNodeKeyDown(event, trace.trace_id)}
                        >
                          <circle className={statusClass[trace.status] ?? "trace-node--created"} r="7" />
                          <svg className="trace-node__clip" x="14" y="-18" width="156" height="38" overflow="hidden">
                            <text className="trace-node__name" x="0" y="14">
                              {trace.name}
                            </text>
                            <text className="trace-node__meta" x="0" y="31">
                              {trace.kind}{label ? ` | ${label}` : ""}
                            </text>
                          </svg>
                          <title>{trace.error ?? `${trace.name} (${trace.status})`}</title>
                        </g>
                      );
                    })}
                  </g>
                </g>
              </svg>

              {treeSourceTraces.length === 0 ? (
                <div className="trace-overlay__empty">
                  {inspectedSummary ? "No archived traces" : "Waiting for traces"}
                </div>
              ) : null}

              {limitedTraces.hiddenCount > 0 ? (
                <div className="trace-overlay__limit">
                  {limitedTraces.hiddenCount} traces hidden
                </div>
              ) : null}
            </div>

            <section className="trace-selection" aria-label="Selected trace">
              <div className="trace-failures__header">
                <strong>Selected Trace</strong>
                <span>{selectedTrace ? selectedTrace.status : "-"}</span>
              </div>
              {selectedTrace ? (
                <div className="trace-selection__body">
                  <strong title={selectedTrace.name}>{selectedTrace.name}</strong>
                  <dl>
                    <div>
                      <dt>Kind</dt>
                      <dd>{selectedTrace.kind}</dd>
                    </div>
                    <div>
                      <dt>Duration</dt>
                      <dd>{compactDuration(selectedTrace.duration_ms)}</dd>
                    </div>
                    <div>
                      <dt>Trace</dt>
                      <dd title={selectedTrace.trace_id}>
                        {isVirtualTrace(selectedTrace)
                          ? "group"
                          : isArchivedTrace(selectedTrace)
                            ? `arch ${selectedTrace.trace_id.slice(0, 6)}`
                            : selectedTrace.trace_id.slice(0, 8)}
                      </dd>
                    </div>
                  </dl>
                  {selectedTrace.error ? (
                    <p title={selectedTrace.error}>{selectedTrace.error}</p>
                  ) : null}
                  {!isVirtualTrace(selectedTrace) && !isArchivedTrace(selectedTrace) ? (
                    <button
                      type="button"
                      onClick={() => deleteTrace(selectedTrace.trace_id)}
                      title="Delete selected trace"
                    >
                      Delete
                    </button>
                  ) : null}
                </div>
              ) : (
                <p>No trace selected</p>
              )}
            </section>

            <section className="trace-failures" aria-label="Failed trace events">
              <div className="trace-failures__header">
                <strong>Failed Events</strong>
                <span>{failedTraceCount}</span>
              </div>
              {failedTraces.length === 0 ? (
                <p>No failed traces</p>
              ) : (
                <ul>
                  {failedTraces.map((trace) => (
                    <li
                      key={trace.trace_id}
                      className={trace.trace_id === selectedTraceId ? "is-selected" : ""}
                      role="button"
                      tabIndex={0}
                      onClick={() => selectTrace(trace.trace_id)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          selectTrace(trace.trace_id);
                        }
                      }}
                    >
                      <span className="trace-failures__name" title={trace.name}>
                        {trace.name}
                      </span>
                      <span className="trace-failures__error" title={trace.error ?? undefined}>
                        {trace.error ?? trace.status}
                      </span>
                      <button
                        type="button"
                        onClick={(event) => {
                          event.stopPropagation();
                          deleteTrace(trace.trace_id);
                        }}
                        title="Delete failed trace"
                      >
                        x
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section className="trace-summaries" aria-label="Deleted trace timing summaries">
              <div className="trace-failures__header">
                <strong>Deleted Averages</strong>
                <span>{summaries.length}</span>
              </div>
              {visibleSummaries.length === 0 ? (
                <p>No deleted traces</p>
              ) : (
                <ul>
                  {visibleSummaries.map((summary) => {
                    const archivedCount = archivedTracesForSummary(summary).length;
                    const selected = summary.summary_id === inspectedSummaryId;
                    return (
                      <li
                        key={summary.summary_id}
                        className={selected ? "is-selected" : ""}
                        role="button"
                        tabIndex={archivedCount > 0 ? 0 : -1}
                        onClick={() => showDeletedSummary(summary)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            showDeletedSummary(summary);
                          }
                        }}
                      >
                        <span className="trace-failures__name" title={summary.name}>
                          {summary.name}
                        </span>
                        <span className="trace-summary__stats">
                          avg {compactDuration(summary.avg_duration_ms)}
                          <b className={(summary.delta_avg_duration_ms ?? 0) > 0 ? "is-slower" : "is-faster"}>
                            {deltaLabel(summary.delta_avg_duration_ms)}
                          </b>
                        </span>
                        <span className="trace-failures__error" title={summary.error ?? undefined}>
                          {summary.sample_count} samples | {archivedCount} archived
                          {summary.status === "failed" ? " | failed" : ""}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              )}
            </section>
          </div>

          {exportOpen ? (
            <section className="trace-export" aria-label="Copyable trace export">
              <div className="trace-export__header">
                <strong>Trace Export</strong>
                <button type="button" onClick={copyExport}>
                  {copyStatus}
                </button>
              </div>
              <textarea
                ref={exportTextRef}
                readOnly
                value={exportText}
                onFocus={(event) => event.currentTarget.select()}
              />
            </section>
          ) : null}
        </div>
      ) : null}
    </aside>
  );
}
