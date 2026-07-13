import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as d3 from "d3";
import {
  formatTraceExport,
  restoreVisibleTraceParents,
  type PerformanceEvent,
  type GroupSnapshot,
  type TraceRecord,
  type TraceSummary,
} from "./trace";

type TraceDatum = {
  trace: TraceRecord;
  children: TraceDatum[];
};

type TraceOverlayProps = {
  tasks: TraceRecord[];
  groups?: GroupSnapshot[];
  performanceEvents?: PerformanceEvent[];
  summaries?: TraceSummary[];
  onClearCompleted?: () => void;
  onClearFailed?: () => void;
  onDeleteTask?: (taskId: string) => void;
};

const statusClass: Record<string, string> = {
  created: "trace-node--created",
  running: "trace-node--running",
  completed: "trace-node--completed",
  success: "trace-node--completed",
  failed: "trace-node--failed",
  error: "trace-node--failed",
  cancelled: "trace-node--cancelled",
};

const MAX_RENDERED_TRACES = 300;
const MAX_SIDE_ITEMS = 50;
const DENSE_SIBLING_GROUP_THRESHOLD = 12;

function durationLabel(trace: TraceRecord) {
  const avgDuration = numberMetadata(trace, "avg_duration_ms");
  const callCount = numberMetadata(trace, "call_count");
  if (callCount != null && callCount > 1 && avgDuration != null) {
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
  return trace.task_id.startsWith("ui-group:");
}

function isArchivedTrace(trace: TraceRecord) {
  return trace.metadata.archived_trace === true;
}

function archivedTracesForSummary(summary: TraceSummary | null | undefined) {
  if (!summary) {
    return [];
  }
  if (Array.isArray(summary.archived_tasks) && summary.archived_tasks.length > 0) {
    return summary.archived_tasks;
  }
  return summary.deleted_task ? [summary.deleted_task] : [];
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

export function groupTraceRecords(traces: TraceRecord[]) {
  const childParents = new Set(traces.map((trace) => trace.parent_task_id).filter(Boolean));
  const denseSiblingCounts = new Map<string, number>();
  for (const trace of traces) {
    if (childParents.has(trace.task_id) || isFailedTrace(trace)) {
      continue;
    }
    const key = denseSiblingKey(trace);
    denseSiblingCounts.set(key, (denseSiblingCounts.get(key) ?? 0) + 1);
  }
  const grouped = new Map<string, TraceRecord[]>();
  const output: TraceRecord[] = [];

  for (const trace of traces) {
    const isLeaf = !childParents.has(trace.task_id);
    const isBackendGroup = trace.metadata.trace_group === true;
    if (!isLeaf || isBackendGroup || isFailedTrace(trace)) {
      output.push(trace);
      continue;
    }

    const denseKey = denseSiblingKey(trace);
    const key = (denseSiblingCounts.get(denseKey) ?? 0) >= DENSE_SIBLING_GROUP_THRESHOLD
      ? denseKey
      : [denseKey, trace.name].join("|");
    const bucket = grouped.get(key) ?? [];
    bucket.push(trace);
    grouped.set(key, bucket);
  }

  for (const [key, records] of grouped) {
    const first = records[0];
    if (!first) {
      continue;
    }
    if (records.length === 1) {
      output.push(first);
      continue;
    }

    const totalDuration = records.reduce((sum, trace) => sum + (trace.duration_ms ?? 0), 0);
    const groupedStatus = statusForGroup(records);
    const sameName = records.every((record) => record.name === first.name);
    const virtualName = sameName ? first.name : `${first.kind} operations`;
    output.push({
      ...first,
      task_id: `ui-group:${key}`,
      name: virtualName,
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
          at: first.created_at,
          event: "grouped",
          status: groupedStatus,
          duration_ms: totalDuration,
        },
      ],
    });
  }

  return output.sort((a, b) => a.created_at - b.created_at);
}

function denseSiblingKey(trace: TraceRecord) {
  return [trace.parent_task_id ?? "root", trace.kind, trace.status].join("|");
}

function limitTraceRecords(traces: TraceRecord[], selectedTaskId: string | null) {
  if (traces.length <= MAX_RENDERED_TRACES) {
    return { hiddenCount: 0, records: traces };
  }

  const byId = new Map(traces.map((trace) => [trace.task_id, trace]));
  const included = new Set<string>();

  const includeWithAncestors = (trace: TraceRecord | undefined) => {
    let current = trace;
    while (current && !included.has(current.task_id) && included.size < MAX_RENDERED_TRACES) {
      included.add(current.task_id);
      current = current.parent_task_id ? byId.get(current.parent_task_id) : undefined;
    }
  };

  for (const trace of traces) {
    if (trace.task_id === selectedTaskId || isFailedTrace(trace) || trace.status === "running") {
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

  const records = traces.filter((trace) => included.has(trace.task_id));
  return { hiddenCount: traces.length - records.length, records };
}

function buildTree(traces: TraceRecord[]) {
  const root: TraceDatum = {
    trace: {
      trace_id: "__root__",
      task_id: "__root__",
      parent_task_id: null,
      name: "Runtime",
      kind: "root",
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
    byId.set(trace.task_id, { trace, children: [] });
  }

  for (const trace of traces) {
    const node = byId.get(trace.task_id);
    if (!node) {
      continue;
    }
    const parent = trace.parent_task_id ? byId.get(trace.parent_task_id) : null;
    (parent ?? root).children.push(node);
  }

  return root;
}

export function TraceOverlay({
  tasks = [],
  groups: _groups = [],
  performanceEvents: _performanceEvents = [],
  summaries = [],
  onClearCompleted,
  onClearFailed,
  onDeleteTask,
}: TraceOverlayProps) {
  const [open, setOpen] = useState(true);
  const [groupedView, setGroupedView] = useState(true);
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null);
  const [inspectedSummaryId, setInspectedSummaryId] = useState<string | null>(null);
  const [preferLiveWhenEmpty, setPreferLiveWhenEmpty] = useState(true);
  const [exportOpen, setExportOpen] = useState(false);
  const [copyStatus, setCopyStatus] = useState<"Copy" | "Copied" | "Selected">("Copy");
  const overlayRef = useRef<HTMLElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const viewportRef = useRef<SVGGElement | null>(null);
  const exportTextRef = useRef<HTMLTextAreaElement | null>(null);
  const zoomRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const panelPositionRef = useRef({ x: 0, y: 0 });
  const panelFrameRef = useRef<number | null>(null);
  const pendingArchiveTaskIdRef = useRef<string | null>(null);
  const pendingArchiveTaskIdsRef = useRef<Set<string>>(new Set());
  const dragRef = useRef<{
    pointerId: number;
    startX: number;
    startY: number;
    originX: number;
    originY: number;
  } | null>(null);
  const liveTasks = tasks;
  const runningCount = useMemo(
    () => liveTasks.filter((trace) => trace.status === "running").length,
    [liveTasks],
  );
  const failedTraceRecords = useMemo(
    () => liveTasks.filter(isFailedTrace).sort((a, b) => b.created_at - a.created_at),
    [liveTasks],
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
    return liveTasks.length === 0 && !preferLiveWhenEmpty ? restorableSummary : null;
  }, [inspectedSummaryId, liveTasks.length, preferLiveWhenEmpty, restorableSummary, summaries]);
  const inspectedTraces = useMemo(
    () => archivedTracesForSummary(inspectedSummary),
    [inspectedSummary],
  );
  const repairedLiveTraces = useMemo(
    () => restoreVisibleTraceParents(liveTasks, summaries),
    [liveTasks, summaries],
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
        : limitTraceRecords(groupedTraces, selectedTaskId),
    [groupedTraces, inspectedSummary, selectedTaskId],
  );
  const visibleTraces = limitedTraces.records;
  const visibleTraceById = useMemo(
    () => new Map(visibleTraces.map((trace) => [trace.task_id, trace])),
    [visibleTraces],
  );
  const visibleTraceShapeKey = useMemo(
    () =>
      visibleTraces
        .map((trace) => `${trace.task_id}:${trace.parent_task_id ?? ""}:${trace.created_at}`)
        .join("|"),
    [visibleTraces],
  );
  const selectedTrace = useMemo(
    () =>
      selectedTaskId
        ? visibleTraces.find((trace) => trace.task_id === selectedTaskId) ??
          inspectedTraces.find((trace) => trace.task_id === selectedTaskId) ??
          liveTasks.find((trace) => trace.task_id === selectedTaskId) ??
          null
        : null,
    [inspectedTraces, liveTasks, selectedTaskId, visibleTraces],
  );
  const selectedPerformanceMetrics = useMemo(
    () => performanceMetricsForTrace(selectedTrace),
    [selectedTrace],
  );
  const visibleSummaries = useMemo(
    () => summaries.slice(0, MAX_SIDE_ITEMS),
    [summaries],
  );
  const liveState = inspectedSummary
    ? "Deleted"
    : runningCount > 0
      ? "Live"
      : liveTasks.length > 0
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
      setInspectedSummaryId(null);
    }
  }, [inspectedSummary, inspectedSummaryId]);

  useEffect(() => {
    setCopyStatus("Copy");
  }, [exportOpen, exportText]);

  useEffect(() => {
    if (selectedTaskId && !selectedTrace) {
      setSelectedTaskId(null);
    }
  }, [selectedTrace, selectedTaskId]);

  const selectTrace = useCallback((taskId: string) => {
    setSelectedTaskId(taskId);
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
      .filter((node) => node.data.trace.task_id !== "__root__");
    const links = positioned
      .links()
      .filter((link) => link.target.data.trace.task_id !== "__root__");
    const minX = Math.min(0, ...nodes.map((node) => node.x));
    const maxX = Math.max(220, ...nodes.map((node) => node.x));
    const maxY = Math.max(360, ...nodes.map((node) => node.y));

    return {
      links,
      nodes,
      viewBox: `${minX - 70} -34 ${maxY + 330} ${maxX - minX + 92}`,
    };
  }, [visibleTraceShapeKey]);

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
    setPreferLiveWhenEmpty(false);
    setInspectedSummaryId(summary.summary_id);
    setSelectedTaskId(summary.deleted_task_id);
    resetZoom();
  }, [resetZoom]);

  const showLiveTraces = useCallback(() => {
    setPreferLiveWhenEmpty(true);
    setInspectedSummaryId(null);
    setSelectedTaskId(null);
    resetZoom();
  }, [resetZoom]);

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
    const liveTraceIds = new Set(liveTasks.map((trace) => trace.task_id));
    const pendingTraceIds = [
      pendingArchiveTaskIdRef.current,
      ...pendingArchiveTaskIdsRef.current,
    ].filter((traceId, index, traceIds): traceId is string => {
      return Boolean(traceId) && traceIds.indexOf(traceId) === index;
    });

    for (const traceId of pendingTraceIds) {
      if (!liveTraceIds.has(traceId)) {
        continue;
      }
      pendingArchiveTaskIdsRef.current.delete(traceId);
      if (pendingArchiveTaskIdRef.current === traceId) {
        pendingArchiveTaskIdRef.current = null;
      }
    }

    const unresolvedPendingTraceIds = pendingTraceIds.filter((traceId) => !liveTraceIds.has(traceId));
    if (unresolvedPendingTraceIds.length === 0) {
      return;
    }

    for (const traceId of unresolvedPendingTraceIds) {
      pendingArchiveTaskIdsRef.current.delete(traceId);
      if (pendingArchiveTaskIdRef.current === traceId) {
        pendingArchiveTaskIdRef.current = null;
      }
    }
  }, [inspectedSummaryId, liveTasks]);

  const deleteTask = useCallback(
    (traceId: string) => {
      if (pendingArchiveTaskIdsRef.current.has(traceId)) {
        return;
      }
      pendingArchiveTaskIdsRef.current.add(traceId);
      pendingArchiveTaskIdRef.current = traceId;
      setPreferLiveWhenEmpty(true);
      setInspectedSummaryId(null);
      onDeleteTask?.(traceId);
    },
    [onDeleteTask],
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
                        key={`${link.source.data.trace.task_id}-${link.target.data.trace.task_id}`}
                        d={`M${link.source.y},${link.source.x}C${(link.source.y + link.target.y) / 2},${link.source.x} ${(link.source.y + link.target.y) / 2},${link.target.x} ${link.target.y},${link.target.x}`}
                      />
                    ))}
                  </g>

                  <g className="trace-nodes">
                    {layout.nodes.map((node) => {
                      const trace =
                        visibleTraceById.get(node.data.trace.task_id) ?? node.data.trace;
                      const label = durationLabel(trace);
                      const selected = trace.task_id === selectedTaskId;
                      return (
                        <g
                          key={trace.task_id}
                          className={`trace-node ${selected ? "is-selected" : ""}`}
                          transform={`translate(${node.y},${node.x})`}
                          role="button"
                          tabIndex={0}
                          aria-label={`${trace.name} ${trace.status}`}
                          onClick={(event) => {
                            event.stopPropagation();
                            selectTrace(trace.task_id);
                          }}
                          onKeyDown={(event) => handleNodeKeyDown(event, trace.task_id)}
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
                      <dt>Task</dt>
                      <dd title={selectedTrace.task_id}>
                        {isVirtualTrace(selectedTrace)
                          ? "group"
                          : isArchivedTrace(selectedTrace)
                            ? `arch ${selectedTrace.task_id.slice(0, 6)}`
                            : selectedTrace.task_id.slice(0, 8)}
                      </dd>
                    </div>
                  </dl>
                  {selectedTrace.error ? (
                    <p title={selectedTrace.error}>{selectedTrace.error}</p>
                  ) : null}
                  <div className="trace-selection__performance">
                    <div>
                      <strong>Attached metrics</strong>
                      <span>{selectedPerformanceMetrics.length}</span>
                    </div>
                    {selectedPerformanceMetrics.length === 0 ? (
                      <p>No metrics attached to this trace</p>
                    ) : (
                      <ul>
                        {selectedPerformanceMetrics.map((metric) => (
                          <li key={metric.name}>
                            <span className="trace-failures__name" title={metric.name}>{metric.name}</span>
                            <span className="trace-performance__duration">
                              {metric.duration_count === 0 ? `${metric.count} marks` : `${metric.count} calls avg ${compactDuration(metric.avg_ms)}`}
                            </span>
                            <span className="trace-failures__error">
                              {metric.duration_count === 0 ? "no duration" : `min ${compactDuration(metric.min_ms)} | max ${compactDuration(metric.max_ms)}`}
                            </span>
                            {metric.metadataLabel ? (
                              <span className="trace-performance__metadata" title={metric.metadataLabel}>
                                {metric.metadataLabel}
                              </span>
                            ) : null}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                  {!isVirtualTrace(selectedTrace) && !isArchivedTrace(selectedTrace) ? (
                    <button
                      type="button"
                      onClick={() => deleteTask(selectedTrace.task_id)}
                      title="Delete selected task"
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
                      key={trace.task_id}
                      className={trace.task_id === selectedTaskId ? "is-selected" : ""}
                      role="button"
                      tabIndex={0}
                      onClick={() => selectTrace(trace.task_id)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          selectTrace(trace.task_id);
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
                          deleteTask(trace.task_id);
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

function performanceMetadataLabel(event: PerformanceEvent) {
  const metadata = event.metadata;
  const details = [
    typeof metadata.packet_kind === "string" ? metadata.packet_kind : null,
    typeof metadata.ssrc === "number" ? `ssrc ${metadata.ssrc}` : null,
    typeof metadata.sequence_number === "number" ? `seq ${metadata.sequence_number}` : null,
    typeof metadata.size_bytes === "number" ? `${metadata.size_bytes} B` : null,
    typeof metadata.error_stage === "string" ? metadata.error_stage : null,
  ].filter((value): value is string => value != null);
  return details.join(" · ") || "-";
}

type TracePerformanceMetric = {
  name: string;
  count: number;
  duration_count: number;
  avg_ms: number | null;
  min_ms: number | null;
  max_ms: number | null;
  metadataLabel: string;
};

function aggregateMetadataLabel(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "";
  return Object.entries(value as Record<string, unknown>)
    .map(([key, item]) => `${key.replaceAll("_", " ")}=${String(item)}`)
    .join(" · ");
}

function performanceMetricsForTrace(trace: TraceRecord | null): TracePerformanceMetric[] {
  const raw = trace?.metadata.performance_metrics;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return [];
  }
  return Object.entries(raw as Record<string, unknown>).flatMap(([name, value]) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return [];
    }
    const metric = value as Record<string, unknown>;
    return [{
      name,
      count: typeof metric.count === "number" ? metric.count : 0,
      duration_count: typeof metric.duration_count === "number" ? metric.duration_count : 0,
      avg_ms: typeof metric.avg_ms === "number" ? metric.avg_ms : null,
      min_ms: typeof metric.min_ms === "number" ? metric.min_ms : null,
      max_ms: typeof metric.max_ms === "number" ? metric.max_ms : null,
      metadataLabel: aggregateMetadataLabel(metric.metadata),
    }];
  });
}
