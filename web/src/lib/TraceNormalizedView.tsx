import { memo, useCallback, useMemo, useRef, useState } from "react";
import * as d3 from "d3";
import type {
  GroupSnapshot, TraceCapture, TraceControl, TraceEntity, TraceFacet, TraceMachine,
  TraceMachineTransition,
} from "./trace";

export const TRACE_GRAPH_NODE_LIMIT = 300;
export const TRACE_LIST_ROW_HEIGHT = 34;
export const TRACE_LIST_OVERSCAN = 6;

export type TraceDataKind =
  | "machine" | "transition" | "control" | "group" | "facet" | "capture" | "failure" | "diagnostic";

export type TraceDataRow = {
  id: string;
  ownerId: string | null;
  parentId: string | null;
  kind: TraceDataKind;
  name: string;
  value: string;
  revision: number;
  activityKind?: string;
  liveAgeMs?: number | null;
};

export type TraceTopologyNode = {
  id: string;
  parentId: string | null;
  x: number;
  y: number;
};

type NormalizedTraceViewProps = {
  machinesById: Map<string, TraceMachine>;
  entitiesById?: Map<string, TraceEntity>;
  transitions: TraceMachineTransition[];
  controlsById: Map<string, TraceControl>;
  groupsById: Map<number, GroupSnapshot>;
  facetsById: Map<string, TraceFacet>;
  capturesById?: Map<number, TraceCapture>;
  operationNamesById: Map<number, string>;
  diagnostics: Record<string, number>;
  topologyVersion: number;
  valueVersion: number;
  onRequestCapture?: (request: Record<string, unknown>) => void;
};

function compactValue(value: unknown) {
  if (typeof value === "string") return value;
  try {
    const encoded = JSON.stringify(value);
    return encoded.length > 160 ? `${encoded.slice(0, 157)}…` : encoded;
  } catch {
    return String(value);
  }
}

function finiteMetric(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

function formatMilliseconds(value: number) {
  if (value === 0) return "0ms";
  if (value >= 100) return `${Math.round(value)}ms`;
  if (value >= 10) return `${value.toFixed(1)}ms`;
  return `${value.toFixed(2)}ms`;
}

export function formatOperationSummary(group: GroupSnapshot) {
  const active = finiteMetric(group.in_flight);
  const calls = finiteMetric(group.calls);
  const parts = [
    active == null ? null : `${active} active`,
    calls == null ? null : `${calls} calls`,
  ];

  const outcomes: string[] = [];
  const successes = finiteMetric(group.successes);
  const errors = finiteMetric(group.errors);
  const cancellations = finiteMetric(group.cancellations);
  if (successes != null) outcomes.push(`${successes} ok`);
  if (errors != null) outcomes.push(`${errors} errors`);
  if (cancellations != null) outcomes.push(`${cancellations} cancelled`);
  if (outcomes.length) parts.push(outcomes.join(" / "));

  const average = finiteMetric(group.average_duration_ms);
  const minimum = finiteMetric(group.min_duration_ms);
  const maximum = finiteMetric(group.max_duration_ms);
  if (average != null) {
    const range = minimum != null && maximum != null
      ? ` (${formatMilliseconds(minimum)}–${formatMilliseconds(maximum)})`
      : "";
    parts.push(`avg ${formatMilliseconds(average)}${range}`);
  }

  const worker = finiteMetric(group.total_worker_ms);
  const queue = finiteMetric(group.total_queue_ms);
  if (worker != null) parts.push(`worker total ${formatMilliseconds(worker)}`);
  if (queue != null) parts.push(`queue total ${formatMilliseconds(queue)}`);
  return parts.filter((part): part is string => part != null).join(" · ");
}

export function buildTraceDataRows(props: Omit<NormalizedTraceViewProps, "topologyVersion" | "valueVersion">) {
  const rows: TraceDataRow[] = [];
  for (const machine of props.machinesById.values()) {
    const descriptor = props.entitiesById?.get(machine.entity_id);
    const cause = typeof machine.cause_id === "string" && props.machinesById.has(machine.cause_id)
      ? `machine:${machine.cause_id}`
      : null;
    rows.push({
      id: `machine:${machine.entity_id}`,
      ownerId: machine.entity_id,
      parentId: cause,
      kind: "machine",
      name: descriptor?.role && descriptor.role !== machine.machine_type
        ? `${machine.machine_type} (${descriptor.role}) · ${machine.entity_id}`
        : `${machine.machine_type} · ${machine.entity_id}`,
      value: machine.state,
      revision: machine.revision,
    });
  }
  for (const transition of props.transitions) {
    const cause = transition.cause_id == null ? "" : ` · cause ${transition.cause_id}`;
    rows.push({
      id: `transition:${transition.order}`,
      ownerId: transition.entity_id,
      parentId: `machine:${transition.entity_id}`,
      kind: "transition",
      name: `${transition.machine_type} transition #${transition.order}`,
      value: `${transition.from_state} → ${transition.to_state}${cause}`,
      revision: transition.revision,
    });
  }
  for (const control of props.controlsById.values()) {
    rows.push({
      id: `control:${control.handle_id}`,
      ownerId: control.owner_entity_id,
      parentId: `machine:${control.owner_entity_id}`,
      kind: "control",
      name: control.name,
      value: control.cancelable ? "cancelable" : "observed",
      revision: control.revision,
    });
  }
  for (const group of props.groupsById.values()) {
    if (typeof group.group_id !== "number") continue;
    const operation = typeof group.operation_id === "number"
      ? props.operationNamesById.get(group.operation_id) ?? group.operation
      : group.operation;
    const owner = group.owner_entity_id ?? null;
    const parent = group.parent_ref_type === "group" && group.parent_ref_id != null
      ? `group:${group.parent_ref_id}`
      : owner ? `machine:${owner}` : null;
    rows.push({
      id: `group:${group.group_id}`,
      ownerId: owner,
      parentId: parent,
      kind: "group",
      name: operation || group.group,
      value: formatOperationSummary(group),
      revision: group.revision ?? 0,
      activityKind: group.activity_kind ?? "request",
      liveAgeMs: group.live_age_ms,
    });
    for (const [index, exemplar] of (group.exemplars ?? []).entries()) {
      const outcome = exemplar.outcome ?? exemplar.exception ?? exemplar.error;
      if (outcome == null || outcome === "success") continue;
      rows.push({
        id: `failure:${group.group_id}:${group.revision ?? 0}:${index}`,
        ownerId: owner,
        parentId: `group:${group.group_id}`,
        kind: "failure",
        name: operation || group.group,
        value: compactValue(exemplar),
        revision: group.revision ?? 0,
      });
    }
  }
  for (const facet of props.facetsById.values()) {
    rows.push({
      id: `facet:${facet.facet_id}`,
      ownerId: facet.owner_entity_id,
      parentId: `machine:${facet.owner_entity_id}`,
      kind: "facet",
      name: facet.facet_id,
      value: compactValue(facet.value),
      revision: facet.revision,
    });
  }
  for (const capture of (props.capturesById ?? new Map()).values()) {
    rows.push({
      id: `capture:${capture.record_id}`,
      ownerId: capture.owner_entity_id,
      parentId: `machine:${capture.owner_entity_id}`,
      kind: "capture",
      name: `[CAPTURE #${capture.capture_id}] ${capture.operation}`,
      value: `${capture.outcome} · ${capture.duration_ms.toFixed(2)}ms${capture.failure_class ? ` · ${capture.failure_class}` : ""}`,
      revision: capture.revision,
    });
  }
  for (const [name, value] of Object.entries(props.diagnostics)) {
    rows.push({
      id: `diagnostic:${name}`,
      ownerId: null,
      parentId: null,
      kind: "diagnostic",
      name,
      value: String(value),
      revision: 0,
    });
  }
  return rows;
}

export function filterTraceDataRows(rows: TraceDataRow[], query: string, kind: "all" | TraceDataKind) {
  const normalized = query.trim().toLocaleLowerCase();
  return rows.filter((row) =>
    (kind === "all" || row.kind === kind) &&
    (!normalized || `${row.name} ${row.value} ${row.ownerId ?? ""}`.toLocaleLowerCase().includes(normalized)),
  );
}

export function formatNormalizedTraceExport(
  rows: TraceDataRow[], entitiesById: Map<string, TraceEntity> = new Map(),
) {
  const kinds: TraceDataKind[] = [
    "machine", "transition", "control", "group", "facet", "capture", "failure", "diagnostic",
  ];
  const counts = new Map(kinds.map((kind) => [kind, 0]));
  for (const row of rows) counts.set(row.kind, (counts.get(row.kind) ?? 0) + 1);

  const ownerAliases = new Map<string, string>(
    [...entitiesById].map(([id, entity]) => [id, entity.alias]),
  );
  for (const row of rows) {
    if (row.ownerId && !ownerAliases.has(row.ownerId)) {
      ownerAliases.set(row.ownerId, `@${ownerAliases.size + 1}`);
    }
  }
  const sanitize = createExportSanitizer(entitiesById);
  const owner = (row: TraceDataRow) => {
    if (!row.ownerId) return "";
    const alias = ownerAliases.get(row.ownerId);
    const entity = entitiesById.get(row.ownerId);
    const semantic = entity
      ? ` ${sanitize(entity.role)}${entity.kind === "machine" ? "" : `, ${sanitize(entity.kind)}`}`
      : "";
    return ` [${alias}]${semantic}`;
  };
  const lines = [
    "WebRTC runtime trace (schema 2, compact LLM summary)",
    `${rows.length} records: ${kinds.flatMap((kind) => {
      const count = counts.get(kind) ?? 0;
      return count ? [`${count} ${kind}`] : [];
    }).join(", ")}`,
  ];

  const sections: Array<[TraceDataKind, string]> = [
    ["machine", "Machine state"],
    ["transition", "Machine transitions"],
    ["control", "Controls"],
    ["group", "Operations"],
    ["facet", "State facets"],
    ["capture", "Diagnostic captures"],
    ["failure", "Failures"],
    ["diagnostic", "Diagnostics"],
  ];
  for (const [kind, title] of sections) {
    const matching = rows.filter((row) => row.kind === kind);
    if (!matching.length) continue;
    lines.push("", `${title}:`);
    if (kind === "group") {
      appendOperationHierarchy(lines, matching, owner, sanitize);
    } else if (kind === "transition") {
      appendGroupedExportRows(lines, matching, owner, (row) =>
        sanitize(row.value.replace(/ · cause .*$/, "")),
      );
    } else if (kind === "facet" || kind === "diagnostic") {
      appendGroupedExportRows(lines, matching, owner, (row) =>
        `${sanitize(row.name)}=${sanitize(row.value)}`,
      );
    } else {
      for (const row of matching) {
        const name = kind === "machine" && row.ownerId
          ? row.name.replace(` · ${row.ownerId}`, "")
          : kind === "capture"
            ? row.name.replace(/^\[CAPTURE #[^\]]+\] /, "")
            : row.name;
        const marker = kind === "capture" ? " [diagnostic capture]" : kind === "failure" ? " [failure exemplar]" : "";
        lines.push(`- ${sanitize(name)}${owner(row)}: ${sanitize(row.value)}${marker}`);
      }
    }
  }
  return lines.join("\n");
}

function appendGroupedExportRows(
  lines: string[],
  rows: TraceDataRow[],
  owner: (row: TraceDataRow) => string,
  format: (row: TraceDataRow) => string,
) {
  const groups = new Map<string, TraceDataRow[]>();
  for (const row of rows) {
    const key = row.ownerId ?? "";
    const group = groups.get(key) ?? [];
    group.push(row);
    groups.set(key, group);
  }
  for (const group of groups.values()) {
    const first = group[0];
    if (!first) continue;
    const label = owner(first).trim();
    lines.push(`- ${label ? `${label}: ` : ""}${group.map(format).join("; ")}`);
  }
}

function appendOperationHierarchy(
  lines: string[],
  rows: TraceDataRow[],
  owner: (row: TraceDataRow) => string,
  sanitize: (value: string) => string,
) {
  const byId = new Map(rows.map((row) => [row.id, row]));
  const children = new Map<string, TraceDataRow[]>();
  const roots: TraceDataRow[] = [];
  for (const row of rows) {
    if (row.parentId && byId.has(row.parentId) && row.parentId !== row.id) {
      const bucket = children.get(row.parentId) ?? [];
      bucket.push(row);
      children.set(row.parentId, bucket);
    } else {
      roots.push(row);
    }
  }

  const emitted = new Set<string>();
  const append = (row: TraceDataRow, depth: number) => {
    if (emitted.has(row.id)) return;
    emitted.add(row.id);
    lines.push(
      `${"  ".repeat(depth)}- ${sanitize(row.name)}${
        depth === 0 || row.ownerId !== byId.get(row.parentId ?? "")?.ownerId ? owner(row) : ""
      }: ` + sanitize(compactOperationExportValue(row)),
    );
    for (const child of children.get(row.id) ?? []) append(child, depth + 1);
  };
  for (const root of roots) append(root, 0);
  // Malformed legacy parent cycles still remain exportable exactly once.
  for (const row of rows) append(row, 0);
}

type AliasTrie = { next: Map<string, AliasTrie>; alias?: string };

function createExportSanitizer(entitiesById: Map<string, TraceEntity>) {
  const root: AliasTrie = { next: new Map() };
  for (const entity of entitiesById.values()) {
    let node = root;
    for (const character of entity.entity_id) {
      let child = node.next.get(character);
      if (!child) {
        child = { next: new Map() };
        node.next.set(character, child);
      }
      node = child;
    }
    node.alias = entity.alias;
  }
  return (value: string) => {
    let sanitized = "";
    const characters = [...value];
    for (let index = 0; index < characters.length;) {
      let node = root;
      let cursor = index;
      let alias: string | undefined;
      let end = index;
      while (cursor < characters.length) {
        const child = node.next.get(characters[cursor]!);
        if (!child) break;
        node = child;
        cursor += 1;
        if (node.alias) {
          alias = node.alias;
          end = cursor;
        }
      }
      if (alias) {
        sanitized += alias;
        index = end;
      } else {
        sanitized += characters[index];
        index += 1;
      }
    }
    return sanitized
      .replace(/\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b/gi, "<id>")
      .replace(/\b[0-9a-f]{24,64}\b/gi, "<id>");
  };
}

function compactOperationExportValue(row: TraceDataRow) {
  const parts = row.value.split(" · ");
  const compact: string[] = [];
  for (const part of parts) {
    if (/^\d+ calls$/.test(part)) compact.push(part);
    else if (/^[1-9]\d* active$/.test(part)) compact.push(part);
    else if (part.includes(" errors") || part.includes(" cancelled")) {
      const failures = part.split(" / ").filter((outcome) =>
        !outcome.endsWith(" ok") && !outcome.startsWith("0 "),
      );
      if (failures.length) compact.push(failures.join(" / "));
    }
  }
  const active = parts.some((part) => /^[1-9]\d* active$/.test(part));
  const kind = ["pump", "wait", "long-running"].includes(row.activityKind ?? "")
    ? row.activityKind! : "request";
  if (kind !== "request") {
    compact.unshift(`[${kind}${active ? " expected active" : ""}]`);
  } else if (active) {
    compact.unshift("[request unexpectedly active]");
  }
  if (active) compact.push(`live incomplete age ${boundedAge(row.liveAgeMs)}`);
  return compact.join(" · ") || row.value;
}

function boundedAge(age: number | null | undefined) {
  if (typeof age !== "number" || !Number.isFinite(age) || age < 0) return "unknown";
  if (age < 1_000) return "<1s";
  if (age < 10_000) return "1–10s";
  if (age < 60_000) return "10–60s";
  return "≥60s";
}

async function writeClipboardText(text: string) {
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  if (typeof document === "undefined") throw new Error("Clipboard is unavailable");
  const field = document.createElement("textarea");
  field.value = text;
  field.setAttribute("readonly", "");
  field.style.position = "fixed";
  field.style.opacity = "0";
  document.body.appendChild(field);
  field.select();
  const copied = document.execCommand("copy");
  field.remove();
  if (!copied) throw new Error("Clipboard copy failed");
}

export async function copyTraceExport(
  text: string,
  writeText: (value: string) => Promise<void> = writeClipboardText,
) {
  await writeText(text);
}

export function stabilizeTraceDataRows(rows: TraceDataRow[], cache: Map<string, TraceDataRow>) {
  const active = new Set<string>();
  const stable = rows.map((row) => {
    active.add(row.id);
    const previous = cache.get(row.id);
    if (
      previous && previous.revision === row.revision && previous.name === row.name &&
      previous.value === row.value && previous.ownerId === row.ownerId &&
      previous.parentId === row.parentId && previous.kind === row.kind
    ) return previous;
    cache.set(row.id, row);
    return row;
  });
  for (const id of cache.keys()) if (!active.has(id)) cache.delete(id);
  return stable;
}

export function virtualTraceWindow(
  count: number,
  scrollTop: number,
  viewportHeight: number,
  rowHeight = TRACE_LIST_ROW_HEIGHT,
  overscan = TRACE_LIST_OVERSCAN,
) {
  const start = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const end = Math.min(count, Math.ceil((scrollTop + viewportHeight) / rowHeight) + overscan);
  return { start, end, offset: start * rowHeight, totalHeight: count * rowHeight };
}

export function selectBoundedTopology(rows: TraceDataRow[], selectedId: string | null, limit = TRACE_GRAPH_NODE_LIMIT) {
  if (rows.length <= limit) return rows;

  // Keep every independent root visible whenever it fits. If the safety cap is
  // reached, prioritize the selected record while retaining deterministic row
  // order for the rest of the graph.
  const selected = selectedId ? rows.find((row) => row.id === selectedId) : undefined;
  if (!selected) return rows.slice(0, limit);
  return [selected, ...rows.filter((row) => row.id !== selected.id)].slice(0, limit);
}

export function layoutTraceTopology(rows: TraceDataRow[]): { nodes: TraceTopologyNode[]; viewBox: string } {
  const ids = new Set(rows.map((row) => row.id));
  const roots = rows.filter((row) => !row.parentId || !ids.has(row.parentId));
  const children = new Map<string, TraceDataRow[]>();
  for (const row of rows) {
    if (row.parentId && ids.has(row.parentId)) {
      const bucket = children.get(row.parentId) ?? [];
      bucket.push(row);
      children.set(row.parentId, bucket);
    }
  }
  const synthetic = { id: "__root__", parentId: null as string | null };
  const hierarchy = d3.hierarchy(synthetic, (node) => {
    if (node.id === "__root__") return roots;
    return children.get(node.id) ?? [];
  });
  const positioned = d3.tree<{ id: string; parentId: string | null }>().nodeSize([38, 180])(hierarchy);
  const nodes = positioned.descendants().slice(1).map((node) => ({
    id: node.data.id,
    parentId: node.data.parentId,
    x: node.x,
    y: node.y,
  }));
  const minX = Math.min(0, ...nodes.map((node) => node.x));
  const maxX = Math.max(180, ...nodes.map((node) => node.x));
  const maxY = Math.max(320, ...nodes.map((node) => node.y));
  return { nodes, viewBox: `${minX - 50} -30 ${maxY + 300} ${maxX - minX + 70}` };
}

const SvgNode = memo(function SvgNode({
  geometry, row, selected, onSelect,
}: {
  geometry: TraceTopologyNode;
  row: TraceDataRow;
  selected: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <g
      className={`trace-node ${selected ? "is-selected" : ""}`}
      transform={`translate(${geometry.y},${geometry.x})`}
      role="button"
      tabIndex={0}
      onClick={() => onSelect(row.id)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") onSelect(row.id);
      }}
    >
      <circle className={`trace-normalized-node--${row.kind}`} r="7" />
      <text className="trace-node__name" x="14" y="-2">{row.name}</text>
      <text className="trace-node__meta" x="14" y="13">{row.value}</text>
    </g>
  );
});

export function NormalizedTraceView(props: NormalizedTraceViewProps) {
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<"all" | TraceDataKind>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [exportOpen, setExportOpen] = useState(false);
  const [copyStatus, setCopyStatus] = useState<"idle" | "copied" | "failed">("idle");
  const viewportRef = useRef<SVGGElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const stableRowsRef = useRef(new Map<string, TraceDataRow>());

  const rows = useMemo(
    () => stabilizeTraceDataRows(buildTraceDataRows(props), stableRowsRef.current),
    [props.machinesById, props.transitions, props.controlsById, props.groupsById, props.facetsById,
      props.capturesById, props.operationNamesById, props.diagnostics, props.valueVersion],
  );
  const filtered = useMemo(() => filterTraceDataRows(rows, query, kind), [rows, query, kind]);
  const windowed = virtualTraceWindow(filtered.length, scrollTop, 240);
  const topologyRows = useMemo(
    () => selectBoundedTopology(rows, selectedId),
    // Cardinality is an inexpensive guard for snapshots, incremental inserts,
    // and development Fast Refresh. Value-only patches keep the same length and
    // therefore do not trigger SVG topology/layout work.
    [props.topologyVersion, rows.length, selectedId],
  );
  const layout = useMemo(
    () => layoutTraceTopology(topologyRows),
    [topologyRows],
  );
  const rowsById = useMemo(() => new Map(rows.map((row) => [row.id, row])), [rows]);
  const geometryById = useMemo(() => new Map(layout.nodes.map((node) => [node.id, node])), [layout]);
  const selectedRow = selectedId ? rowsById.get(selectedId) ?? null : null;
  const captureRequest = selectedRow ? captureRequestForRow(selectedRow, props) : null;
  const exportText = useMemo(
    () => exportOpen ? formatNormalizedTraceExport(rows, props.entitiesById ?? new Map()) : "",
    [exportOpen, rows, props.entitiesById],
  );

  const installZoom = useCallback((svg: SVGSVGElement | null) => {
    if (svgRef.current) d3.select(svgRef.current).on(".zoom", null);
    svgRef.current = svg;
    if (!svg) return;
    d3.select(svg).call(d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.45, 3])
      .on("zoom", (event) => viewportRef.current?.setAttribute("transform", event.transform.toString())));
  }, []);

  return (
    <div className="trace-normalized-view">
      <section className="trace-normalized-graph" aria-label="Selected trace topology">
        <svg ref={installZoom} viewBox={layout.viewBox} role="img" aria-label="Selected bounded trace subtree">
          <g ref={viewportRef}>
            {layout.nodes.flatMap((node) => {
              if (!node.parentId) return [];
              const parent = geometryById.get(node.parentId);
              return parent ? [<path
                className="trace-normalized-link"
                key={`${parent.id}-${node.id}`}
                d={`M${parent.y},${parent.x}C${(parent.y + node.y) / 2},${parent.x} ${(parent.y + node.y) / 2},${node.x} ${node.y},${node.x}`}
              />] : [];
            })}
            {layout.nodes.map((node) => {
              const row = rowsById.get(node.id);
              return row ? <SvgNode
                key={node.id}
                geometry={node}
                row={row}
                selected={selectedId === node.id}
                onSelect={setSelectedId}
              /> : null;
            })}
          </g>
        </svg>
        {topologyRows.length >= TRACE_GRAPH_NODE_LIMIT ? (
          <span className="trace-overlay__limit">Graph capped at {TRACE_GRAPH_NODE_LIMIT} records</span>
        ) : null}
      </section>
      <section className="trace-data-list" aria-label="Complete trace data">
        <div className="trace-data-list__filters">
          <input
            aria-label="Search trace data"
            value={query}
            onChange={(event) => { setQuery(event.target.value); setScrollTop(0); }}
            placeholder="Search state…"
          />
          <select aria-label="Trace data kind" value={kind} onChange={(event) => setKind(event.target.value as typeof kind)}>
            <option value="all">All</option>
            <option value="machine">Machines</option>
            <option value="transition">Transitions</option>
            <option value="control">Controls</option>
            <option value="group">Groups</option>
            <option value="facet">Facets</option>
            <option value="capture">Captures</option>
            <option value="failure">Failures</option>
            <option value="diagnostic">Diagnostics</option>
          </select>
        </div>
        <div
          className="trace-data-list__viewport"
          onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
        >
          <div style={{ height: windowed.totalHeight, position: "relative" }}>
            <div style={{ transform: `translateY(${windowed.offset}px)` }}>
              {filtered.slice(windowed.start, windowed.end).map((row) => (
                <button
                  type="button"
                  className={selectedId === row.id ? "is-selected" : ""}
                  key={row.id}
                  style={{ height: TRACE_LIST_ROW_HEIGHT }}
                  onClick={() => setSelectedId(row.id)}
                >
                  <span>{row.kind}</span>
                  <strong title={row.name}>{row.name}</strong>
                  <em title={row.value}>{row.value}</em>
                </button>
              ))}
            </div>
          </div>
        </div>
        {captureRequest && props.onRequestCapture ? (
          <button
            type="button"
            className="trace-capture-request"
            onClick={() => props.onRequestCapture?.({
              ...captureRequest, duration_seconds: 30, call_budget: 100,
            })}
          >Capture selected (30s / 100 calls)</button>
        ) : null}
        <details
          className="trace-export"
          onToggle={(event) => {
            setExportOpen(event.currentTarget.open);
            setCopyStatus("idle");
          }}
        >
          <summary>Export for LLM</summary>
          <div className="trace-export__actions">
            <button
              type="button"
              onClick={() => {
                void copyTraceExport(exportText).then(
                  () => setCopyStatus("copied"),
                  () => setCopyStatus("failed"),
                );
              }}
            >{copyStatus === "copied" ? "Copied" : "Copy LLM summary"}</button>
            <span role="status" aria-live="polite">
              {copyStatus === "failed" ? "Copy failed — select the text below" : ""}
            </span>
          </div>
          <textarea
            readOnly
            aria-label="Compact trace summary for LLM"
            value={exportText}
            onFocus={(event) => event.currentTarget.select()}
          />
        </details>
        <footer>{filtered.length} records · {topologyRows.length} in graph</footer>
      </section>
    </div>
  );
}

function captureRequestForRow(
  row: TraceDataRow,
  props: NormalizedTraceViewProps,
): { selector_kind: string; selector_value: string | number } | null {
  if (row.kind === "machine" && row.ownerId) {
    return { selector_kind: "entity", selector_value: row.ownerId };
  }
  if (row.kind === "control") {
    return { selector_kind: "control", selector_value: row.id.slice("control:".length) };
  }
  if (row.kind === "facet") {
    return { selector_kind: "facet", selector_value: row.id.slice("facet:".length) };
  }
  if (row.kind === "group") {
    const group = props.groupsById.get(Number(row.id.slice("group:".length)));
    return typeof group?.operation_id === "number"
      ? { selector_kind: "operation", selector_value: group.operation_id }
      : null;
  }
  return null;
}
