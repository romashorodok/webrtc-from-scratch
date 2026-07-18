import { buildTraceDataRows, formatNormalizedTraceExport } from "./TraceNormalizedView";
import { createInitialTraceState, reduceTraceState, type TraceEventInput } from "./trace";

// Cross-language fixture consumer: stdin is exactly what the signaling
// send_json boundary delivered. Keep this on the production reducer/export path.
const envelopes = await Bun.stdin.json() as TraceEventInput[];
let state = createInitialTraceState();
for (const envelope of envelopes) {
  state = reduceTraceState(state, { type: "events", events: [envelope] });
}
const rows = buildTraceDataRows({
  machinesById: state.machinesById,
  entitiesById: state.entitiesById,
  transitions: state.transitions,
  controlsById: state.controlsById,
  groupsById: state.groupsById,
  facetsById: state.facetsById,
  capturesById: state.capturesById,
  operationNamesById: state.operationNamesById,
  diagnostics: state.diagnostics,
});
process.stdout.write(formatNormalizedTraceExport(rows, state.entitiesById));
