import { expect, test } from "bun:test";
import { renderToString } from "react-dom/server";
import { TraceOverlay } from "./TraceOverlay";

test("closed normalized overlay does not mount list, SVG, export, or animation work", () => {
  const html = renderToString(
    <TraceOverlay
      tasks={[]}
      groups={[]}
      summaries={[]}
      machinesById={new Map([["peer", {
        entity_id: "peer",
        machine_type: "peer",
        state: "connected",
        machine_epoch: 1,
        revision: 1,
        cause_id: null,
        monotonic_ns: 1,
      }]])}
      controlsById={new Map()}
      groupsById={new Map()}
      facetsById={new Map()}
      operationNamesById={new Map()}
      diagnostics={{}}
      topologyVersion={1}
      valueVersion={1}
    />,
  );

  expect(html).toContain("trace-overlay__toggle");
  expect(html).not.toContain("trace-normalized-view");
  expect(html).not.toContain("<svg");
  expect(html).not.toContain("Search state");
  expect(html).not.toContain("trace-export");
});
