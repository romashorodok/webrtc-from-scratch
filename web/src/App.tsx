import { useEffect, useState } from "react";
import { ClientPage } from "./lib/ClientPage";
import { OpusPage } from "./lib/OpusPage";
import { ServerPage } from "./lib/ServerPage";
import "./index.css";

type Page = "client" | "server" | "opus";

function getPageFromHash(hash: string): Page {
  const normalized = hash.replace(/^#/, "");
  if (normalized === "server" || normalized === "opus") {
    return normalized;
  }
  return "client";
}

const pageMeta: Record<Page, { title: string; hint: string }> = {
  client: {
    title: "Client Mode",
    hint: "Use with `make run` to let Python act as the server.",
  },
  server: {
    title: "Server Mode",
    hint: "Use with `make client` to let Python act as the client.",
  },
  opus: {
    title: "Opus Audio",
    hint: "Use with `uvicorn examples.opus_ws:app --reload --port 9001`.",
  },
};

export function App() {
  const [currentPage, setCurrentPage] = useState<Page>(() =>
    typeof window === "undefined" ? "client" : getPageFromHash(window.location.hash),
  );

  useEffect(() => {
    const updatePage = () => {
      setCurrentPage(getPageFromHash(window.location.hash));
    };

    updatePage();
    window.addEventListener("hashchange", updatePage);
    return () => window.removeEventListener("hashchange", updatePage);
  }, []);

  const navigate = (page: Page) => {
    if (window.location.hash.slice(1) !== page) {
      window.location.hash = page;
    }
  };

  const page = pageMeta[currentPage];

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar__copy">
          <p className="eyebrow">WebRTC Demo</p>
          <h1>{page.title}</h1>
          <p className="hint">{page.hint}</p>
        </div>

        <nav className="nav-tabs" aria-label="Demo modes">
          <button
            type="button"
            className={currentPage === "client" ? "active" : ""}
            onClick={() => navigate("client")}
          >
            Client Mode
          </button>
          <button
            type="button"
            className={currentPage === "server" ? "active" : ""}
            onClick={() => navigate("server")}
          >
            Server Mode
          </button>
          <button
            type="button"
            className={currentPage === "opus" ? "active" : ""}
            onClick={() => navigate("opus")}
          >
            Opus Audio
          </button>
        </nav>
      </header>

      <main className="page-frame">
        {currentPage === "client" ? <ClientPage /> : null}
        {currentPage === "server" ? <ServerPage /> : null}
        {currentPage === "opus" ? <OpusPage /> : null}
      </main>
    </div>
  );
}

export default App;
