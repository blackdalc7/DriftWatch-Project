import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { HashRouter } from "react-router-dom";
import "@xyflow/react/dist/style.css";
import "./index.css";
import { App } from "./App";
import { syncClock } from "./lib/api";

// Replay mode reads the snapshot time first so relative times ("seen 2m ago") are right on first paint.
void syncClock().finally(() => createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <HashRouter>
      <App />
    </HashRouter>
  </StrictMode>,
));
