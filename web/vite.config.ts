import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// `npm run build`      -> live build served by the Driftwatch server; calls /api with the operator key.
// `npm run build:demo` -> static build (GitHub Pages) that replays public/demo/*.json, exported by
//                         scripts/export_demo.py from a seeded database.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    base: "./",
    plugins: [react(), tailwindcss()],
    // The shared design system is vendored in ../packages; make it use this app's single React copy.
    resolve: {
      dedupe: ["react", "react-dom", "motion", "cytoscape", "@radix-ui/react-dialog", "@radix-ui/react-switch", "clsx",
        "tailwind-merge", "class-variance-authority"],
    },
    define: {
      __DATA_MODE__: JSON.stringify(mode === "demo" ? "replay" : env.VITE_DATA_MODE || "auto"),
    },
    server: {
      proxy: { "/api": { target: env.VITE_SERVER_URL || "http://127.0.0.1:8000", changeOrigin: true } },
    },
    build: {
      outDir: mode === "demo" ? "dist-demo" : "dist",
      chunkSizeWarningLimit: 1500,
      rollupOptions: {
        output: {
          // Rolldown only accepts the function form.
          manualChunks(id: string) {
            if (id.includes("@xyflow")) return "flow";
            if (/node_modules\/(react|react-dom|react-router|react-router-dom|scheduler)\//.test(id)) return "react";
            return undefined;
          },
        },
      },
    },
    test: { environment: "node", include: ["src/**/*.test.ts"] },
  };
});
