/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies /api to the FastAPI core so the SPA reads live read models.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
  // Component tests run under jsdom with Testing Library (Vitest — the Vite-native runner).
  // TODO(human): there was no pre-existing web test harness, so this adds the minimal one a Vite +
  // React + TS project implies (Vitest + Testing Library + jsdom). If the team standardises on a
  // different runner, swap it here. Test files are excluded from the `tsc -b` build (see
  // tsconfig.json) so the CI web-build gate stays independent of test-only type deps; `npm run
  // typecheck` covers the shipped app and `npm test` type-transforms the tests via esbuild.
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
