import { useEffect, useState } from "react";

type ModuleManifest = {
  name: string;
  displayName: string;
  kind: "service" | "job";
  enabled: boolean;
  scaleProfile: { minReplicas: number; maxReplicas: number };
};

/**
 * Minimal console: lists the platform's modules and their independent scale ranges.
 * Reads the API read model only (no state writes from the SPA).
 */
export function App() {
  const [modules, setModules] = useState<ModuleManifest[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/modules")
      .then((r) => (r.ok ? r.json() : Promise.reject(r.statusText)))
      .then(setModules)
      .catch((e) => setError(String(e)));
  }, []);

  return (
    <main style={{ fontFamily: "system-ui, sans-serif", padding: 24, maxWidth: 880 }}>
      <h1>Workloads Platform</h1>
      <p>In-boundary discovery, quality, dependency &amp; blast radius, AIOps and alerts.</p>
      {error && <p style={{ color: "crimson" }}>API unavailable: {error}</p>}
      <table style={{ borderCollapse: "collapse", width: "100%" }}>
        <thead>
          <tr>
            <th style={th}>Module</th>
            <th style={th}>Kind</th>
            <th style={th}>Scale (min→max)</th>
            <th style={th}>Enabled</th>
          </tr>
        </thead>
        <tbody>
          {modules.map((m) => (
            <tr key={m.name}>
              <td style={td}>{m.displayName}</td>
              <td style={td}>{m.kind}</td>
              <td style={td}>
                {m.scaleProfile.minReplicas} → {m.scaleProfile.maxReplicas}
              </td>
              <td style={td}>{m.enabled ? "yes" : "no"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}

const th: React.CSSProperties = { textAlign: "left", borderBottom: "2px solid #ddd", padding: 8 };
const td: React.CSSProperties = { borderBottom: "1px solid #eee", padding: 8 };
