import { useCallback, useEffect, useState } from "react";

/** Discriminated async state so every consumer handles loading / error / data explicitly. */
export type AsyncState<T> =
  | { status: "loading" }
  | { status: "error"; error: Error }
  | { status: "success"; data: T };

/**
 * Runs an async loader and tracks its lifecycle. `deps` re-triggers the load (e.g. when the
 * selected workload changes). A cancel guard prevents setting state after unmount / re-run.
 */
export function useAsync<T>(loader: () => Promise<T>, deps: ReadonlyArray<unknown>): AsyncState<T> {
  const [state, setState] = useState<AsyncState<T>>({ status: "loading" });

  // The loader identity intentionally comes from `deps`, not from the function reference.
  const run = useCallback(loader, deps);

  useEffect(() => {
    let cancelled = false;
    setState({ status: "loading" });
    run()
      .then((data) => {
        if (!cancelled) setState({ status: "success", data });
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setState({ status: "error", error: error instanceof Error ? error : new Error(String(error)) });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [run]);

  return state;
}
