import { useCallback, useEffect, useState } from "react";

/** Discriminated async state so every consumer handles loading / error / data explicitly. */
export type AsyncState<T> =
  | { status: "loading" }
  | { status: "error"; error: Error }
  | { status: "success"; data: T };

/**
 * Runs an async loader and tracks its lifecycle. `deps` re-triggers the load (e.g. when the
 * selected workload changes). The loader receives an `AbortSignal` that is aborted when the effect
 * re-runs or unmounts, so an in-flight request is CANCELLED (not merely ignored) before the next
 * one starts. A cancel guard also prevents setting state after unmount / re-run.
 */
export function useAsync<T>(
  loader: (signal: AbortSignal) => Promise<T>,
  deps: ReadonlyArray<unknown>,
): AsyncState<T> {
  const [state, setState] = useState<AsyncState<T>>({ status: "loading" });

  // The loader identity intentionally comes from `deps`, not from the function reference.
  const run = useCallback(loader, deps);

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;
    setState({ status: "loading" });
    run(controller.signal)
      .then((data) => {
        if (!cancelled) setState({ status: "success", data });
      })
      .catch((error: unknown) => {
        // A cancelled/aborted request must never surface as an error (fail-closed, no stale flip).
        if (cancelled || controller.signal.aborted) return;
        setState({ status: "error", error: error instanceof Error ? error : new Error(String(error)) });
      });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [run]);

  return state;
}
