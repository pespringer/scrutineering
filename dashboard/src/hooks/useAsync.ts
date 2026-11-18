"use client";

import { useCallback, useEffect, useState } from "react";

export type AsyncState<T> = {
  /** The last successful result; kept while a reload is in flight, so the page doesn't flash empty. */
  data: T | undefined;
  /** Why the latest load failed, or null. */
  error: string | null;
  /** True until the current loader (and reload) has answered. */
  loading: boolean;
  /** Run the loader again. */
  reload: () => void;
};

type Settled<T> = {
  load: (() => Promise<T>) | null;
  version: number;
  data: T | undefined;
  error: string | null;
};

/**
 * Run `load` (wrap it in useCallback; it reruns when it changes) and hold its result.
 *
 * State is only set when the promise settles, never synchronously in the effect, and `loading` is
 * derived by comparing the settled result with the current loader, so pages need no loading flags
 * of their own. A result that arrives for an older loader is dropped.
 */
export function useAsync<T>(load: () => Promise<T>): AsyncState<T> {
  const [version, setVersion] = useState(0);
  const [settled, setSettled] = useState<Settled<T>>({ load: null, version: -1, data: undefined, error: null });

  useEffect(() => {
    let current = true;
    load().then(
      (data) => {
        if (current) setSettled({ load, version, data, error: null });
      },
      (error: unknown) => {
        const message = error instanceof Error ? error.message : "Request failed";
        if (current) setSettled((previous) => ({ load, version, data: previous.data, error: message }));
      },
    );
    return () => {
      current = false;
    };
  }, [load, version]);

  const reload = useCallback(() => setVersion((value) => value + 1), []);
  const loading = settled.load !== load || settled.version !== version;
  return { data: settled.data, error: loading ? null : settled.error, loading, reload };
}
