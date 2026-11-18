"use client";

import { useCallback, useEffect, useState } from "react";
import { useAsync } from "@/hooks/useAsync";
import { getJson, postJson } from "@/lib/http";
import type { RemediationEvent, RemediationRecord, RemediationStatus } from "@/types";
import type { RemediationAction } from "@/components/remediations/ExecutionControls";

type EventsResponse = { events: RemediationEvent[]; latest_event: Omit<RemediationEvent, "id" | "sequence"> | null };

/** Statuses where the worker still has to report back; the page polls until it does. */
export const IN_FLIGHT_STATES: RemediationStatus[] = ["building", "verifying"];

type Loaded = {
  remediation: RemediationRecord;
  events: RemediationEvent[];
  latestEvent: EventsResponse["latest_event"];
};

/** One remediation and its events, with actions that refresh it and polling while execution runs. */
export function useRemediation(id: string | null, pollMs = 3000) {
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const loadRemediation = useCallback(async (): Promise<Loaded | null> => {
    if (!id) return null;
    const [record, history] = await Promise.all([
      getJson<RemediationRecord>(`/api/remediations/${id}`),
      getJson<EventsResponse>(`/api/remediations/${id}/events`),
    ]);
    return { remediation: record, events: history.events || [], latestEvent: history.latest_event || null };
  }, [id]);
  const loaded = useAsync(loadRemediation);
  const { reload } = loaded;
  const remediation = loaded.data?.remediation ?? null;
  const latestEvent = loaded.data?.latestEvent ?? null;

  const status = remediation?.status;
  // A requested publication runs on the worker; the status stays `ready` until it reports back.
  const publishing = status === "ready" && latestEvent?.event_type === "publication_queued";
  useEffect(() => {
    if (!status || !(IN_FLIGHT_STATES.includes(status) || publishing)) return;
    const timer = window.setInterval(reload, pollMs);
    return () => window.clearInterval(timer);
  }, [status, publishing, reload, pollMs]);

  /** POST a lifecycle action and reload the record. */
  const act = useCallback(
    async (action: RemediationAction) => {
      if (!id) return;
      setBusy(true);
      setNotice("");
      try {
        await postJson(`/api/remediations/${id}/${action}`);
      } catch (error) {
        setNotice(error instanceof Error ? error.message : "Request failed");
      } finally {
        setBusy(false);
        reload();
      }
    },
    [id, reload],
  );

  return {
    remediation,
    events: loaded.data?.events ?? [],
    latestEvent,
    loadError: loaded.error,
    notice,
    busy,
    publishing,
    act,
  };
}
