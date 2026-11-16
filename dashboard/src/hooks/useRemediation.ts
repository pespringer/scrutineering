"use client";

import { useCallback, useEffect, useState } from "react";
import { getJson, postJson } from "@/lib/http";
import type { RemediationEvent, RemediationRecord } from "@/types";

type EventsResponse = { events: RemediationEvent[]; latest_event: Omit<RemediationEvent, "id" | "sequence"> | null };

/** Execution states where the worker still has to report back; the page polls until it does. */
export const IN_FLIGHT_STATES = ["execution_queued", "execution_started"];

/** One remediation and its events, with actions that refresh it and polling while execution runs. */
export function useRemediation(id: string | null, pollMs = 3000) {
  const [remediation, setRemediation] = useState<RemediationRecord | null>(null);
  const [events, setEvents] = useState<RemediationEvent[]>([]);
  const [latestEvent, setLatestEvent] = useState<EventsResponse["latest_event"]>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!id) return;
    try {
      const [record, history] = await Promise.all([
        getJson<RemediationRecord>(`/api/remediations/${id}`),
        getJson<EventsResponse>(`/api/remediations/${id}/events`),
      ]);
      setRemediation(record);
      setEvents(history.events || []);
      setLatestEvent(history.latest_event || null);
      setLoadError(null);
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Unable to load this remediation.");
    }
  }, [id]);

  useEffect(() => {
    load();
  }, [load]);

  const workflowState = remediation?.workflow_state || remediation?.status || "";
  useEffect(() => {
    if (!IN_FLIGHT_STATES.includes(workflowState)) return;
    const timer = window.setInterval(load, pollMs);
    return () => window.clearInterval(timer);
  }, [workflowState, load, pollMs]);

  /** POST an action (approve, execute, retry) and reload the record. */
  const act = useCallback(
    async (action: "approve" | "execute" | "retry") => {
      if (!id) return;
      setBusy(true);
      setNotice("");
      try {
        const result = await postJson<{ status?: string }>(`/api/remediations/${id}/${action}`);
        setNotice(result.status ? `Workflow status: ${result.status.replaceAll("_", " ")}` : "Action accepted.");
      } catch (error) {
        setNotice(error instanceof Error ? error.message : "Request failed");
      } finally {
        setBusy(false);
        await load();
      }
    },
    [id, load],
  );

  return { remediation, events, latestEvent, loadError, notice, busy, workflowState, act };
}
