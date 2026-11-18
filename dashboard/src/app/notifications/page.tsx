"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { useAsync } from "@/hooks/useAsync";
import { Bell, CheckCircle2, Clock, RefreshCw, Send, XCircle } from "lucide-react";
import Layout from "@/components/Layout";
import EmptyState from "@/components/EmptyState";
import LoadingSpinner from "@/components/LoadingSpinner";
import { cx } from "@/lib/cx";
import { getJson, postJson } from "@/lib/http";

type Channel = { name: "slack" | "webhook"; configured: boolean };

type Delivery = {
  id: number;
  channel: string;
  event: string;
  remediation_id: number | null;
  status: "pending" | "sent" | "failed";
  attempts: number;
  last_error: string | null;
  created_at: string | null;
  sent_at: string | null;
  next_attempt_at: string | null;
};

type NotificationsPage = { channels: Channel[]; events: string[]; links: boolean; deliveries: Delivery[] };

const CHANNEL_LABELS: Record<string, { title: string; variable: string }> = {
  slack: { title: "Slack", variable: "NOTIFICATION_SLACK_WEBHOOK_URL" },
  webhook: { title: "Webhook (signed JSON)", variable: "NOTIFICATION_WEBHOOK_URL" },
};
const POLL_MS = 2000;
const POLL_TRIES = 15;

function StatusBadge({ delivery }: { delivery: Delivery }) {
  if (delivery.status === "sent")
    return (
      <span className="inline-flex items-center gap-1 text-emerald-300">
        <CheckCircle2 className="h-3.5 w-3.5" /> sent
      </span>
    );
  if (delivery.status === "failed")
    return (
      <span className="inline-flex items-center gap-1 text-rose-300">
        <XCircle className="h-3.5 w-3.5" /> failed
      </span>
    );
  return (
    <span className="inline-flex items-center gap-1 text-amber-200">
      <Clock className="h-3.5 w-3.5" /> {delivery.attempts ? "retrying" : "pending"}
    </span>
  );
}

/** What happened to the messages a test send queued, one line per channel. */
function TestResult({ ids, deliveries }: { ids: number[]; deliveries: Delivery[] }) {
  const rows = deliveries.filter((delivery) => ids.includes(delivery.id));
  return (
    <ul className="mt-4 space-y-1 text-sm">
      {rows.map((delivery) => (
        <li key={delivery.id} className="flex flex-wrap items-center gap-2">
          <span className="text-slate-300">{CHANNEL_LABELS[delivery.channel]?.title || delivery.channel}:</span>
          <StatusBadge delivery={delivery} />
          {delivery.last_error && <span className="font-mono text-xs text-slate-500">{delivery.last_error}</span>}
          {delivery.status === "pending" && delivery.attempts > 0 && (
            <span className="text-xs text-slate-500">retries continue in the background</span>
          )}
        </li>
      ))}
    </ul>
  );
}

function loadNotifications(): Promise<NotificationsPage> {
  return getJson<NotificationsPage>("/api/notifications");
}

export default function NotificationsPage() {
  const notifications = useAsync(loadNotifications);
  const { reload } = notifications;
  const [actionError, setActionError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [testIds, setTestIds] = useState<number[]>([]);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const page = notifications.data ?? null;
  const error = actionError ?? notifications.error;
  const load = reload;

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );

  /** Refresh until the test's first delivery attempt is done, or the tries run out. */
  const poll = (ids: number[], tries: number) => {
    timer.current = setTimeout(async () => {
      const next = await loadNotifications().catch(() => null);
      reload();
      const waiting = next?.deliveries.some(
        (item) => ids.includes(item.id) && item.status === "pending" && !item.attempts,
      );
      if (waiting && tries > 1) poll(ids, tries - 1);
      else setSending(false);
    }, POLL_MS);
  };

  const sendTest = async () => {
    setSending(true);
    setActionError(null);
    try {
      const result = await postJson<{ queued: Delivery[] }>("/api/notifications/test");
      const ids = result.queued.map((item) => item.id);
      setTestIds(ids);
      reload();
      poll(ids, POLL_TRIES);
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Could not send a test");
      setSending(false);
    }
  };

  if (!page && !error)
    return (
      <Layout>
        <LoadingSpinner />
      </Layout>
    );
  const configured = page?.channels.some((channel) => channel.configured) ?? false;
  return (
    <Layout>
      <div className="mb-8 flex items-end justify-between gap-4">
        <div>
          <div className="eyebrow mb-3">Governance / Notifications</div>
          <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Notifications</h1>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Messages when a remediation needs someone or finishes. Channels are set in the environment.
          </p>
        </div>
        <button
          onClick={load}
          className={cx(
            "inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm",
            "text-slate-300 hover:text-white",
          )}
        >
          <RefreshCw className="h-4 w-4" /> Refresh
        </button>
      </div>
      {error && <div className="panel mb-5 rounded-2xl p-4 text-sm text-amber-200">{error}</div>}
      {page && (
        <>
          <section className="mb-5 grid gap-4 sm:grid-cols-2">
            {page.channels.map((channel) => (
              <div key={channel.name} className="panel rounded-2xl p-5">
                <div className="flex items-center justify-between">
                  <div className="text-sm font-medium text-slate-200">{CHANNEL_LABELS[channel.name].title}</div>
                  <span
                    className={cx(
                      "rounded-full px-2.5 py-0.5 text-xs",
                      channel.configured ? "bg-emerald-400/10 text-emerald-300" : "bg-slate-800 text-slate-400",
                    )}
                  >
                    {channel.configured ? "Configured" : "Not configured"}
                  </span>
                </div>
                <div className="mt-2 font-mono text-xs text-slate-500">{CHANNEL_LABELS[channel.name].variable}</div>
              </div>
            ))}
          </section>
          <section className="panel mb-5 rounded-2xl p-5">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="text-sm text-slate-400">
                <div>
                  Sent for:{" "}
                  {page.events.length ? (
                    page.events.map((event) => (
                      <span key={event} className="mr-1.5 rounded bg-slate-800 px-1.5 py-0.5 font-mono text-xs">
                        {event}
                      </span>
                    ))
                  ) : (
                    <span>no statuses (NOTIFICATION_EVENTS is empty)</span>
                  )}
                </div>
                <div className="mt-2 text-xs text-slate-500">
                  {page.links
                    ? "Messages link to the remediation."
                    : "Set DASHBOARD_PUBLIC_URL to link messages to the remediation."}
                </div>
              </div>
              <button
                onClick={sendTest}
                disabled={!configured || sending}
                className={cx(
                  "inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-sm font-medium",
                  "bg-cyan-400 text-slate-950 hover:bg-cyan-300 disabled:bg-slate-800 disabled:text-slate-500",
                )}
              >
                <Send className="h-4 w-4" /> {sending ? "Sending…" : "Send test"}
              </button>
            </div>
            {!configured && (
              <p className="mt-3 text-xs text-slate-500">
                No channel is configured. See the operator guide, section 10, to set one up.
              </p>
            )}
            {testIds.length > 0 && <TestResult ids={testIds} deliveries={page.deliveries} />}
          </section>
          <section className="panel overflow-hidden rounded-2xl">
            <div className="border-b border-slate-800/70 px-5 py-3 text-sm font-medium text-slate-300">
              Recent deliveries
            </div>
            {page.deliveries.length ? (
              <div className="divide-y divide-slate-800/70">
                {page.deliveries.map((delivery) => (
                  <div key={delivery.id} className="flex flex-col gap-1 px-5 py-3 text-sm sm:flex-row sm:items-center">
                    <div className="flex flex-1 flex-wrap items-center gap-2">
                      <span className="font-mono text-xs text-slate-300">{delivery.event}</span>
                      <span className="text-xs text-slate-500">
                        {CHANNEL_LABELS[delivery.channel]?.title || delivery.channel}
                      </span>
                      {delivery.remediation_id !== null && (
                        <Link
                          className="text-xs text-cyan-300 underline"
                          href={`/remediations/${delivery.remediation_id}`}
                        >
                          remediation #{delivery.remediation_id}
                        </Link>
                      )}
                      {delivery.last_error && (
                        <span className="font-mono text-xs text-slate-500">{delivery.last_error}</span>
                      )}
                    </div>
                    <div className="flex items-center gap-3 text-xs">
                      <StatusBadge delivery={delivery} />
                      <span className="text-slate-500">
                        {delivery.created_at ? new Date(delivery.created_at).toLocaleString() : ""}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={Bell}
                title="No deliveries yet"
                description="Messages appear here when a remediation changes status, or after a test send."
              />
            )}
          </section>
        </>
      )}
    </Layout>
  );
}
