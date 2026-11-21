"use client";

import { useCallback } from "react";
import { RefreshCw, Users } from "lucide-react";
import Layout from "@/components/Layout";
import EmptyState from "@/components/EmptyState";
import LoadingSpinner from "@/components/LoadingSpinner";
import { useAsync } from "@/hooks/useAsync";
import { cx } from "@/lib/cx";
import { getJson } from "@/lib/http";
import type { Person } from "@/types";

function when(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "";
}

export default function PeoplePage() {
  const loadPeople = useCallback(() => getJson<{ items: Person[] }>("/api/people"), []);
  const people = useAsync(loadPeople);

  if (people.loading && !people.data)
    return (
      <Layout>
        <LoadingSpinner />
      </Layout>
    );
  const items = people.data?.items ?? [];
  return (
    <Layout>
      <div className="mb-8 flex items-end justify-between gap-4">
        <div>
          <div className="eyebrow mb-3">Governance / People</div>
          <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">People</h1>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Everyone who has signed in, with the roles they had last time. Accounts and groups are managed in your
            identity provider; people unseen for a year are removed.
          </p>
        </div>
        <button
          onClick={people.reload}
          className={cx(
            "inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm",
            "text-slate-300 hover:text-white",
          )}
        >
          <RefreshCw className="h-4 w-4" /> Refresh
        </button>
      </div>
      {people.error && (
        <div className="panel mb-5 rounded-2xl p-4 text-sm text-amber-200">
          {people.error === "operator role required" ? "Only admins can see who has signed in." : people.error}
        </div>
      )}
      <section className={cx("panel overflow-hidden rounded-2xl", people.error && !people.data && "hidden")}>
        {items.length ? (
          <div className="divide-y divide-slate-800/70">
            {items.map((person) => (
              <div key={person.subject} className="flex flex-col gap-2 px-5 py-3 text-sm sm:flex-row sm:items-center">
                <div className="flex-1">
                  <div className="text-slate-200">{person.email || person.subject}</div>
                  <div className="font-mono text-xs text-slate-500">{person.subject}</div>
                </div>
                <div className="flex flex-1 flex-wrap gap-1.5">
                  {person.roles.length ? (
                    person.roles.map((role) => (
                      <span key={role} className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-xs text-slate-300">
                        {role}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-amber-200">No role: can't see anything</span>
                  )}
                </div>
                <div className="text-xs text-slate-500 sm:text-right">
                  <div>Last seen {when(person.last_seen_at)}</div>
                  <div>First seen {when(person.first_seen_at)}</div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            icon={Users}
            title="Nobody has signed in yet"
            description="People appear here after they sign in through your forward-auth proxy."
          />
        )}
      </section>
    </Layout>
  );
}
