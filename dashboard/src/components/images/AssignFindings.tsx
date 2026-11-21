"use client";

import { useEffect, useState } from "react";
import { UserRound } from "lucide-react";
import { getJson, postJson } from "@/lib/http";

type Assignee = { subject: string; email: string | null };

type Props = {
  findingIds: number[];
  onDone: (message: string, changed: boolean) => void;
};

/** Assign the selected findings to someone who has signed in. Hidden when nobody has (local mode). */
export default function AssignFindings({ findingIds, onDone }: Props) {
  const [assignees, setAssignees] = useState<Assignee[]>([]);
  useEffect(() => {
    getJson<{ items: Assignee[] }>("/api/people/assignees")
      .then((body) => setAssignees(body.items))
      .catch(() => setAssignees([]));
  }, []);
  if (assignees.length === 0) return null;

  async function assign(value: string) {
    const assignee = value === "-" ? null : value;
    try {
      await postJson("/api/findings/bulk-assign", { finding_ids: findingIds, assignee });
      onDone(assignee ? `Assigned to ${assignee}.` : "Unassigned.", true);
    } catch (error) {
      onDone(`Couldn't assign: ${(error as Error).message}`, false);
    }
  }

  return (
    <label className="inline-flex items-center gap-1 rounded-lg border border-cyan-400/30 px-2.5 py-1">
      <UserRound className="h-3.5 w-3.5" />
      <select
        aria-label="Assign selected findings"
        value=""
        onChange={(event) => assign(event.target.value)}
        className="bg-transparent text-cyan-200 outline-none"
      >
        <option value="" disabled>
          Assign to…
        </option>
        {assignees.map((person) => (
          <option key={person.subject} value={person.subject} className="bg-slate-900">
            {person.email || person.subject}
          </option>
        ))}
        <option value="-" className="bg-slate-900">
          Unassign
        </option>
      </select>
    </label>
  );
}
