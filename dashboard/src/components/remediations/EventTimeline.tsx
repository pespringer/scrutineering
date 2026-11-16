import { CheckCircle2, CircleAlert } from "lucide-react";
import type { RemediationEvent } from "@/types";

export default function EventTimeline({ events }: { events: RemediationEvent[] }) {
  return (
    <div className="panel rounded-2xl p-5 sm:p-6">
      <div className="mb-5 flex items-center gap-2 text-sm font-semibold text-slate-200">
        <CheckCircle2 className="h-4 w-4 text-cyan-300" /> Events
      </div>
      <div className="space-y-5">
        {events.map((event) => {
          const problem = event.event_type.includes("rollback") || event.event_type.includes("blocked");
          return (
            <div key={event.id} className="flex gap-3">
              <div className="mt-0.5 text-cyan-300">
                {problem ? <CircleAlert className="h-4 w-4 text-rose-300" /> : <CheckCircle2 className="h-4 w-4" />}
              </div>
              <div>
                <div className="text-sm font-medium text-slate-200">{event.event_type.replaceAll("_", " ")}</div>
                <div className="text-xs text-slate-500">
                  Step {event.sequence} · {new Date(event.created_at).toLocaleString()}
                </div>
              </div>
            </div>
          );
        })}
        {!events.length && <p className="text-sm text-slate-500">No lifecycle events yet.</p>}
      </div>
    </div>
  );
}
