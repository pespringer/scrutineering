const sevStyles: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  LOW: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  UNKNOWN: "bg-slate-600/20 text-slate-400 border-slate-600/30",
};

export default function SeverityBadge({ severity }: { severity: string | null }) {
  const s = (severity || "UNKNOWN").toUpperCase();
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${sevStyles[s] || sevStyles.UNKNOWN}`}>
      {s}
    </span>
  );
}
