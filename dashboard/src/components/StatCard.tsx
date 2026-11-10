interface StatCardProps {
  label: string;
  value: number | string;
  icon?: React.ReactNode;
  color?: string;
  detail?: string;
}

const colorMap: Record<string, string> = {
  red: "bg-red-500/10 text-red-400 border-red-500/20",
  orange: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  yellow: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  blue: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  green: "bg-green-500/10 text-green-400 border-green-500/20",
  default: "bg-slate-800/50 text-slate-300 border-slate-700/50",
};

export default function StatCard({ label, value, icon, color = "default", detail }: StatCardProps) {
  return (
    <div className={`group rounded-2xl border p-5 ${colorMap[color] || colorMap.default} transition-all hover:-translate-y-0.5 hover:shadow-xl hover:shadow-black/20`}>
      <div className="mb-5 flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-[0.14em] opacity-65">{label}</span>
        {icon && <span className="opacity-60 transition group-hover:scale-110">{icon}</span>}
      </div>
      <div className="text-3xl font-bold tracking-tight sm:text-4xl">{value}</div>
      {detail && <div className="mt-2 text-xs opacity-60">{detail}</div>}
    </div>
  );
}
