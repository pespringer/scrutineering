interface StatCardProps {
  label: string;
  value: number | string;
  icon?: React.ReactNode;
  color?: string;
}

const colorMap: Record<string, string> = {
  red: "bg-red-500/10 text-red-400 border-red-500/20",
  orange: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  yellow: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  blue: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  green: "bg-green-500/10 text-green-400 border-green-500/20",
  default: "bg-slate-800/50 text-slate-300 border-slate-700/50",
};

export default function StatCard({ label, value, icon, color = "default" }: StatCardProps) {
  return (
    <div className={`rounded-xl border p-5 ${colorMap[color] || colorMap.default} transition-all hover:shadow-lg hover:shadow-black/20`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium opacity-70 uppercase tracking-wider">{label}</span>
        {icon && <span className="opacity-60">{icon}</span>}
      </div>
      <div className="text-3xl font-bold tracking-tight">{value}</div>
    </div>
  );
}
