import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import EmptyState from "@/components/EmptyState";
import type { SeverityTrend } from "@/types";

const SERIES = [
  { key: "critical", name: "Critical", color: "#ff647c" },
  { key: "high", name: "High", color: "#ff9f5b" },
  { key: "medium", name: "Medium", color: "#f5cf6b" },
  { key: "low", name: "Low", color: "#55a6ff" },
] as const;

export default function SeverityTrendChart({ trends }: { trends: SeverityTrend[] }) {
  return (
    <section className="panel rounded-2xl p-5 sm:p-6">
      <div className="mb-6 flex items-start justify-between">
        <div>
          <div className="eyebrow mb-2">Exposure over time</div>
          <h3 className="text-lg font-semibold text-white">Severity trend</h3>
        </div>
        <div className="rounded-lg border border-slate-700/70 px-2.5 py-1 text-xs text-slate-500">Last 30 days</div>
      </div>
      {trends.length ? (
        <div className="h-[280px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={trends} margin={{ top: 8, right: 8, left: -22, bottom: 0 }}>
              <CartesianGrid stroke="#1d2b3d" vertical={false} />
              <XAxis
                dataKey="date"
                axisLine={false}
                tickLine={false}
                tick={{ fill: "#68788d", fontSize: 11 }}
                tickFormatter={(v: string) => v.slice(5)}
              />
              <YAxis axisLine={false} tickLine={false} tick={{ fill: "#68788d", fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: "#111925", border: "1px solid #2a3b50", borderRadius: 12, color: "#fff" }}
              />
              <Legend iconType="circle" wrapperStyle={{ fontSize: 11, color: "#8d9aab" }} />
              {SERIES.map((series) => (
                <Line
                  key={series.key}
                  type="monotone"
                  dataKey={series.key}
                  stroke={series.color}
                  strokeWidth={2.5}
                  dot={false}
                  name={series.name}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <EmptyState title="No trend data" description="Trend data will appear after the first scan." />
      )}
    </section>
  );
}
