import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import type { SeverityTrendPoint } from "@/types";

const COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

export function SeverityTrendChart({ data }: { data: SeverityTrendPoint[] }) {
  if (data.length === 0) {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-4">Severity Trend</h3>
        <div className="text-gray-500 text-center py-8">
          No trend data available yet.
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
      <h3 className="text-sm font-semibold text-gray-300 mb-4">Severity Trend Over Time</h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
            <XAxis dataKey="date" stroke="#6b7280" fontSize={11} />
            <YAxis stroke="#6b7280" fontSize={11} />
            <Tooltip
              contentStyle={{ backgroundColor: "#111827", border: "1px solid #1f2937", borderRadius: "8px" }}
              labelStyle={{ color: "#9ca3af" }}
            />
            {(Object.keys(COLORS) as string[]).map((key) => (
              <Line
                key={key}
                type="monotone"
                dataKey={key}
                stroke={COLORS[key]}
                strokeWidth={2}
                dot={false}
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>
      <div className="flex gap-4 mt-2 justify-center">
        {(Object.keys(COLORS) as string[]).map((key) => (
          <div key={key} className="flex items-center gap-1 text-xs text-gray-400">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS[key] }} />
            {key.charAt(0).toUpperCase() + key.slice(1)}
          </div>
        ))}
      </div>
    </div>
  );
}
