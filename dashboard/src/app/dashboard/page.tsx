"use client";

import { use, useEffect, useState } from "react";
import Layout from "@/components/Layout";
import StatCard from "@/components/StatCard";
import SeverityBadge from "@/components/SeverityBadge";
import LoadingSpinner from "@/components/LoadingSpinner";
import EmptyState from "@/components/EmptyState";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from "recharts";
import { Shield, ShieldAlert, AlertTriangle, AlertCircle, Info, Package, Calendar, Clock } from "lucide-react";
import type { SeverityTrend, ScanResult, ImageDetail, VulnerabilityFinding } from "@/types";

export default function DashboardPage() {
  const [posture, setPosture] = useState<any>(null);
  const [trends, setTrends] = useState<SeverityTrend[]>([]);
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [images, setImages] = useState<ImageDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const API = process.env.NEXT_PUBLIC_API_URL || "";
    Promise.all([
      fetch(`${API}/api/posture/summary`).then(r => r.json()),
      fetch(`${API}/api/posture/trend`).then(r => r.json()),
      fetch(`${API}/api/scans`).then(r => r.json()),
      fetch(`${API}/api/images`).then(r => r.json()),
    ])
      .then(([{ posture: p, trends: t, scans: s, images: i }]) => {
        setPosture(p);
        setTrends(t);
        setScans(s);
        setImages(i);
        setLoading(false);
      })
      .catch((err) => {
        // Fallback to local seed if external API fails
        fetch(`/api/posture/summary`).then(r => r.json()).then(p => setPosture(p)).catch(() => {});
        fetch(`/api/posture/trend`).then(r => r.json()).then(t => setTrends(t)).catch(() => {});
        fetch(`/api/scans`).then(r => r.json()).then(s => setScans(s)).catch(() => {});
        fetch(`/api/images`).then(r => r.json()).then(i => setImages(i)).catch(() => {});
        setLoading(false);
      });
  }, []);

  if (loading) return <Layout><LoadingSpinner /></Layout>;

  const p = posture || {
    total_scanned_images: 0, total_findings: 0, critical_count: 0,
    high_count: 0, medium_count: 0, low_count: 0, fixable_count: 0,
    last_scan_at: null, last_scan_status: null,
  };

  return (
    <Layout>
      <div className="mb-6">
        <h2 className="text-2xl font-bold tracking-tight">Security Posture</h2>
        <p className="text-slate-400 mt-1">Overview of container vulnerability scanning</p>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
        <StatCard label="Images" value={p.total_scanned_images} icon={<Package className="w-4 h-4" />} color="blue" />
        <StatCard label="Total Findings" value={p.total_findings} icon={<Shield className="w-4 h-4" />} />
        <StatCard label="Critical" value={p.critical_count} icon={<ShieldAlert className="w-4 h-4" />} color="red" />
        <StatCard label="High" value={p.high_count} icon={<AlertTriangle className="w-4 h-4" />} color="orange" />
        <StatCard label="Medium" value={p.medium_count} icon={<AlertCircle className="w-4 h-4" />} color="yellow" />
        <StatCard label="Fixable" value={p.fixable_count} icon={<Info className="w-4 h-4" />} color="green" />
      </div>

      {/* Severity Trend Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/50 p-6">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Calendar className="w-4 h-4 text-slate-400" />
            Severity Trend
          </h3>
          {trends.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={trends}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="date" stroke="#94a3b8" fontSize={12} tickFormatter={(v: string) => v.slice(5)} />
                <YAxis stroke="#94a3b8" fontSize={12} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#1e293b", border: "1px solid #334155", borderRadius: "8px" }}
                  labelStyle={{ color: "#f1f5f9" }}
                />
                <Legend />
                <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} dot={{ r: 3 }} name="Critical" />
                <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} dot={{ r: 3 }} name="High" />
                <Line type="monotone" dataKey="medium" stroke="#eab308" strokeWidth={2} dot={{ r: 3 }} name="Medium" />
                <Line type="monotone" dataKey="low" stroke="#3b82f6" strokeWidth={2} dot={{ r: 3 }} name="Low" />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState message="No trend data available" />
          )}
        </div>

        {/* Recent Scans */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Clock className="w-4 h-4 text-slate-400" />
            Recent Scans
          </h3>
          <div className="space-y-3">
            {scans.slice(0, 5).map((scan) => (
              <div key={scan.scan_id} className="p-3 rounded-lg bg-slate-800/50 border border-slate-700/50">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium truncate" title={scan.image_name}>{scan.image_name}</span>
                  <span className={`text-xs px-2 py-0.5 rounded-full ${
                    scan.status === "completed" ? "bg-green-500/20 text-green-400" :
                    scan.status === "failed" ? "bg-red-500/20 text-red-400" :
                    "bg-yellow-500/20 text-yellow-400"
                  }`}>{scan.status}</span>
                </div>
                <div className="flex gap-2 text-xs text-slate-400">
                  <span>{scan.findings} findings</span>
                  <span className={scan.critical_count > 0 ? "text-red-400" : ""}>
                    {scan.critical_count}C
                  </span>
                  <span className={scan.high_count > 0 ? "text-orange-400" : ""}>
                    {scan.high_count}H
                  </span>
                </div>
              </div>
            ))}
            {scans.length === 0 && <EmptyState message="No scan history" />}
          </div>
        </div>
      </div>

      {/* Images Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
        <h3 className="text-lg font-semibold mb-4">Tracked Images</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700/50 text-slate-400 text-left">
                <th className="pb-3 font-medium">Image</th>
                <th className="pb-3 font-medium">Findings</th>
                <th className="pb-3 font-medium hidden md:table-cell">Critical</th>
                <th className="pb-3 font-medium hidden md:table-cell">High</th>
                <th className="pb-3 font-medium hidden md:table-cell">Medium</th>
                <th className="pb-3 font-medium hidden md:table-cell">Last Scan</th>
              </tr>
            </thead>
            <tbody>
              {images.map((img) => (
                <tr key={img.id} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 font-mono text-xs">
                    <span className="text-slate-400">{img.registry === "dockerhub" ? "docker.io/" : `${img.registry}/`}</span>
                    <span>{img.repo_name}:{img.tag}</span>
                  </td>
                  <td className="py-3">
                    <span className={`font-semibold ${img.open_findings > 10 ? "text-red-400" : img.open_findings > 5 ? "text-orange-400" : "text-slate-300"}`}>
                      {img.open_findings}
                    </span>
                  </td>
                  <td className="py-3 hidden md:table-cell">
                    <span className={img.critical_count > 0 ? "text-red-400 font-semibold" : "text-slate-500"}>{img.critical_count}</span>
                  </td>
                  <td className="py-3 hidden md:table-cell">
                    <span className={img.high_count > 0 ? "text-orange-400" : "text-slate-500"}>{img.high_count}</span>
                  </td>
                  <td className="py-3 hidden md:table-cell">
                    <span className="text-yellow-400">{img.medium_count}</span>
                  </td>
                  <td className="py-3 text-xs text-slate-500 hidden md:table-cell">
                    {img.last_scan_at ? new Date(img.last_scan_at).toLocaleDateString() : "Never"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </Layout>
  );
}
