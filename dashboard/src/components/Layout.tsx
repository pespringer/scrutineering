"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, ArrowUpRight, ClipboardList, Gauge, LayoutDashboard, Radar, ShieldCheck } from "lucide-react";

export default function Layout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  return (
    <div className="min-h-screen bg-transparent text-slate-100">
      <div className="mx-auto flex min-h-screen max-w-[1600px]">
        <aside className="hidden w-64 shrink-0 border-r border-slate-800/70 bg-[#0b111a]/80 px-5 py-6 lg:flex lg:flex-col">
          <Link href="/dashboard" className="mb-12 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-blue-400 to-cyan-500 text-sm font-black text-slate-950 shadow-lg shadow-cyan-500/20">CS</div>
            <div><div className="font-semibold tracking-tight">Container</div><div className="text-xs text-slate-500">Sentinel / Control room</div></div>
          </Link>
          <div className="eyebrow mb-3 px-3">Workspace</div>
          <nav className="space-y-1">
            <NavLink href="/dashboard" active={pathname === "/dashboard"} icon={<LayoutDashboard className="h-4 w-4" />}>Overview</NavLink>
            <NavLink href="/scans" active={pathname.startsWith("/scans")} icon={<Radar className="h-4 w-4" />}>Scan history</NavLink>
            <NavLink href="/audit" active={pathname.startsWith("/audit")} icon={<ClipboardList className="h-4 w-4" />}>Audit trail</NavLink>
            <NavLink href="/operations" active={pathname.startsWith("/operations")} icon={<Gauge className="h-4 w-4" />}>Operations</NavLink>
            <NavLink href="/remediations" active={pathname.startsWith("/remediations")} icon={<ShieldCheck className="h-4 w-4" />}>Remediations</NavLink>
          </nav>
          <div className="mt-auto rounded-2xl border border-emerald-400/15 bg-emerald-400/[0.05] p-4">
            <div className="mb-3 flex items-center gap-2 text-sm font-medium text-emerald-300"><span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_12px_rgba(56,211,159,.8)]" />System operational</div>
            <p className="text-xs leading-5 text-slate-500">All services are reporting. Last sync is live from the scan control plane.</p>
          </div>
        </aside>
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-50 border-b border-slate-800/70 bg-[#080b12]/80 backdrop-blur-xl">
            <div className="flex h-16 items-center justify-between px-5 sm:px-8">
              <div className="flex items-center gap-3 lg:hidden"><div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-400 text-xs font-black text-slate-950">CS</div><span className="font-semibold">Container Sentinel</span></div>
              <div className="hidden items-center gap-2 text-sm text-slate-400 sm:flex"><Activity className="h-4 w-4 text-emerald-400" /> Live posture monitoring</div>
              <div className="ml-auto flex items-center gap-3"><span className="hidden rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-400 sm:inline-flex">v0.1.0 · Local</span><div className="flex h-8 w-8 items-center justify-center rounded-full border border-slate-700 bg-slate-800 text-xs font-semibold text-cyan-300">PS</div></div>
            </div>
          <nav className="flex gap-1 overflow-x-auto border-t border-slate-800/50 px-5 py-2 lg:hidden"><NavLink href="/dashboard" active={pathname === "/dashboard"} icon={<LayoutDashboard className="h-4 w-4" />}>Overview</NavLink><NavLink href="/scans" active={pathname.startsWith("/scans")} icon={<Radar className="h-4 w-4" />}>Scans</NavLink><NavLink href="/audit" active={pathname.startsWith("/audit")} icon={<ClipboardList className="h-4 w-4" />}>Audit</NavLink><NavLink href="/operations" active={pathname.startsWith("/operations")} icon={<Gauge className="h-4 w-4" />}>Ops</NavLink><NavLink href="/remediations" active={pathname.startsWith("/remediations")} icon={<ShieldCheck className="h-4 w-4" />}>Fixes</NavLink></nav>
          </header>
          <main className="mx-auto w-full max-w-[1360px] flex-1 px-5 py-8 sm:px-8 lg:px-10">{children}</main>
          <footer className="border-t border-slate-800/70 px-5 py-5 text-xs text-slate-600 sm:px-8 lg:px-10"><div className="mx-auto flex max-w-[1360px] items-center justify-between"><span>Container Sentinel · Security posture control plane</span><span className="hidden items-center gap-1 sm:flex">Protected by <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" /></span></div></footer>
        </div>
      </div>
    </div>
  );
}

function NavLink({ href, children, icon, active }: { href: string; children: React.ReactNode; icon?: React.ReactNode; active?: boolean }) {
  return (
    <Link href={href} className={`group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition ${active ? "bg-blue-400/10 font-medium text-blue-300 ring-1 ring-inset ring-blue-400/20" : "text-slate-500 hover:bg-slate-800/70 hover:text-slate-200"}`}>
      {icon}<span>{children}</span>{active && <ArrowUpRight className="ml-auto h-3.5 w-3.5 opacity-60" />}
    </Link>
  );
}
