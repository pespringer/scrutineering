"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowUpRight, Bell, ClipboardList, LayoutDashboard, Package, Radar, ShieldCheck } from "lucide-react";
import { SystemStatusBadge, SystemStatusPanel } from "@/components/SystemStatusPanel";
import { useSystemStatus } from "@/hooks/useSystemStatus";
import { cx } from "@/lib/cx";

type Session = {
  subject?: string;
  email?: string | null;
  roles?: string[];
  auth_method?: string;
  logout_url?: string | null;
};

type NavItem = { href: string; label: string; icon: React.ReactNode; roles?: string[]; exact?: boolean };

/** The loop, in order. `roles`: only shown to sessions holding one of them (the API enforces it too). */
const NAV: NavItem[] = [
  { href: "/dashboard", label: "Overview", icon: <LayoutDashboard className="h-4 w-4" />, exact: true },
  { href: "/images", label: "Images", icon: <Package className="h-4 w-4" /> },
  { href: "/scans", label: "Scans", icon: <Radar className="h-4 w-4" /> },
  {
    href: "/remediations",
    label: "Remediations",
    icon: <ShieldCheck className="h-4 w-4" />,
    roles: ["remediator", "security-operator", "admin"],
  },
  { href: "/audit", label: "Audit", icon: <ClipboardList className="h-4 w-4" /> },
  {
    href: "/notifications",
    label: "Notifications",
    icon: <Bell className="h-4 w-4" />,
    roles: ["security-operator", "admin"],
  },
];

/** Most capable first: the header shows the strongest role the session holds. */
const ROLE_ORDER = ["admin", "security-operator", "remediator", "operator", "dashboard"];

function NavLinks({ pathname, roles }: { pathname: string; roles: string[] }) {
  return (
    <>
      {NAV.filter((item) => !item.roles || item.roles.some((role) => roles.includes(role))).map((item) => (
        <NavLink
          key={item.href}
          href={item.href}
          icon={item.icon}
          active={item.exact ? pathname === item.href : pathname.startsWith(item.href)}
        >
          {item.label}
        </NavLink>
      ))}
    </>
  );
}

/** Signed in through the proxy, but none of the user's groups maps to a role. */
function NoRole() {
  return (
    <div className="flex min-h-screen items-center justify-center px-5 text-slate-100">
      <div className="panel max-w-md rounded-2xl p-8">
        <h1 className="text-xl font-semibold text-white">No access yet</h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          You are signed in, but none of your groups has a role in Scrutineering. An administrator can add one with{" "}
          <code className="text-slate-300">DASHBOARD_GROUP_ROLES</code>.
        </p>
      </div>
    </div>
  );
}

export default function Layout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const system = useSystemStatus();
  const [session, setSession] = useState<Session | null>(null);
  const [noRole, setNoRole] = useState(false);
  useEffect(() => {
    fetch("/api/session", { cache: "no-store" })
      .then(async (response) => {
        const body = await response.json().catch(() => null);
        if (response.status === 403 && body?.error === "no_role") {
          setNoRole(true);
          return null;
        }
        return response.ok ? body : null;
      })
      .then(setSession)
      .catch(() => setSession(null));
  }, []);
  if (noRole) return <NoRole />;
  const identity = session?.email || session?.subject || "Local operator";
  const role = ROLE_ORDER.find((name) => session?.roles?.includes(name)) || "dashboard";
  return (
    <div className="min-h-screen bg-transparent text-slate-100">
      <div className="mx-auto flex min-h-screen max-w-[1600px]">
        <aside
          className={cx(
            "hidden w-64 shrink-0 border-r border-slate-800/70",
            "bg-[#0b111a]/80 px-5 py-6 lg:flex lg:flex-col",
          )}
        >
          <Link href="/dashboard" className="mb-12 flex items-center gap-3">
            <div
              className={cx(
                "flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br",
                "from-blue-400 to-cyan-500 text-sm font-black text-slate-950 shadow-lg shadow-cyan-500/20",
              )}
            >
              S
            </div>
            <div>
              <div className="font-semibold tracking-tight">Scrutineering</div>
              <div className="text-xs text-slate-500">Scan · fix · verify</div>
            </div>
          </Link>
          <div className="eyebrow mb-3 px-3">Workspace</div>
          <nav className="space-y-1">
            <NavLinks pathname={pathname} roles={session?.roles || []} />
          </nav>
          <SystemStatusPanel system={system} />
        </aside>
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-50 border-b border-slate-800/70 bg-[#080b12]/80 backdrop-blur-xl">
            <div className="flex h-16 items-center justify-between px-5 sm:px-8">
              <div className="flex items-center gap-3 lg:hidden">
                <div
                  className={cx(
                    "flex h-8 w-8 items-center justify-center",
                    "rounded-lg bg-cyan-400 text-xs font-black text-slate-950",
                  )}
                >
                  S
                </div>
                <span className="font-semibold">Scrutineering</span>
              </div>
              <SystemStatusBadge system={system} />
              <div className="ml-auto flex items-center gap-3">
                <span
                  className={cx(
                    "hidden rounded-full border border-slate-700",
                    "px-3 py-1 text-xs text-slate-400",
                    "sm:inline-flex",
                  )}
                >
                  {role} · {identity}
                </span>
                <div
                  title={identity}
                  className={cx(
                    "flex h-8 w-8 items-center justify-center rounded-full border border-slate-700 bg-slate-800",
                    "text-xs font-semibold text-cyan-300",
                  )}
                >
                  {identity.slice(0, 2).toUpperCase()}
                </div>
                {session?.logout_url && (
                  <a href={session.logout_url} className="text-xs text-slate-400 hover:text-white">
                    Sign out
                  </a>
                )}
              </div>
            </div>
            <nav className="flex gap-1 overflow-x-auto border-t border-slate-800/50 px-5 py-2 lg:hidden">
              <NavLinks pathname={pathname} roles={session?.roles || []} />
            </nav>
          </header>
          <main className="mx-auto w-full max-w-[1360px] flex-1 px-5 py-8 sm:px-8 lg:px-10">{children}</main>
          <footer className="border-t border-slate-800/70 px-5 py-5 text-xs text-slate-600 sm:px-8 lg:px-10">
            <div className="mx-auto flex max-w-[1360px] items-center justify-between">
              <span>Scrutineering · container vulnerability scanning and remediation</span>
            </div>
          </footer>
        </div>
      </div>
    </div>
  );
}

function NavLink({
  href,
  children,
  icon,
  active,
}: {
  href: string;
  children: React.ReactNode;
  icon?: React.ReactNode;
  active?: boolean;
}) {
  return (
    <Link
      href={href}
      className={cx(
        "group flex items-center gap-3",
        "rounded-xl px-3 py-2.5 text-sm",
        "transition",
        active
          ? "bg-blue-400/10 font-medium text-blue-300 ring-1 ring-inset ring-blue-400/20"
          : "text-slate-500 hover:bg-slate-800/70 hover:text-slate-200",
      )}
    >
      {icon}
      <span>{children}</span>
      {active && <ArrowUpRight className="ml-auto h-3.5 w-3.5 opacity-60" />}
    </Link>
  );
}
