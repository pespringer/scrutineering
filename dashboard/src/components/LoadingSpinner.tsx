export default function LoadingSpinner() {
  return (
    <div className="space-y-6 py-8" aria-label="Loading dashboard">
      <div className="h-32 animate-pulse rounded-3xl bg-slate-800/60" />
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4"><div className="h-28 animate-pulse rounded-2xl bg-slate-800/60" /><div className="h-28 animate-pulse rounded-2xl bg-slate-800/60" /><div className="h-28 animate-pulse rounded-2xl bg-slate-800/60" /><div className="h-28 animate-pulse rounded-2xl bg-slate-800/60" /></div>
      <div className="h-80 animate-pulse rounded-2xl bg-slate-800/60" />
    </div>
  );
}
