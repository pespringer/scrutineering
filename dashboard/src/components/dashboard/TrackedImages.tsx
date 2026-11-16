import Link from "next/link";
import { ChevronRight, Package } from "lucide-react";
import EmptyState from "@/components/EmptyState";
import { cx } from "@/lib/cx";
import type { ImageDetail } from "@/types";

function openTone(open: number): string {
  if (open > 10) return "text-rose-300";
  if (open > 5) return "text-orange-300";
  return "text-slate-200";
}

export default function TrackedImages({ images }: { images: ImageDetail[] }) {
  return (
    <section className="panel overflow-hidden rounded-2xl">
      <div className="flex items-center justify-between border-b border-slate-800/80 px-5 py-5 sm:px-6">
        <div>
          <div className="eyebrow mb-2">Inventory</div>
          <h3 className="text-lg font-semibold text-white">Tracked images</h3>
        </div>
        <Link href="/images" className="rounded-full bg-slate-800 px-2.5 py-1 text-xs text-slate-500">
          {images.length} shown · view all
        </Link>
      </div>
      <div className="divide-y divide-slate-800/70">
        {images.slice(0, 5).map((image) => (
          <Link
            href={`/images/${image.id}`}
            key={image.id}
            className="group flex items-center gap-4 px-5 py-4 transition hover:bg-slate-800/40 sm:px-6"
          >
            <div
              className={cx(
                "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-700",
                "bg-slate-800/80 text-cyan-300",
              )}
            >
              <Package className="h-4 w-4" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="truncate font-mono text-sm text-slate-200">{image.name}</div>
              <div className="mt-1 flex items-center gap-2 text-xs text-slate-600">
                <span>
                  Last scanned {image.last_scan_at ? new Date(image.last_scan_at).toLocaleDateString() : "never"}
                </span>
                {image.critical_count > 0 && <span className="text-rose-300">· {image.critical_count} critical</span>}
              </div>
            </div>
            <div className="text-right">
              <div className={cx("text-lg font-semibold", openTone(image.open_findings))}>{image.open_findings}</div>
              <div className="text-[10px] uppercase tracking-wider text-slate-600">open</div>
            </div>
            <ChevronRight
              className={cx(
                "h-4 w-4 text-slate-700",
                "transition group-hover:translate-x-0.5 group-hover:text-cyan-300",
              )}
            />
          </Link>
        ))}
        {!images.length && (
          <EmptyState title="No images tracked" description="Your inventory will appear here after scanning." />
        )}
      </div>
    </section>
  );
}
