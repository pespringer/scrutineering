import { Filter, Search } from "lucide-react";
import { cx } from "@/lib/cx";
import { SCAN_STATUS_FILTERS, type ScanStatusFilter } from "@/hooks/useScanHistory";

type Props = {
  search: string;
  filter: ScanStatusFilter;
  onSearch: (value: string) => void;
  onFilter: (value: ScanStatusFilter) => void;
};

export default function ScanFilters({ search, filter, onSearch, onFilter }: Props) {
  return (
    <div
      className={cx(
        "flex flex-col gap-4 border-b border-slate-800/80 p-5",
        "sm:flex-row sm:items-center sm:justify-between sm:p-6",
      )}
    >
      <div className="relative w-full sm:max-w-sm">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" />
        <input
          id="scan-search"
          aria-label="Search scans"
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="Search images or repositories"
          className={cx(
            "w-full rounded-xl border border-slate-700 bg-slate-900/70 py-2.5 pl-10 pr-4 text-sm text-slate-200",
            "outline-none placeholder:text-slate-600 focus:border-cyan-400/50",
          )}
        />
      </div>
      <div className="flex items-center gap-2 overflow-x-auto">
        <Filter className="h-4 w-4 shrink-0 text-slate-600" />
        {SCAN_STATUS_FILTERS.map((status) => (
          <button
            type="button"
            key={status}
            onClick={() => onFilter(status)}
            className={cx(
              "whitespace-nowrap rounded-lg px-3 py-2 text-xs font-medium capitalize transition",
              filter === status
                ? "bg-cyan-400/10 text-cyan-200 ring-1 ring-inset ring-cyan-300/20"
                : "text-slate-500 hover:bg-slate-800 hover:text-slate-200",
            )}
          >
            {status}
          </button>
        ))}
      </div>
    </div>
  );
}
