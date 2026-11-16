type Props = {
  offset: number;
  count: number;
  total: number;
  pageSize: number;
  noun: string;
  onChange: (offset: number) => void;
};

export default function Pagination({ offset, count, total, pageSize, noun, onChange }: Props) {
  return (
    <div className="mt-5 flex items-center justify-between text-xs text-slate-600">
      <span>
        Showing {total ? offset + 1 : 0}–{Math.min(offset + count, total)} of {total} {noun}
      </span>
      <div className="flex gap-3">
        <button
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - pageSize))}
          className="text-cyan-300 disabled:text-slate-700"
        >
          Previous
        </button>
        <button
          disabled={offset + pageSize >= total}
          onClick={() => onChange(offset + pageSize)}
          className="text-cyan-300 disabled:text-slate-700"
        >
          Next
        </button>
      </div>
    </div>
  );
}
