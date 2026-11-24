import type { RemediationSource } from "@/types";

/** The source this fix builds from: the image's source as it was when the fix was proposed. */
export default function SourceCopy({ source, changed }: { source?: RemediationSource | null; changed?: boolean }) {
  return (
    <div className="panel rounded-2xl p-5 sm:p-6">
      <div className="mb-4 text-sm font-semibold text-slate-200">Builds from</div>
      {source ? (
        <dl className="grid gap-x-6 gap-y-1 text-xs sm:grid-cols-[auto_1fr]">
          <dt className="text-slate-500">Repository</dt>
          <dd className="break-all font-mono text-slate-300">{source.repository}</dd>
          <dt className="text-slate-500">Ref</dt>
          <dd className="font-mono text-slate-300">{source.ref}</dd>
          <dt className="text-slate-500">Dockerfile</dt>
          <dd className="font-mono text-slate-300">{source.dockerfile_path}</dd>
          <dt className="text-slate-500">Build context</dt>
          <dd className="font-mono text-slate-300">{source.build_context}</dd>
          <dt className="text-slate-500">Build arguments</dt>
          <dd className="break-all font-mono text-slate-300">
            {Object.keys(source.build_args || {}).join(", ") || "none"}
          </dd>
          <dt className="text-slate-500">Test command</dt>
          <dd className="break-all font-mono text-slate-300">
            {source.test_command ? source.test_command.join(" ") : "none"}
          </dd>
        </dl>
      ) : (
        <p className="text-sm text-slate-500">No source was recorded for this fix.</p>
      )}
      {changed && (
        <p className="mt-4 rounded-lg border border-amber-400/30 bg-amber-400/10 px-3 py-2 text-xs text-amber-200">
          The image&apos;s source has changed since this fix was proposed. The fix still builds from the source shown
          here; a retry picks up the change.
        </p>
      )}
    </div>
  );
}
