import Link from "next/link";
import { cx } from "@/lib/cx";

/** The loop every finding follows, each step linked to the page where it happens. */
const STEPS = [
  { title: "Scan", detail: "Push or pick an image and scan it", href: "/images" },
  { title: "Triage", detail: "Review the image's findings", href: "/images" },
  { title: "Fix", detail: "Propose, approve, build and verify", href: "/remediations" },
  { title: "Ship", detail: "Open a pull request or apply the patch", href: "/remediations" },
  { title: "Verify", detail: "A rescan of the rebuilt image completes it", href: "/scans" },
];

/** The core loop, shown on the overview page. */
export default function LoopSteps() {
  return (
    <section className="panel mb-6 rounded-2xl p-5 sm:p-6">
      <div className="mb-4">
        <div className="eyebrow mb-2">How it works</div>
        <h2 className="text-lg font-semibold text-white">From image to resolved risk</h2>
        <p className="mt-1 text-sm text-slate-500">
          Every finding follows this path. Each step opens where it happens.
        </p>
      </div>
      <div className="grid gap-3 md:grid-cols-5">
        {STEPS.map((step, index) => (
          <Link
            key={step.title}
            href={step.href}
            className={cx(
              "rounded-xl border border-slate-800 bg-slate-950/40 p-4 transition",
              "hover:border-cyan-400/30 hover:bg-cyan-400/[0.04]",
            )}
          >
            <div
              className={cx(
                "mb-3 flex h-7 w-7 items-center justify-center rounded-full bg-cyan-400/10",
                "text-xs font-bold text-cyan-200",
              )}
            >
              {index + 1}
            </div>
            <div className="text-sm font-medium text-slate-200">{step.title}</div>
            <div className="mt-1 text-xs leading-5 text-slate-500">{step.detail}</div>
          </Link>
        ))}
      </div>
      <div
        className={cx(
          "mt-4 rounded-xl border border-amber-400/15 bg-amber-400/[0.04] px-4 py-3",
          "text-xs leading-5 text-amber-200/80",
        )}
      >
        Opening pull requests needs <code>GITHUB_TOKEN</code> and a github.com source. Without them, apply the verified
        patch yourself; scanning, fixing and verification work the same.
      </div>
    </section>
  );
}
