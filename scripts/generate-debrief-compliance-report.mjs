import fs from "node:fs";
import path from "node:path";

const projectRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const inputPath = path.join(projectRoot, "fixtures", "hiring", "debrief-events.json");
const outputPath = path.join(projectRoot, "docs", "hiring", "weekly-debrief-compliance-report.md");

const now = process.env.REPORT_NOW ? new Date(process.env.REPORT_NOW) : new Date();
if (Number.isNaN(now.getTime())) {
  throw new Error("REPORT_NOW must be an ISO-8601 timestamp");
}

const raw = fs.readFileSync(inputPath, "utf8");
const records = JSON.parse(raw);

const endOfDayUtc = (isoTimestamp) => {
  const d = new Date(isoTimestamp);
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), 23, 59, 59, 999));
};

const rows = records.map((record) => {
  const dueAt = endOfDayUtc(record.interviewEndedAt);
  const submittedAt = record.debriefSubmittedAt ? new Date(record.debriefSubmittedAt) : null;

  let status = "on_time";
  if (!submittedAt && now > dueAt) {
    status = "overdue_open";
  } else if (submittedAt && submittedAt > dueAt) {
    status = "overdue_submitted";
  }

  return {
    ...record,
    dueAt: dueAt.toISOString(),
    status,
  };
});

const totals = {
  total: rows.length,
  onTime: rows.filter((r) => r.status === "on_time").length,
  overdueOpen: rows.filter((r) => r.status === "overdue_open").length,
  overdueSubmitted: rows.filter((r) => r.status === "overdue_submitted").length,
};

const lines = [];
lines.push("# Weekly Debrief Compliance Report");
lines.push("");
lines.push(`Generated at: ${now.toISOString()}`);
lines.push("");
lines.push("## Summary");
lines.push("");
lines.push(`- Total interviews: ${totals.total}`);
lines.push(`- On-time debriefs: ${totals.onTime}`);
lines.push(`- Overdue and still open: ${totals.overdueOpen}`);
lines.push(`- Overdue but submitted late: ${totals.overdueSubmitted}`);
lines.push("");
lines.push("## Detailed View");
lines.push("");
lines.push("| Interview | Candidate | Loop | Owner | Ended (UTC) | Due (UTC) | Submitted (UTC) | Status |",);
lines.push("|---|---|---|---|---|---|---|---|");

for (const row of rows) {
  lines.push(
    `| ${row.interviewId} | ${row.candidate} | ${row.loop} | ${row.owner} | ${row.interviewEndedAt} | ${row.dueAt} | ${row.debriefSubmittedAt ?? "-"} | ${row.status} |`,
  );
}

lines.push("");
lines.push("Status legend: `on_time`, `overdue_open`, `overdue_submitted`.");

fs.writeFileSync(outputPath, `${lines.join("\n")}\n`, "utf8");
console.log(`Wrote ${outputPath}`);
