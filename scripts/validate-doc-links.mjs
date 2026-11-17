// Every relative link in the repository's Markdown resolves: the file exists, and a
// `#anchor` matches a heading in it (GitHub's slugs). External links are not fetched.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** GitHub's anchor for a heading: lowercase, punctuation dropped, each space a hyphen. */
export function slug(heading) {
  return heading
    .trim()
    .toLowerCase()
    .replace(/<[^>]+>/g, "")
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .replace(/ /g, "-");
}

/** Markdown without fenced code blocks, whose lines are neither headings nor links. */
function withoutFences(text) {
  return text.replace(/^(```|~~~)[^\n]*\n[\s\S]*?^\1[^\n]*$/gm, "");
}

/** Prose to search for links: no fenced blocks and no inline code, which may contain link-like text. */
function prose(text) {
  return withoutFences(text).replace(/`[^`\n]*`/g, "");
}

/** The anchors a Markdown file defines, with GitHub's -1, -2 suffixes for repeated headings. */
export function anchors(text) {
  const seen = new Map();
  const result = new Set();
  for (const match of withoutFences(text).matchAll(
    /^#{1,6}\s+(.+?)\s*#*\s*$/gm,
  )) {
    const base = slug(match[1].replace(/\[([^\]]*)\]\([^)]*\)/g, "$1"));
    const count = seen.get(base) || 0;
    seen.set(base, count + 1);
    result.add(count ? `${base}-${count}` : base);
  }
  return result;
}

/** Problems with the relative links in `files` (paths relative to `root`). */
export function checkLinks(files, root = process.cwd()) {
  const problems = [];
  const anchorCache = new Map();
  const anchorsOf = (file) => {
    if (!anchorCache.has(file))
      anchorCache.set(file, anchors(fs.readFileSync(file, "utf8")));
    return anchorCache.get(file);
  };
  for (const file of files) {
    const absolute = path.resolve(root, file);
    const text = prose(fs.readFileSync(absolute, "utf8"));
    for (const match of text.matchAll(
      /!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g,
    )) {
      const target = match[1];
      if (/^[a-z][a-z0-9+.-]*:/i.test(target)) continue; // https:, mailto:, ...
      const [linkPath, anchor] = target.split("#", 2);
      const resolved = linkPath
        ? path.resolve(path.dirname(absolute), decodeURI(linkPath))
        : absolute;
      if (!fs.existsSync(resolved)) {
        problems.push(`${file}: ${target} (no such file)`);
        continue;
      }
      if (
        anchor &&
        resolved.endsWith(".md") &&
        !anchorsOf(resolved).has(decodeURIComponent(anchor).toLowerCase())
      ) {
        problems.push(`${file}: ${target} (no heading #${anchor})`);
      }
    }
  }
  return problems;
}

function trackedMarkdown() {
  return execFileSync("git", ["ls-files", "*.md"], { encoding: "utf8" })
    .split("\n")
    .filter(Boolean);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const files = trackedMarkdown();
  const problems = checkLinks(files);
  if (problems.length) {
    console.error(
      `Broken Markdown links:\n${problems.map((problem) => `  ${problem}`).join("\n")}`,
    );
    process.exit(1);
  }
  console.log(`PASS Markdown links resolve in ${files.length} files`);
}
