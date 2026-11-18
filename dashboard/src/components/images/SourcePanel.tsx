"use client";

import { FormEvent, useState } from "react";
import { GitBranch } from "lucide-react";
import { cx } from "@/lib/cx";
import type { ImageSource } from "@/types";

type Props = { imageId: number; source: ImageSource | null | undefined; canEdit: boolean; onSaved: () => void };

const FIELD = cx(
  "w-full rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-slate-200",
  "outline-none placeholder:text-slate-600 focus:border-cyan-400/50",
);

async function saveSource(imageId: number, body: Record<string, unknown> | null): Promise<void> {
  const response = await fetch(`/api/images/${imageId}/source`, {
    method: body ? "PUT" : "DELETE",
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    const detail = payload?.detail;
    throw new Error(typeof detail === "string" ? detail : Array.isArray(detail) ? detail[0]?.msg : "Save failed");
  }
}

/** `["npm", "test"]` from the field's text; empty means no test command. Throws on anything else. */
function parseTestCommand(text: string): string[] | null {
  if (!text.trim()) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('Test command must be a JSON list of arguments, e.g. ["npm", "test"]');
  }
  if (!Array.isArray(parsed) || !parsed.length || !parsed.every((part) => typeof part === "string" && part)) {
    throw new Error('Test command must be a JSON list of arguments, e.g. ["npm", "test"]');
  }
  return parsed;
}

/** Where this image is built from. Remediation needs it to patch and rebuild the image. */
export default function SourcePanel({ imageId, source, canEdit, onSaved }: Props) {
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({
    repository: "",
    ref: "HEAD",
    dockerfile_path: "Dockerfile",
    build_context: ".",
    test_command: "",
  });
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  /** Open the form filled with the current source (rather than copying props into state in an effect). */
  function startEditing() {
    if (source) {
      setForm({
        repository: source.repository,
        ref: source.ref,
        dockerfile_path: source.dockerfile_path,
        build_context: source.build_context,
        test_command: source.test_command ? JSON.stringify(source.test_command) : "",
      });
    }
    setNotice(null);
    setEditing(true);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setNotice(null);
    try {
      // Build arguments are not edited here; send them back so saving keeps them.
      await saveSource(imageId, {
        ...form,
        test_command: parseTestCommand(form.test_command),
        build_args: source?.build_args || {},
      });
      setEditing(false);
      onSaved();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  async function disconnect() {
    setSaving(true);
    try {
      await saveSource(imageId, null);
      onSaved();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Remove failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="panel mb-6 rounded-2xl p-5 sm:p-6">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
          <GitBranch className="h-4 w-4 text-cyan-300" /> Source
        </div>
        {canEdit && !editing && (
          <button onClick={startEditing} className="text-xs font-medium text-cyan-300 hover:text-cyan-200">
            {source ? "Edit" : "Connect source"}
          </button>
        )}
      </div>
      {!editing &&
        (source ? (
          <dl className="grid gap-x-6 gap-y-1 text-xs sm:grid-cols-[auto_1fr]">
            <dt className="text-slate-500">Repository</dt>
            <dd className="break-all font-mono text-slate-300">{source.repository}</dd>
            <dt className="text-slate-500">Ref</dt>
            <dd className="font-mono text-slate-300">{source.ref}</dd>
            <dt className="text-slate-500">Dockerfile</dt>
            <dd className="font-mono text-slate-300">{source.dockerfile_path}</dd>
            <dt className="text-slate-500">Build context</dt>
            <dd className="font-mono text-slate-300">{source.build_context}</dd>
            <dt className="text-slate-500">Test command</dt>
            <dd className="break-all font-mono text-slate-300">
              {source.test_command ? source.test_command.join(" ") : "none"}
            </dd>
          </dl>
        ) : (
          <p className="text-sm leading-6 text-slate-400">
            Not connected. Findings are shown, but fixing this image needs the repository and Dockerfile it is built
            from.
          </p>
        ))}
      {editing && (
        <form onSubmit={submit} className="grid gap-3 sm:grid-cols-2">
          <label className="text-xs text-slate-500 sm:col-span-2">
            Repository: an https:// git URL, or a folder under the worker&apos;s sources directory
            <input
              id="source-repository"
              required
              value={form.repository}
              onChange={(e) => setForm({ ...form, repository: e.target.value })}
              placeholder="team/app or https://github.com/acme/app.git"
              className={cx(FIELD, "mt-1")}
            />
          </label>
          <label className="text-xs text-slate-500">
            Branch, tag, or commit
            <input
              id="source-ref"
              value={form.ref}
              onChange={(e) => setForm({ ...form, ref: e.target.value })}
              className={cx(FIELD, "mt-1")}
            />
          </label>
          <label className="text-xs text-slate-500">
            Dockerfile
            <input
              id="source-dockerfile"
              value={form.dockerfile_path}
              onChange={(e) => setForm({ ...form, dockerfile_path: e.target.value })}
              className={cx(FIELD, "mt-1")}
            />
          </label>
          <label className="text-xs text-slate-500">
            Build context
            <input
              id="source-context"
              value={form.build_context}
              onChange={(e) => setForm({ ...form, build_context: e.target.value })}
              className={cx(FIELD, "mt-1")}
            />
          </label>
          <label className="text-xs text-slate-500 sm:col-span-2">
            Test command (optional): runs inside the patched image before it is scanned; a failure fails the fix
            <input
              id="source-test-command"
              value={form.test_command}
              onChange={(e) => setForm({ ...form, test_command: e.target.value })}
              placeholder='["npm", "test"]'
              className={cx(FIELD, "mt-1 font-mono")}
            />
          </label>
          <div className="flex items-end gap-3">
            <button
              disabled={saving}
              className="rounded-xl bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950 disabled:opacity-50"
            >
              {saving ? "Saving…" : "Save source"}
            </button>
            <button type="button" onClick={() => setEditing(false)} className="text-sm text-slate-400">
              Cancel
            </button>
            {source && (
              <button type="button" onClick={disconnect} className="ml-auto text-sm text-rose-300">
                Disconnect
              </button>
            )}
          </div>
        </form>
      )}
      {notice && <p className="mt-3 text-sm text-amber-200">{notice}</p>}
    </section>
  );
}
