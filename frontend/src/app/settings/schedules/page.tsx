"use client";

import { useCallback, useEffect, useState } from "react";
import {
  CalendarClock,
  Check,
  Loader2,
  MoreHorizontal,
  Pencil,
  Plus,
  Power,
  PowerOff,
  Trash2,
  X,
} from "lucide-react";
import {
  createSchedule,
  deleteSchedule,
  listScheduleRuns,
  listSchedules,
  patchSchedule,
} from "@/lib/api";
import type { Schedule, ScheduleRun, ScanType } from "@/lib/api";
import { PageHeader } from "@/components/page-header";
import { DataTable, type Column } from "@/components/data-table";

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

const ALL_SCAN_TYPES: ScanType[] = ["code", "dependency", "iac", "baseline", "dast", "network"];

function relativeTime(iso?: string | null): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "never";
  const diff = Date.now() - then;
  const sec = Math.round(diff / 1000);
  if (sec < 5) return "just now";
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.round(hr / 24);
  return `${day}d ago`;
}

function fullTime(iso?: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString();
}

/* ------------------------------------------------------------------ */
/* Toast                                                                */
/* ------------------------------------------------------------------ */

interface Toast {
  id: number;
  kind: "success" | "error";
  message: string;
}

let _toastId = 0;

function useToasts() {
  const [toasts, setToasts] = useState<Toast[]>([]);

  function push(kind: Toast["kind"], message: string) {
    const id = ++_toastId;
    setToasts((prev) => [...prev, { id, kind, message }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 3500);
  }

  function dismiss(id: number) {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }

  return { toasts, push, dismiss };
}

function ToastStack({ toasts, dismiss }: { toasts: Toast[]; dismiss: (id: number) => void }) {
  if (!toasts.length) return null;
  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`flex items-center gap-3 rounded-lg border px-4 py-3 text-sm shadow-lg transition-all ${
            t.kind === "success"
              ? "border-accent/30 bg-accent-soft text-accent"
              : "border-red-500/30 bg-red-500/10 text-red-400"
          }`}
        >
          {t.kind === "success" ? <Check size={14} /> : <X size={14} />}
          <span>{t.message}</span>
          <button
            type="button"
            onClick={() => dismiss(t.id)}
            className="ml-2 opacity-60 hover:opacity-100"
            aria-label="Dismiss"
          >
            <X size={12} />
          </button>
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Create/Edit Modal                                                    */
/* ------------------------------------------------------------------ */

interface ScheduleFormState {
  name: string;
  target_path: string;
  scan_types: ScanType[];
  cron_expression: string;
}

const BLANK_FORM: ScheduleFormState = {
  name: "",
  target_path: "",
  scan_types: ["code", "dependency"],
  cron_expression: "0 2 * * *",
};

interface ScheduleModalProps {
  initial?: ScheduleFormState;
  title: string;
  submitLabel: string;
  busy: boolean;
  error: string | null;
  onSubmit: (state: ScheduleFormState) => void;
  onClose: () => void;
}

function ScheduleModal({
  initial = BLANK_FORM,
  title,
  submitLabel,
  busy,
  error,
  onSubmit,
  onClose,
}: ScheduleModalProps) {
  const [form, setForm] = useState<ScheduleFormState>(initial);

  function toggleType(t: ScanType) {
    setForm((prev) => ({
      ...prev,
      scan_types: prev.scan_types.includes(t)
        ? prev.scan_types.filter((x) => x !== t)
        : [...prev.scan_types, t],
    }));
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-md rounded-xl border border-border bg-card p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-5 flex items-center justify-between">
          <h2 className="text-base font-semibold">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            className="text-muted hover:text-foreground"
            aria-label="Close"
          >
            <X size={18} />
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-muted" htmlFor="s-name">
              Name
            </label>
            <input
              id="s-name"
              className="w-full rounded-md border border-border bg-surface-2 px-3 py-2 text-sm outline-none focus:border-accent"
              value={form.name}
              onChange={(e) => setForm((p) => ({ ...p, name: e.target.value }))}
              placeholder="Nightly scan"
            />
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-medium text-muted" htmlFor="s-path">
              Target path
            </label>
            <input
              id="s-path"
              className="w-full rounded-md border border-border bg-surface-2 px-3 py-2 font-mono text-sm outline-none focus:border-accent"
              value={form.target_path}
              onChange={(e) => setForm((p) => ({ ...p, target_path: e.target.value }))}
              placeholder="/home/user/project"
            />
          </div>

          <div>
            <p className="mb-1.5 text-xs font-medium text-muted">Scan types</p>
            <div className="flex flex-wrap gap-2">
              {ALL_SCAN_TYPES.map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => toggleType(t)}
                  className={`rounded-full border px-2.5 py-0.5 font-mono text-[0.6875rem] transition-colors ${
                    form.scan_types.includes(t)
                      ? "border-accent/40 bg-accent-soft text-accent"
                      : "border-border bg-surface-2 text-muted hover:text-foreground"
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-medium text-muted" htmlFor="s-cron">
              Cron expression
            </label>
            <input
              id="s-cron"
              className="w-full rounded-md border border-border bg-surface-2 px-3 py-2 font-mono text-sm outline-none focus:border-accent"
              value={form.cron_expression}
              onChange={(e) => setForm((p) => ({ ...p, cron_expression: e.target.value }))}
              placeholder="0 2 * * *"
            />
            <p className="mt-1 text-[0.6875rem] text-muted">
              Standard 5-field cron: minute hour day-of-month month day-of-week
            </p>
          </div>

          {error && (
            <p className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
              {error}
            </p>
          )}

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md border border-border px-4 py-2 text-sm text-muted hover:text-foreground"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={busy || !form.name || !form.target_path || !form.cron_expression || !form.scan_types.length}
              onClick={() => onSubmit(form)}
              className="flex items-center gap-2 rounded-md bg-accent px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
            >
              {busy && <Loader2 size={14} className="animate-spin" />}
              {submitLabel}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Runs Drawer                                                          */
/* ------------------------------------------------------------------ */

function RunsDrawer({ schedule, onClose }: { schedule: Schedule; onClose: () => void }) {
  const [runs, setRuns] = useState<ScheduleRun[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listScheduleRuns(schedule.id)
      .then(setRuns)
      .catch((err: Error) => setError(err.message));
  }, [schedule.id]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-end justify-center bg-black/60 p-4 sm:items-center"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-xl border border-border bg-card shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <div>
            <p className="text-sm font-semibold">{schedule.name}</p>
            <p className="text-xs text-muted">Run history (last 50)</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-muted hover:text-foreground"
            aria-label="Close"
          >
            <X size={18} />
          </button>
        </div>

        <div className="max-h-80 overflow-y-auto">
          {error && (
            <p className="px-5 py-4 text-sm text-red-400">{error}</p>
          )}
          {!runs && !error && (
            <div className="flex justify-center py-8">
              <Loader2 size={20} className="animate-spin text-muted" />
            </div>
          )}
          {runs && runs.length === 0 && (
            <p className="px-5 py-8 text-center text-sm text-muted">No runs yet</p>
          )}
          {runs && runs.length > 0 && (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-surface-2/40 text-xs text-muted">
                  <th className="px-5 py-2.5 text-left font-medium uppercase tracking-wide">Triggered</th>
                  <th className="px-5 py-2.5 text-left font-medium uppercase tracking-wide">Scan ID</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr
                    key={run.id}
                    className="border-b border-border last:border-b-0 hover:bg-surface-2"
                  >
                    <td className="px-5 py-3 text-muted" title={fullTime(run.triggered_at)}>
                      {relativeTime(run.triggered_at)}
                    </td>
                    <td className="px-5 py-3 font-mono text-xs">
                      {run.scan_id ? (
                        <a
                          href={`/scan/${run.scan_id}`}
                          className="text-accent hover:underline"
                        >
                          {run.scan_id.slice(0, 8)}…
                        </a>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Row menu                                                             */
/* ------------------------------------------------------------------ */

function RowMenu({
  schedule,
  onEdit,
  onToggle,
  onDelete,
  onHistory,
}: {
  schedule: Schedule;
  onEdit: () => void;
  onToggle: () => void;
  onDelete: () => void;
  onHistory: () => void;
}) {
  const [open, setOpen] = useState(false);

  return (
    <div className="relative inline-block">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="inline-flex h-7 w-7 items-center justify-center rounded-md text-muted hover:bg-surface-2 hover:text-foreground"
        aria-label="Actions"
      >
        <MoreHorizontal size={16} />
      </button>
      {open && (
        <>
          <div
            className="fixed inset-0 z-10"
            onClick={() => setOpen(false)}
            aria-hidden
          />
          <div className="absolute right-0 z-20 mt-1 w-44 rounded-lg border border-border bg-card py-1 shadow-lg">
            <button
              type="button"
              onClick={() => { setOpen(false); onHistory(); }}
              className="flex w-full items-center gap-2 px-3 py-2 text-sm text-muted hover:bg-surface-2 hover:text-foreground"
            >
              <CalendarClock size={14} /> History
            </button>
            <button
              type="button"
              onClick={() => { setOpen(false); onEdit(); }}
              className="flex w-full items-center gap-2 px-3 py-2 text-sm text-muted hover:bg-surface-2 hover:text-foreground"
            >
              <Pencil size={14} /> Edit
            </button>
            <button
              type="button"
              onClick={() => { setOpen(false); onToggle(); }}
              className="flex w-full items-center gap-2 px-3 py-2 text-sm text-muted hover:bg-surface-2 hover:text-foreground"
            >
              {schedule.enabled ? <PowerOff size={14} /> : <Power size={14} />}
              {schedule.enabled ? "Disable" : "Enable"}
            </button>
            <div className="my-1 border-t border-border" />
            <button
              type="button"
              onClick={() => { setOpen(false); onDelete(); }}
              className="flex w-full items-center gap-2 px-3 py-2 text-sm text-red-400 hover:bg-red-500/10"
            >
              <Trash2 size={14} /> Delete
            </button>
          </div>
        </>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Delete confirm modal                                                 */
/* ------------------------------------------------------------------ */

function DeleteModal({
  schedule,
  busy,
  onConfirm,
  onClose,
}: {
  schedule: Schedule;
  busy: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-sm rounded-xl border border-border bg-card p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-3 text-base font-semibold">Delete schedule?</h2>
        <p className="mb-5 text-sm text-muted">
          <span className="font-medium text-foreground">{schedule.name}</span> and all its run
          history will be permanently deleted.
        </p>
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-border px-4 py-2 text-sm text-muted hover:text-foreground"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={onConfirm}
            className="flex items-center gap-2 rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50 hover:bg-red-700"
          >
            {busy && <Loader2 size={14} className="animate-spin" />}
            Delete
          </button>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Page                                                                 */
/* ------------------------------------------------------------------ */

export default function SchedulesPage() {
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const { toasts, push, dismiss } = useToasts();

  const [showCreate, setShowCreate] = useState(false);
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const [editTarget, setEditTarget] = useState<Schedule | null>(null);
  const [editBusy, setEditBusy] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);

  const [deleteTarget, setDeleteTarget] = useState<Schedule | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);

  const [historyTarget, setHistoryTarget] = useState<Schedule | null>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await listSchedules();
      setSchedules(data);
    } catch (err) {
      setFetchError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function handleCreate(form: ScheduleFormState) {
    setCreateBusy(true);
    setCreateError(null);
    try {
      const created = await createSchedule(form);
      setSchedules((prev) => [created, ...prev]);
      setShowCreate(false);
      push("success", `Schedule "${created.name}" created`);
    } catch (err) {
      setCreateError((err as Error).message);
    } finally {
      setCreateBusy(false);
    }
  }

  async function handleEdit(form: ScheduleFormState) {
    if (!editTarget) return;
    setEditBusy(true);
    setEditError(null);
    try {
      const updated = await patchSchedule(editTarget.id, form);
      setSchedules((prev) => prev.map((s) => (s.id === updated.id ? updated : s)));
      setEditTarget(null);
      push("success", `Schedule "${updated.name}" updated`);
    } catch (err) {
      setEditError((err as Error).message);
    } finally {
      setEditBusy(false);
    }
  }

  async function handleToggle(schedule: Schedule) {
    try {
      const updated = await patchSchedule(schedule.id, { enabled: !schedule.enabled });
      setSchedules((prev) => prev.map((s) => (s.id === updated.id ? updated : s)));
      push("success", `Schedule "${updated.name}" ${updated.enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      push("error", (err as Error).message);
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    setDeleteBusy(true);
    try {
      await deleteSchedule(deleteTarget.id);
      setSchedules((prev) => prev.filter((s) => s.id !== deleteTarget.id));
      push("success", `Schedule "${deleteTarget.name}" deleted`);
      setDeleteTarget(null);
    } catch (err) {
      push("error", (err as Error).message);
    } finally {
      setDeleteBusy(false);
    }
  }

  const columns: Column<Schedule>[] = [
    {
      key: "name",
      header: "Name",
      cell: (row) => (
        <span className="font-medium text-foreground-strong">{row.name}</span>
      ),
    },
    {
      key: "target_path",
      header: "Target",
      cell: (row) => (
        <span className="font-mono text-xs text-muted" title={row.target_path}>
          {row.target_path.length > 40 ? `…${row.target_path.slice(-38)}` : row.target_path}
        </span>
      ),
    },
    {
      key: "scan_types",
      header: "Types",
      cell: (row) => (
        <div className="flex flex-wrap gap-1">
          {row.scan_types.map((t) => (
            <span
              key={t}
              className="inline-flex items-center rounded-full border border-border bg-surface-2 px-2 py-0.5 font-mono text-[0.6875rem] text-foreground"
            >
              {t}
            </span>
          ))}
        </div>
      ),
    },
    {
      key: "cron_expression",
      header: "Cron",
      cell: (row) => (
        <span className="font-mono text-xs text-foreground">{row.cron_expression}</span>
      ),
    },
    {
      key: "last_run",
      header: "Last run",
      cell: (row) => (
        <span className="text-muted" title={fullTime(row.last_run)}>
          {relativeTime(row.last_run)}
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      cell: (row) =>
        row.enabled ? (
          <span className="inline-flex items-center gap-1 rounded-full border border-accent/40 bg-accent-soft px-2 py-0.5 text-[0.6875rem] text-accent">
            <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-accent" />
            Active
          </span>
        ) : (
          <span className="inline-flex items-center rounded-full border border-border bg-surface-2 px-2 py-0.5 text-[0.6875rem] text-muted">
            Disabled
          </span>
        ),
    },
    {
      key: "actions",
      header: "",
      align: "right",
      cell: (row) => (
        <RowMenu
          schedule={row}
          onEdit={() => setEditTarget(row)}
          onToggle={() => handleToggle(row)}
          onDelete={() => setDeleteTarget(row)}
          onHistory={() => setHistoryTarget(row)}
        />
      ),
    },
  ];

  return (
    <>
      <ToastStack toasts={toasts} dismiss={dismiss} />

      {showCreate && (
        <ScheduleModal
          title="Create schedule"
          submitLabel="Create"
          busy={createBusy}
          error={createError}
          onSubmit={handleCreate}
          onClose={() => { setShowCreate(false); setCreateError(null); }}
        />
      )}

      {editTarget && (
        <ScheduleModal
          title="Edit schedule"
          submitLabel="Save"
          busy={editBusy}
          error={editError}
          initial={{
            name: editTarget.name,
            target_path: editTarget.target_path,
            scan_types: editTarget.scan_types,
            cron_expression: editTarget.cron_expression,
          }}
          onSubmit={handleEdit}
          onClose={() => { setEditTarget(null); setEditError(null); }}
        />
      )}

      {deleteTarget && (
        <DeleteModal
          schedule={deleteTarget}
          busy={deleteBusy}
          onConfirm={handleDelete}
          onClose={() => setDeleteTarget(null)}
        />
      )}

      {historyTarget && (
        <RunsDrawer
          schedule={historyTarget}
          onClose={() => setHistoryTarget(null)}
        />
      )}

      <div className="flex flex-col gap-6 p-6">
        <PageHeader
          title="Schedules"
          meta="Cron-driven recurring scans"
          actions={
            <button
              type="button"
              onClick={() => setShowCreate(true)}
              className="flex items-center gap-2 rounded-md bg-accent px-3 py-2 text-sm font-medium text-white hover:bg-accent/90"
            >
              <Plus size={16} />
              New schedule
            </button>
          }
        />

        {fetchError && (
          <div className="rounded-lg border border-red-500/20 bg-red-500/5 px-4 py-3 text-sm text-red-400">
            {fetchError}
          </div>
        )}

        {loading ? (
          <div className="flex justify-center py-12">
            <Loader2 size={24} className="animate-spin text-muted" />
          </div>
        ) : (
          <DataTable
            data={schedules}
            columns={columns}
            getRowKey={(row) => row.id}
            emptyState={
              <div className="flex flex-col items-center gap-3 py-12 text-center">
                <CalendarClock size={32} className="text-muted/50" />
                <p className="text-sm text-muted">No schedules yet</p>
                <button
                  type="button"
                  onClick={() => setShowCreate(true)}
                  className="flex items-center gap-2 rounded-md bg-accent px-3 py-2 text-sm font-medium text-white hover:bg-accent/90"
                >
                  <Plus size={14} />
                  Create your first schedule
                </button>
              </div>
            }
          />
        )}
      </div>
    </>
  );
}
