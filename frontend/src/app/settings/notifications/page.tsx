"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Bell, Loader2, Save } from "lucide-react";

import {
  getNotificationSettings,
  updateNotificationSettings,
  type NotificationEventType,
  type NotificationThresholdSetting,
  type ThresholdSeverity,
} from "@/lib/api";
import { PageHeader } from "@/components/page-header";

const SEVERITY_OPTIONS: { value: ThresholdSeverity; label: string }[] = [
  { value: "info", label: "info (always notify)" },
  { value: "low", label: "low" },
  { value: "medium", label: "medium" },
  { value: "high", label: "high" },
  { value: "critical", label: "critical (only criticals)" },
];

const EVENT_LABELS: Record<NotificationEventType, { title: string; description: string }> = {
  "scan.complete": {
    title: "Scan complete",
    description:
      "Notify when a scan finishes. Threshold is compared against the highest finding severity in the run; clean scans never notify.",
  },
  "scan.failed": {
    title: "Scan failed",
    description:
      "Notify when a scan errors out. Treated as critical severity, so any threshold up to and including critical fires.",
  },
  "scanner.failed": {
    title: "Scanner failed",
    description:
      "Notify when an individual scanner crashes. Same critical synthesis as scan.failed.",
  },
};

const EVENT_ORDER: NotificationEventType[] = [
  "scan.complete",
  "scan.failed",
  "scanner.failed",
];

export default function NotificationSettingsPage() {
  const [rows, setRows] = useState<NotificationThresholdSetting[] | null>(null);
  const [draft, setDraft] = useState<Record<string, ThresholdSeverity>>({});
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const data = await getNotificationSettings();
      setRows(data.thresholds);
      const next: Record<string, ThresholdSeverity> = {};
      for (const r of data.thresholds) {
        next[r.event_type] = r.min_severity;
      }
      setDraft(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load settings");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const dirty = useMemo(() => {
    if (!rows) return false;
    return rows.some((r) => draft[r.event_type] !== r.min_severity);
  }, [rows, draft]);

  const handleSave = useCallback(async () => {
    if (!rows || !dirty) return;
    setSaving(true);
    setError(null);
    try {
      const updates = rows
        .filter((r) => draft[r.event_type] !== r.min_severity)
        .map((r) => ({
          event_type: r.event_type,
          min_severity: draft[r.event_type],
        }));
      const data = await updateNotificationSettings(updates);
      setRows(data.thresholds);
      const next: Record<string, ThresholdSeverity> = {};
      for (const r of data.thresholds) {
        next[r.event_type] = r.min_severity;
      }
      setDraft(next);
      setSavedAt(Date.now());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save settings");
    } finally {
      setSaving(false);
    }
  }, [rows, draft, dirty]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={
          <span className="inline-flex items-center gap-1.5">
            <Bell size={12} aria-hidden /> Settings
          </span>
        }
        title="Notifications"
        meta="Control which events buzz the dashboard bell. Set a per-event minimum severity threshold; events below the threshold are silently dropped."
      />

      {error && (
        <div
          role="alert"
          className="rounded-md border border-sev-critical/40 bg-sev-critical-bg px-4 py-3 text-sm text-sev-critical"
        >
          {error}
        </div>
      )}

      {!rows && !error && (
        <div className="flex items-center gap-2 text-sm text-muted">
          <Loader2 size={14} className="animate-spin" aria-hidden />
          Loading…
        </div>
      )}

      {rows && (
        <div className="space-y-3">
          {EVENT_ORDER.map((event) => {
            const row = rows.find((r) => r.event_type === event);
            if (!row) return null;
            const meta = EVENT_LABELS[event];
            const current = draft[event] ?? row.min_severity;
            const changed = current !== row.min_severity;
            return (
              <div
                key={event}
                className="rounded-md border border-border bg-card p-4"
              >
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <h2 className="text-sm font-semibold text-foreground-strong">
                      {meta.title}
                      <span className="ml-2 font-mono text-[0.6875rem] text-muted">
                        {event}
                      </span>
                    </h2>
                    <p className="mt-1 text-xs text-muted">{meta.description}</p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <label className="sr-only" htmlFor={`sev-${event}`}>
                      Minimum severity for {meta.title}
                    </label>
                    <select
                      id={`sev-${event}`}
                      value={current}
                      onChange={(e) =>
                        setDraft((d) => ({
                          ...d,
                          [event]: e.target.value as ThresholdSeverity,
                        }))
                      }
                      className="rounded-md border border-border bg-card px-2 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-accent"
                    >
                      {SEVERITY_OPTIONS.map((opt) => (
                        <option key={opt.value} value={opt.value}>
                          {opt.label}
                        </option>
                      ))}
                    </select>
                    {changed && (
                      <span className="text-[0.6875rem] uppercase tracking-wider text-accent">
                        unsaved
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}

          <div className="flex items-center gap-3 pt-2">
            <button
              type="button"
              disabled={!dirty || saving}
              onClick={() => void handleSave()}
              className="inline-flex items-center gap-2 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-foreground hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {saving ? (
                <Loader2 size={14} className="animate-spin" aria-hidden />
              ) : (
                <Save size={14} aria-hidden />
              )}
              Save changes
            </button>
            {!dirty && savedAt && (
              <span className="text-xs text-muted">Saved.</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
