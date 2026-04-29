"use client";

import { useEffect, useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const POLL_MS = 30_000;
const HEALTH_TIMEOUT_MS = 5_000;
const SLOW_THRESHOLD_MS = 1_500;

type Status = "connecting" | "connected" | "degraded" | "offline";

interface StatusState {
  status: Status;
  durationMs: number | null;
}

async function probe(
  path: string,
  timeoutMs: number,
): Promise<{ ok: boolean; ms: number }> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  const start =
    typeof performance !== "undefined" ? performance.now() : Date.now();
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      signal: ctl.signal,
      cache: "no-store",
    });
    const end =
      typeof performance !== "undefined" ? performance.now() : Date.now();
    return { ok: res.ok, ms: end - start };
  } catch {
    const end =
      typeof performance !== "undefined" ? performance.now() : Date.now();
    return { ok: false, ms: end - start };
  } finally {
    clearTimeout(timer);
  }
}

export function ApiStatus() {
  const [s, setS] = useState<StatusState>({
    status: "connecting",
    durationMs: null,
  });

  useEffect(() => {
    let cancelled = false;

    async function tick() {
      const health = await probe("/health", HEALTH_TIMEOUT_MS);
      if (cancelled) return;

      if (health.ok) {
        const status: Status =
          health.ms > SLOW_THRESHOLD_MS ? "degraded" : "connected";
        setS({ status, durationMs: Math.round(health.ms) });
        return;
      }

      // /health failed — try /ready to differentiate degraded vs fully offline.
      const ready = await probe("/ready", HEALTH_TIMEOUT_MS);
      if (cancelled) return;
      setS({
        status: ready.ok ? "degraded" : "offline",
        durationMs: Math.round(health.ms),
      });
    }

    tick();
    const id = setInterval(tick, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const meta = (() => {
    switch (s.status) {
      case "connected":
        return { label: "Connected", dot: "bg-accent" };
      case "degraded":
        return { label: "Reconnecting", dot: "bg-sev-medium" };
      case "offline":
        return { label: "Offline", dot: "bg-sev-critical" };
      default:
        return { label: "Checking…", dot: "bg-muted" };
    }
  })();

  const tooltip =
    s.durationMs != null ? `${meta.label} · ${s.durationMs}ms` : meta.label;

  return (
    <div
      className="hidden sm:inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs text-muted"
      title={tooltip}
      aria-label={tooltip}
      role="status"
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${meta.dot}`}
        aria-hidden
      />
      <span>{meta.label}</span>
    </div>
  );
}
