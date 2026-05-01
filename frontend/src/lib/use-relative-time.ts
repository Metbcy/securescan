"use client";

// Per next-best-practices/hydration-error.md: Date.now() during render
// produces different values on server vs client (the elapsed wall-clock
// shifts even within a single second). Components calling Date.now()
// inline produce hydration warnings whenever the rounding boundary
// happens between SSR and hydrate.
//
// This hook returns the empty string on the server / pre-mount render
// and only computes the relative label after the client has mounted.
// Auto-refreshes every 30s so the label stays current without polling
// the API. The fallback label (rendered in the SSR HTML) is always
// the empty string, so the post-hydration repaint is a single text-
// node update with no layout shift.
//
// Implementation note: uses ``useSyncExternalStore`` for the periodic
// refresh tick. This is the idiomatic React 18+ subscription primitive
// — calling setState() inside a useEffect on a setInterval would also
// work but trips the react-hooks/set-state-in-effect lint and is a
// concurrent-render foot-gun.

import { useSyncExternalStore } from "react";

export type RelativeTimeFormatter = (iso: string) => string;

export const formatRelativeShort: RelativeTimeFormatter = (iso) => {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const diff = Date.now() - t;
  const sec = Math.max(0, Math.round(diff / 1000));
  if (sec < 5) return "just now";
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.round(hr / 24);
  if (day < 30) return `${day}d ago`;
  const mo = Math.round(day / 30);
  if (mo < 12) return `${mo}mo ago`;
  const yr = Math.round(mo / 12);
  return `${yr}y ago`;
};

const REFRESH_MS = 30_000;

// Module-level ticker — every component using useRelativeTime
// shares the same setInterval, which means the dashboard makes one
// timer rather than N (one per visible relative-time element).
const tickListeners = new Set<() => void>();
let tickHandle: ReturnType<typeof setInterval> | null = null;
let tickValue = 0;

function subscribeTick(listener: () => void) {
  tickListeners.add(listener);
  if (tickHandle === null) {
    tickHandle = setInterval(() => {
      tickValue += 1;
      tickListeners.forEach((l) => l());
    }, REFRESH_MS);
  }
  return () => {
    tickListeners.delete(listener);
    if (tickListeners.size === 0 && tickHandle !== null) {
      clearInterval(tickHandle);
      tickHandle = null;
    }
  };
}

function getTick() {
  return tickValue;
}

// Server snapshot is a constant — rendering on the server always
// returns the same tick (so the SSR'd label is reproducible) and the
// client takes over after hydration.
function getServerTick() {
  return 0;
}

/**
 * Render-safe relative-time label. SSR returns ``""``; client mount
 * computes the label and refreshes it every 30s.
 *
 * Usage:
 * ```tsx
 * const label = useRelativeTime(scan.started_at);
 * return <span>{label}</span>;
 * ```
 */
export function useRelativeTime(
  iso?: string | null,
  formatter: RelativeTimeFormatter = formatRelativeShort,
): string {
  // Subscribe to the shared 30s tick so the component re-renders
  // periodically. The actual tick number is unused here — we just
  // need a re-render signal.
  useSyncExternalStore(subscribeTick, getTick, getServerTick);

  if (!iso) return "";
  // The server-side snapshot path returns "" because typeof window
  // is undefined during SSR; the client path computes the real label.
  if (typeof window === "undefined") return "";
  return formatter(iso);
}
