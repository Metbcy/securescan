"use client";

// Hydration-safe "has the client mounted yet?" hook. Returns false
// during SSR / pre-hydration render and true after the client takes
// over. Useful for gating reads of state that only resolves on the
// client (next-themes' resolvedTheme, browser APIs, etc.) so the SSR
// pass produces a stable, theme-neutral output.
//
// Implemented with useSyncExternalStore so the lint rule
// react-hooks/set-state-in-effect stays happy. The classic
// useState+useEffect("setMounted(true)") pattern works at runtime but
// trips that lint and is a known concurrent-render foot-gun.

import { useSyncExternalStore } from "react";

const noopSubscribe = () => () => {};

export function useIsMounted(): boolean {
  return useSyncExternalStore(
    noopSubscribe,
    () => true,
    () => false,
  );
}
