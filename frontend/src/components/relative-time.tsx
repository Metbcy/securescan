"use client";

// Stable wrapper around useRelativeTime so that table rows / lists
// can render relative-time labels without each row needing to call
// the hook itself. Renders the empty string on the server (no
// hydration mismatch) then re-renders the label on the client.
//
// Set ``title`` on the rendered <time> via the absolute prop so
// hovering shows the exact timestamp.

import { useRelativeTime } from "@/lib/use-relative-time";

interface RelativeTimeProps {
  iso?: string | null;
  /**
   * Optional title attribute. If omitted, the iso value itself is
   * shown on hover so the user can recover the absolute time.
   */
  title?: string;
  className?: string;
  /**
   * Fallback shown when iso is undefined / unparseable / pre-hydration.
   * Defaults to em-dash so empty cells line up with non-empty ones.
   */
  fallback?: string;
}

export function RelativeTime({
  iso,
  title,
  className,
  fallback = "—",
}: RelativeTimeProps) {
  const label = useRelativeTime(iso ?? undefined);
  const display = label || fallback;
  return (
    <time className={className} title={title ?? iso ?? undefined}>
      {display}
    </time>
  );
}
