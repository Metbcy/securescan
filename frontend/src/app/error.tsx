"use client";

// Per next-best-practices/error-handling.md: an app-level error.tsx
// catches uncaught render/effect errors in any descendant route segment
// and shows a friendly UI instead of Next's default red-screen overlay.
// Without this, users hit blank pages or the dev-mode error stack.

import { AlertTriangle, RefreshCw } from "lucide-react";
import { useEffect } from "react";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Surface the failure on the dev server console so a maintainer
    // running `npm run dev` sees the full stack. In prod the message
    // alone is shown to the user.
    console.error("[securescan/app/error]", error);
  }, [error]);

  return (
    <div className="min-h-[60vh] flex items-center justify-center px-4">
      <div
        role="alert"
        className="w-full max-w-md rounded-md border border-sev-critical/30 bg-sev-critical-bg p-6"
      >
        <div className="flex items-start gap-3">
          <AlertTriangle
            size={20}
            strokeWidth={1.5}
            className="text-sev-critical shrink-0 mt-0.5"
          />
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-semibold text-sev-critical">
              Something went wrong
            </h2>
            <p className="mt-1 text-xs text-muted">
              The dashboard hit an unexpected error. The page state was
              preserved — try reloading the affected view first.
            </p>
            {error.digest && (
              <p className="mt-2 text-[0.6875rem] text-muted font-mono">
                error id: {error.digest}
              </p>
            )}
            <button
              type="button"
              onClick={reset}
              className="mt-4 inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-1.5 text-xs hover:bg-surface-2"
            >
              <RefreshCw size={14} strokeWidth={1.5} />
              Try again
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
