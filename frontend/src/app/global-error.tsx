"use client";

// Per next-best-practices/error-handling.md: global-error.tsx replaces
// the root layout entirely when an error happens above the page level
// (e.g. a crash inside a client component used by layout.tsx itself).
// Must include its own <html> and <body> because the root layout is
// not rendered when this component takes over.

import { AlertTriangle } from "lucide-react";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en">
      <body
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#0b0b0c",
          color: "#e8e8ea",
          fontFamily:
            "ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif",
        }}
      >
        <div
          role="alert"
          style={{
            maxWidth: 420,
            width: "100%",
            padding: 24,
            border: "1px solid rgba(239, 68, 68, 0.3)",
            borderRadius: 8,
            background: "rgba(127, 29, 29, 0.1)",
          }}
        >
          <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
            <AlertTriangle size={20} color="#ef4444" />
            <div>
              <h2 style={{ fontSize: 14, margin: 0, color: "#ef4444" }}>
                The dashboard crashed
              </h2>
              <p style={{ fontSize: 12, marginTop: 4, color: "#a3a3ad" }}>
                A fatal error occurred above the page boundary. Reloading
                often clears it.
              </p>
              {error.digest && (
                <p
                  style={{
                    marginTop: 8,
                    fontSize: 11,
                    fontFamily: "ui-monospace, monospace",
                    color: "#737382",
                  }}
                >
                  error id: {error.digest}
                </p>
              )}
              <button
                type="button"
                onClick={reset}
                style={{
                  marginTop: 16,
                  padding: "6px 12px",
                  fontSize: 12,
                  border: "1px solid #404049",
                  borderRadius: 6,
                  background: "#1a1a1d",
                  color: "#e8e8ea",
                  cursor: "pointer",
                }}
              >
                Reload
              </button>
            </div>
          </div>
        </div>
      </body>
    </html>
  );
}
