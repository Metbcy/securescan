"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import {
  Folder,
  FolderOpen,
  File,
  ArrowUp,
  X,
  Loader2,
  Package,
} from "lucide-react";
import { browsePath } from "@/lib/api";
import type { BrowseResult } from "@/lib/api";

const PROJECT_FILES = new Set([
  "package.json",
  "pyproject.toml",
  "Cargo.toml",
  "go.mod",
  "Makefile",
  "Dockerfile",
]);

interface DirectoryPickerProps {
  isOpen: boolean;
  onClose: () => void;
  onSelect: (path: string) => void;
  initialPath?: string;
  /**
   * If `true`, render the no-scanners-installed teaching empty state in
   * place of the normal browse view. Lets callers signal that even if the
   * filesystem is browsable, there's nothing useful to scan with yet.
   */
  noScannersInstalled?: boolean;
}

export function DirectoryPicker({
  isOpen,
  onClose,
  onSelect,
  initialPath,
  noScannersInstalled = false,
}: DirectoryPickerProps) {
  const [result, setResult] = useState<BrowseResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const navigate = useCallback(async (path?: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await browsePath(path);
      setResult(data);
    } catch {
      setError("Failed to load directory. Is the backend running?");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isOpen && !noScannersInstalled) {
      navigate(initialPath);
    }
  }, [isOpen, initialPath, navigate, noScannersInstalled]);

  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const projectFileNames = new Set(
    result?.entries.filter((e) => !e.is_dir).map((e) => e.name) ?? [],
  );
  const isProjectRoot = [...projectFileNames].some((n) => PROJECT_FILES.has(n));

  const segments: { name: string; path: string }[] = [];
  if (result) {
    const parts = result.current.split("/").filter(Boolean);
    let built = "";
    for (const part of parts) {
      built += "/" + part;
      segments.push({ name: part, path: built });
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-background/70 backdrop-blur-sm"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-xl rounded-lg border border-border bg-surface shadow-2xl flex flex-col max-h-[80vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <h2 className="text-sm font-semibold text-foreground-strong">
            Browse directory
          </h2>
          <button
            onClick={onClose}
            className="p-1 rounded text-muted hover:bg-surface-2 hover:text-foreground transition-colors"
            aria-label="Close"
          >
            <X size={16} />
          </button>
        </div>

        {noScannersInstalled ? (
          <div className="flex-1 flex flex-col items-center justify-center px-8 py-12 text-center gap-3">
            <div className="h-12 w-12 rounded-full bg-surface-2 border border-border flex items-center justify-center">
              <Package size={20} className="text-muted" strokeWidth={1.5} />
            </div>
            <p className="text-base font-medium text-foreground-strong">
              No scanners installed
            </p>
            <p className="text-sm text-muted max-w-sm leading-relaxed">
              Run{" "}
              <code className="px-1.5 py-0.5 rounded bg-surface-2 border border-border text-xs font-mono">
                pip install securescan[all]
              </code>{" "}
              or visit Scanners to install individual tools.
            </p>
            <Link
              href="/scanners"
              onClick={onClose}
              className="mt-2 inline-flex items-center gap-2 px-4 py-2 rounded-md bg-accent text-accent-foreground text-sm font-medium hover:opacity-90 transition-opacity"
            >
              Go to Scanners
            </Link>
          </div>
        ) : (
          <>
            {/* Breadcrumb */}
            {result && (
              <div className="flex items-center gap-1 px-5 py-3 border-b border-border overflow-x-auto text-xs">
                <button
                  onClick={() => navigate("/")}
                  className="text-muted hover:text-accent shrink-0 transition-colors"
                >
                  /
                </button>
                {segments.map((seg, i) => (
                  <span key={seg.path} className="flex items-center gap-1 shrink-0">
                    <span className="text-muted">/</span>
                    {i < segments.length - 1 ? (
                      <button
                        onClick={() => navigate(seg.path)}
                        className="text-muted hover:text-accent transition-colors"
                      >
                        {seg.name}
                      </button>
                    ) : (
                      <span className="text-foreground-strong font-medium">
                        {seg.name}
                      </span>
                    )}
                  </span>
                ))}
              </div>
            )}

            {/* Content */}
            <div className="flex-1 overflow-y-auto min-h-0">
              {loading && (
                <div className="flex items-center justify-center py-16">
                  <Loader2 size={20} className="animate-spin text-muted" />
                </div>
              )}

              {error && (
                <div className="px-5 py-8 text-center">
                  <p className="text-sm text-sev-critical">{error}</p>
                  <button
                    onClick={() => navigate(result?.current)}
                    className="mt-3 text-xs text-accent hover:underline"
                  >
                    Retry
                  </button>
                </div>
              )}

              {!loading && !error && result && (
                <div className="py-1">
                  {result.parent && (
                    <button
                      onClick={() => navigate(result.parent!)}
                      className="flex items-center gap-3 w-full px-5 py-2.5 text-left text-sm text-muted hover:bg-surface-2 transition-colors"
                    >
                      <ArrowUp size={16} className="text-muted" />
                      <span>Up to parent directory</span>
                    </button>
                  )}

                  {result.entries.length === 0 && (
                    <p className="px-5 py-8 text-center text-sm text-muted">
                      Empty directory
                    </p>
                  )}

                  {result.entries.map((entry) => {
                    if (entry.is_dir) {
                      const isGit = entry.name === ".git";
                      return (
                        <button
                          key={entry.path}
                          onClick={() => navigate(entry.path)}
                          className="flex items-center gap-3 w-full px-5 py-2.5 text-left text-sm hover:bg-surface-2 transition-colors group"
                        >
                          <Folder size={16} className="text-accent shrink-0" />
                          <span className="text-foreground truncate">
                            {entry.name}
                          </span>
                          {isGit && (
                            <span className="ml-auto text-2xs font-medium px-1.5 py-0.5 rounded bg-accent-soft text-accent shrink-0">
                              Git
                            </span>
                          )}
                        </button>
                      );
                    }

                    return (
                      <div
                        key={entry.path}
                        className="flex items-center gap-3 w-full px-5 py-2.5 text-sm"
                      >
                        <File size={16} className="text-muted shrink-0" />
                        <span className="text-muted truncate">{entry.name}</span>
                        {PROJECT_FILES.has(entry.name) && (
                          <span className="ml-auto text-2xs font-medium px-1.5 py-0.5 rounded bg-accent-soft text-accent shrink-0">
                            Project
                          </span>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="flex items-center justify-between px-5 py-4 border-t border-border">
              <div className="flex items-center gap-2 min-w-0">
                {isProjectRoot && (
                  <span className="flex items-center gap-1.5 text-2xs font-medium px-2 py-1 rounded-full bg-accent-soft text-accent shrink-0">
                    <FolderOpen size={12} />
                    Project root detected
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={onClose}
                  className="px-4 py-2 rounded-md text-sm text-foreground bg-card border border-border hover:bg-surface-2 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={() => result && onSelect(result.current)}
                  disabled={!result}
                  className="px-4 py-2 rounded-md text-sm font-medium bg-accent text-accent-foreground hover:opacity-90 transition-opacity disabled:opacity-50"
                >
                  Select this directory
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
