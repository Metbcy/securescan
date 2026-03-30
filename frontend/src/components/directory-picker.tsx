"use client";

import { useState, useEffect, useCallback } from "react";
import { Folder, FolderOpen, File, ArrowUp, X, Loader2 } from "lucide-react";
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
}

export function DirectoryPicker({
  isOpen,
  onClose,
  onSelect,
  initialPath,
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
    if (isOpen) {
      navigate(initialPath);
    }
  }, [isOpen, initialPath, navigate]);

  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  // Check whether the current directory looks like a project root
  const projectFileNames = new Set(
    result?.entries.filter((e) => !e.is_dir).map((e) => e.name) ?? [],
  );
  const isProjectRoot = [...projectFileNames].some((n) => PROJECT_FILES.has(n));

  // Build clickable breadcrumb segments from current path
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
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-xl rounded-xl border border-[#262626] bg-[#0a0a0a] shadow-2xl flex flex-col max-h-[80vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#262626]">
          <h2 className="text-sm font-semibold text-[#ededed]">Browse Directory</h2>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-[#262626] text-[#a1a1aa] transition-colors"
          >
            <X size={16} />
          </button>
        </div>

        {/* Breadcrumb */}
        {result && (
          <div className="flex items-center gap-1 px-5 py-3 border-b border-[#262626] overflow-x-auto text-xs">
            <button
              onClick={() => navigate("/")}
              className="text-[#a1a1aa] hover:text-blue-400 shrink-0 transition-colors"
            >
              /
            </button>
            {segments.map((seg, i) => (
              <span key={seg.path} className="flex items-center gap-1 shrink-0">
                <span className="text-[#52525b]">/</span>
                {i < segments.length - 1 ? (
                  <button
                    onClick={() => navigate(seg.path)}
                    className="text-[#a1a1aa] hover:text-blue-400 transition-colors"
                  >
                    {seg.name}
                  </button>
                ) : (
                  <span className="text-[#ededed] font-medium">{seg.name}</span>
                )}
              </span>
            ))}
          </div>
        )}

        {/* Content */}
        <div className="flex-1 overflow-y-auto min-h-0">
          {loading && (
            <div className="flex items-center justify-center py-16">
              <Loader2 size={24} className="animate-spin text-blue-400" />
            </div>
          )}

          {error && (
            <div className="px-5 py-8 text-center">
              <p className="text-sm text-red-400">{error}</p>
              <button
                onClick={() => navigate(result?.current)}
                className="mt-3 text-xs text-blue-400 hover:underline"
              >
                Retry
              </button>
            </div>
          )}

          {!loading && !error && result && (
            <div className="py-1">
              {/* Up button */}
              {result.parent && (
                <button
                  onClick={() => navigate(result.parent!)}
                  className="flex items-center gap-3 w-full px-5 py-2.5 text-left text-sm text-[#a1a1aa] hover:bg-[#141414] transition-colors"
                >
                  <ArrowUp size={16} className="text-[#52525b]" />
                  <span>Up to parent directory</span>
                </button>
              )}

              {result.entries.length === 0 && (
                <p className="px-5 py-8 text-center text-sm text-[#52525b]">
                  Empty directory
                </p>
              )}

              {result.entries.map((entry) => {
                if (entry.is_dir) {
                  // Check if this dir looks like a project root by checking
                  // sibling files (not possible from data alone), so we mark
                  // .git dirs as project indicators
                  const isGit = entry.name === ".git";
                  return (
                    <button
                      key={entry.path}
                      onClick={() => navigate(entry.path)}
                      className="flex items-center gap-3 w-full px-5 py-2.5 text-left text-sm hover:bg-[#141414] transition-colors group"
                    >
                      <Folder size={16} className="text-blue-400 shrink-0" />
                      <span className="text-[#ededed] truncate">{entry.name}</span>
                      {isGit && (
                        <span className="ml-auto text-[10px] font-medium px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 shrink-0">
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
                    <File size={16} className="text-[#52525b] shrink-0" />
                    <span className="text-[#71717a] truncate">{entry.name}</span>
                    {PROJECT_FILES.has(entry.name) && (
                      <span className="ml-auto text-[10px] font-medium px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shrink-0">
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
        <div className="flex items-center justify-between px-5 py-4 border-t border-[#262626]">
          <div className="flex items-center gap-2 min-w-0">
            {isProjectRoot && (
              <span className="flex items-center gap-1.5 text-[10px] font-medium px-2 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shrink-0">
                <FolderOpen size={12} />
                Project root detected
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg text-sm text-[#a1a1aa] hover:bg-[#141414] border border-[#262626] transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={() => result && onSelect(result.current)}
              disabled={!result}
              className="px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 hover:bg-blue-700 text-white transition-colors disabled:opacity-50"
            >
              Select This Directory
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
