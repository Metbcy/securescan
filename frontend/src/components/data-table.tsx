"use client";

import { ChevronDown, ChevronUp, ChevronsUpDown } from "lucide-react";
import type { ReactNode } from "react";

export type SortDirection = "asc" | "desc";

export interface SortState {
  key: string;
  direction: SortDirection;
}

export interface Column<T> {
  key: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  sortable?: boolean;
  width?: string;
  align?: "left" | "right" | "center";
  className?: string;
  headerClassName?: string;
}

export type Density = "compact" | "comfortable";

interface DataTableProps<T> {
  data: T[];
  columns: Column<T>[];
  sort?: SortState;
  onSortChange?: (next: SortState) => void;
  onRowClick?: (row: T) => void;
  getRowKey: (row: T) => string;
  density?: Density;
  rowClassName?: (row: T) => string | undefined;
  emptyState?: ReactNode;
}

const ALIGN: Record<NonNullable<Column<unknown>["align"]>, string> = {
  left: "text-left",
  right: "text-right",
  center: "text-center",
};

export function DataTable<T>({
  data,
  columns,
  sort,
  onSortChange,
  onRowClick,
  getRowKey,
  density = "compact",
  rowClassName,
  emptyState,
}: DataTableProps<T>) {
  const cellPad = density === "comfortable" ? "px-4 py-4" : "px-4 py-3";
  const headPad = density === "comfortable" ? "px-4 py-3" : "px-4 py-2.5";

  function toggleSort(col: Column<T>) {
    if (!col.sortable || !onSortChange) return;
    if (sort?.key === col.key) {
      onSortChange({ key: col.key, direction: sort.direction === "asc" ? "desc" : "asc" });
    } else {
      onSortChange({ key: col.key, direction: "desc" });
    }
  }

  return (
    <div className="overflow-x-auto rounded-md border border-border bg-card">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-surface-2/40 text-muted">
            {columns.map((col) => {
              const align = col.align ?? "left";
              const isActive = sort?.key === col.key;
              const sortable = !!col.sortable;
              return (
                <th
                  key={col.key}
                  scope="col"
                  className={`${headPad} ${ALIGN[align]} text-xs font-medium tracking-wide uppercase select-none ${col.width ?? ""} ${col.headerClassName ?? ""}`}
                  aria-sort={
                    isActive ? (sort!.direction === "asc" ? "ascending" : "descending") : undefined
                  }
                >
                  {sortable ? (
                    <button
                      type="button"
                      onClick={() => toggleSort(col)}
                      className={`inline-flex items-center gap-1 rounded-sm hover:text-foreground focus-visible:text-foreground transition-colors ${isActive ? "text-foreground" : ""}`}
                    >
                      <span>{col.header}</span>
                      {isActive ? (
                        sort!.direction === "asc" ? (
                          <ChevronUp size={12} aria-hidden="true" />
                        ) : (
                          <ChevronDown size={12} aria-hidden="true" />
                        )
                      ) : (
                        <ChevronsUpDown size={12} className="opacity-50" aria-hidden="true" />
                      )}
                    </button>
                  ) : (
                    col.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {data.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="p-0">
                {emptyState ?? (
                  <div className="px-6 py-12 text-center text-sm text-muted">No rows</div>
                )}
              </td>
            </tr>
          ) : (
            data.map((row) => {
              const clickable = !!onRowClick;
              const extra = rowClassName?.(row) ?? "";
              return (
                <tr
                  key={getRowKey(row)}
                  onClick={clickable ? () => onRowClick(row) : undefined}
                  className={`border-b border-border last:border-b-0 ${clickable ? "cursor-pointer hover:bg-surface-2 focus-within:bg-surface-2" : ""} transition-colors ${extra}`}
                >
                  {columns.map((col) => {
                    const align = col.align ?? "left";
                    return (
                      <td
                        key={col.key}
                        className={`${cellPad} ${ALIGN[align]} align-middle ${col.className ?? ""}`}
                      >
                        {col.cell(row)}
                      </td>
                    );
                  })}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
