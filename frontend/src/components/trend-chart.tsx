"use client";

import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import type { TrendPoint } from "@/lib/api";

interface TrendChartProps {
  data: TrendPoint[];
  height?: number;
}

const ACCENT = "oklch(0.72 0.16 155)";

export function TrendChart({ data, height = 160 }: TrendChartProps) {
  if (data.length === 0) {
    return (
      <p className="text-sm text-muted py-4">
        No trend data yet. Complete more scans to see trends.
      </p>
    );
  }

  return (
    <div style={{ width: "100%", height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart
          data={data}
          margin={{ top: 4, right: 8, bottom: 0, left: -24 }}
        >
          <CartesianGrid
            strokeDasharray="2 4"
            stroke="var(--border)"
            vertical={false}
          />
          <XAxis
            dataKey="date"
            tick={{ fill: "var(--muted)", fontSize: 11 }}
            axisLine={{ stroke: "var(--border)" }}
            tickLine={false}
            tickMargin={6}
            tickFormatter={(v: string) => {
              const d = new Date(v);
              return `${d.getMonth() + 1}/${d.getDate()}`;
            }}
          />
          <YAxis
            tick={{ fill: "var(--muted)", fontSize: 11 }}
            axisLine={false}
            tickLine={false}
            domain={[0, 100]}
            width={32}
          />
          <Tooltip
            contentStyle={{
              background: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              color: "var(--text)",
              fontSize: 12,
              padding: "6px 10px",
            }}
            labelStyle={{ color: "var(--muted)" }}
            cursor={{ stroke: "var(--border-strong)", strokeWidth: 1 }}
          />
          <Line
            type="monotone"
            dataKey="risk_score"
            stroke={ACCENT}
            strokeWidth={1.75}
            dot={false}
            activeDot={{ r: 3, fill: ACCENT, stroke: "var(--bg)" }}
            name="Risk score"
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
