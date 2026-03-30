"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

interface SeverityChartProps {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

const COLORS: Record<string, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#3b82f6",
  Info: "#6b7280",
};

export function SeverityChart({ critical, high, medium, low, info }: SeverityChartProps) {
  const data = [
    { name: "Critical", count: critical },
    { name: "High", count: high },
    { name: "Medium", count: medium },
    { name: "Low", count: low },
    { name: "Info", count: info },
  ];

  return (
    <div className="w-full h-64">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
          <XAxis
            dataKey="name"
            tick={{ fill: "#a1a1aa", fontSize: 12 }}
            axisLine={{ stroke: "#262626" }}
            tickLine={false}
          />
          <YAxis
            tick={{ fill: "#a1a1aa", fontSize: 12 }}
            axisLine={false}
            tickLine={false}
            allowDecimals={false}
          />
          <Tooltip
            contentStyle={{
              background: "#1a1a1a",
              border: "1px solid #262626",
              borderRadius: "8px",
              color: "#ededed",
              fontSize: 13,
            }}
            cursor={{ fill: "rgba(255,255,255,0.04)" }}
          />
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {data.map((entry) => (
              <Cell key={entry.name} fill={COLORS[entry.name]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
