"use client"

import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"

import type { SeverityChartDatum } from "@/types/report"

const COLORS = {
  critical: "var(--destructive)",
  high: "var(--destructive)",
  medium: "var(--chart-1)",
  low: "var(--muted-foreground)",
  info: "var(--chart-2)",
}

export function SeverityChart({ data }: { data: SeverityChartDatum[] }) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
        <CartesianGrid vertical={false} stroke="var(--border)" strokeOpacity={0.45} />
        <XAxis
          dataKey="label"
          axisLine={false}
          tickLine={false}
          tick={{ fill: "var(--muted-foreground)", fontSize: 12 }}
        />
        <YAxis
          allowDecimals={false}
          axisLine={false}
          tickLine={false}
          tick={{ fill: "var(--muted-foreground)", fontSize: 12 }}
        />
        <Tooltip
          cursor={{ fill: "var(--accent)", fillOpacity: 0.28 }}
          contentStyle={{
            borderRadius: 16,
            border: "1px solid var(--border)",
            background: "var(--card)",
            color: "var(--foreground)",
          }}
        />
        <Bar dataKey="value" radius={[10, 10, 0, 0]} fillOpacity={0.78}>
          {data.map((entry) => (
            <Cell key={entry.severity} fill={COLORS[entry.severity]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
