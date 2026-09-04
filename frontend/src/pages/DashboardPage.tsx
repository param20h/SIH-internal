import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { fetchStats, listAnalyses } from "../lib/api";
import { formatRelativeTime } from "../lib/utils";
import { Badge, type BadgeTone } from "../components/ui/Badge";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { Spinner } from "../components/ui/Spinner";

const VERDICT_COLORS: Record<string, string> = {
  clean: "hsl(142 71% 45%)",
  suspicious: "hsl(38 92% 55%)",
  malicious: "hsl(0 84% 60%)",
};

const verdictTone: Record<string, BadgeTone> = { clean: "safe", suspicious: "warning", malicious: "danger" };

function KpiCard({ label, value, tone }: { label: string; value: number | string; tone?: BadgeTone }) {
  return (
    <Card>
      <CardBody>
        <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
        <p
          className={`mt-1 text-3xl font-bold ${
            tone === "danger" ? "text-danger" : tone === "warning" ? "text-warning" : "text-foreground"
          }`}
        >
          {value}
        </p>
      </CardBody>
    </Card>
  );
}

export default function DashboardPage() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ["stats"],
    queryFn: fetchStats,
    refetchInterval: 5000,
  });
  const { data: recent } = useQuery({
    queryKey: ["analyses", "recent"],
    queryFn: () => listAnalyses({ limit: 8 }),
    refetchInterval: 5000,
  });

  if (isLoading || !stats) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center gap-2 text-muted-foreground">
        <Spinner /> Loading dashboard…
      </div>
    );
  }

  const verdictData = Object.entries(stats.verdict_breakdown).map(([name, value]) => ({ name, value }));
  const anomalyTypeData = Object.entries(stats.anomaly_type_breakdown)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([name, value]) => ({ name: name.replace(/_/g, " "), value }));
  const authData = [
    { name: "SPF fail", value: stats.spf_breakdown.fail || 0 },
    { name: "DKIM fail", value: stats.dkim_breakdown.fail || 0 },
    { name: "DMARC fail", value: stats.dmarc_breakdown.fail || 0 },
  ];

  return (
    <div className="mx-auto max-w-6xl px-4 py-8">
      <h1 className="text-2xl font-bold text-foreground">Dashboard</h1>
      <p className="mb-6 text-sm text-muted-foreground">Aggregate stats across every analyzed email.</p>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard label="Total analyses" value={stats.total_analyses} />
        <KpiCard label="Malicious" value={stats.verdict_breakdown.malicious || 0} tone="danger" />
        <KpiCard label="Suspicious" value={stats.verdict_breakdown.suspicious || 0} tone="warning" />
        <KpiCard label="Last 24h" value={stats.analyses_last_24h} />
      </div>

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader title="Verdict breakdown" />
          <CardBody>
            {verdictData.length === 0 ? (
              <EmptyChart />
            ) : (
              <ResponsiveContainer width="100%" height={240}>
                <PieChart>
                  <Pie
                    data={verdictData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={50}
                    outerRadius={80}
                    isAnimationActive={false}
                  >
                    {verdictData.map((entry) => (
                      <Cell key={entry.name} fill={VERDICT_COLORS[entry.name] ?? "hsl(var(--muted))"} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
            <div className="mt-2 flex justify-center gap-4 text-xs">
              {verdictData.map((entry) => (
                <span key={entry.name} className="flex items-center gap-1.5 text-muted-foreground">
                  <span
                    className="h-2 w-2 rounded-full"
                    style={{ background: VERDICT_COLORS[entry.name] }}
                  />
                  {entry.name} ({entry.value})
                </span>
              ))}
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Authentication failures" />
          <CardBody>
            {authData.every((d) => d.value === 0) ? (
              <EmptyChart />
            ) : (
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={authData} layout="vertical" margin={{ left: 16 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" horizontal={false} />
                  <XAxis type="number" allowDecimals={false} stroke="hsl(var(--muted-foreground))" fontSize={12} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    stroke="hsl(var(--muted-foreground))"
                    fontSize={12}
                    width={80}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  <Bar
                    dataKey="value"
                    fill="hsl(var(--danger))"
                    radius={[0, 4, 4, 0]}
                    isAnimationActive={false}
                  />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader title="Top anomaly types" />
          <CardBody>
            {anomalyTypeData.length === 0 ? (
              <EmptyChart />
            ) : (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={anomalyTypeData} margin={{ bottom: 40 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                  <XAxis
                    dataKey="name"
                    stroke="hsl(var(--muted-foreground))"
                    fontSize={11}
                    angle={-30}
                    textAnchor="end"
                    interval={0}
                  />
                  <YAxis allowDecimals={false} stroke="hsl(var(--muted-foreground))" fontSize={12} />
                  <Tooltip
                    contentStyle={{
                      background: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  <Bar
                    dataKey="value"
                    fill="hsl(var(--accent))"
                    radius={[4, 4, 0, 0]}
                    isAnimationActive={false}
                  />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardBody>
        </Card>
      </div>

      <Card className="mt-6">
        <CardHeader title="Recent Nexus Events" action={<Link to="/analyses" className="text-xs text-accent hover:underline">View all →</Link>} />
        <div className="divide-y divide-border">
          {recent?.items.length === 0 && (
            <p className="p-4 text-sm text-muted-foreground">Nothing analyzed yet.</p>
          )}
          {recent?.items.map((item) => (
            <Link
              key={item.id}
              to={`/analyses/${item.id}`}
              className="flex items-center justify-between gap-4 p-4 hover:bg-muted/30"
            >
              <div className="min-w-0">
                <p className="truncate text-sm text-foreground">{item.subject || "(no subject)"}</p>
                <p className="truncate text-xs text-muted-foreground">{item.from_address}</p>
              </div>
              <div className="flex shrink-0 items-center gap-3">
                <Badge tone={verdictTone[item.verdict]}>{item.verdict}</Badge>
                <span className="text-xs text-muted-foreground">{formatRelativeTime(item.created_at)}</span>
              </div>
            </Link>
          ))}
        </div>
      </Card>
    </div>
  );
}

function EmptyChart() {
  return (
    <div className="flex h-[200px] items-center justify-center text-sm text-muted-foreground">
      No data yet
    </div>
  );
}
