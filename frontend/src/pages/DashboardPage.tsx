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
import { Spinner } from "../components/ui/Spinner";

const VERDICT_COLORS: Record<string, string> = {
  clean: "#10B981", // forensic-green
  suspicious: "#F59E0B", // forensic-amber
  malicious: "#EF4444", // forensic-red
};

const verdictTone: Record<string, BadgeTone> = { clean: "safe", suspicious: "warning", malicious: "danger" };

function KpiPanel({ label, value, tone }: { label: string; value: number | string; tone?: BadgeTone }) {
  return (
    <div className="border border-whisper-border bg-pure-surface rounded-lg p-5 shadow-whisper-drop transition-spring hover:border-technical-cyan/30">
      <p className="label-md text-muted-steel">{label}</p>
      <p
        className={`mt-2 text-3xl font-semibold tracking-tight mono-data ${
          tone === "danger" ? "text-forensic-red" : tone === "warning" ? "text-forensic-amber" : "text-clinical-white"
        }`}
      >
        {value}
      </p>
    </div>
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
      <div className="flex min-h-[60vh] items-center justify-center gap-3 text-technical-cyan mono-data">
        <Spinner /> Initializing telemetry dashboard...
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
    <div className="mx-auto max-w-6xl px-4 py-12">
      <div className="mb-10">
        <h1 className="text-3xl font-semibold text-clinical-white">Global Telemetry</h1>
        <p className="mt-2 text-sm text-muted-steel">Aggregate statistics across the forensic pipeline.</p>
      </div>

      <div className="grid grid-cols-2 gap-6 sm:grid-cols-4">
        <KpiPanel label="Total analyses" value={stats.total_analyses} />
        <KpiPanel label="Malicious" value={stats.verdict_breakdown.malicious || 0} tone="danger" />
        <KpiPanel label="Suspicious" value={stats.verdict_breakdown.suspicious || 0} tone="warning" />
        <KpiPanel label="Last 24h" value={stats.analyses_last_24h} />
      </div>

      <div className="mt-8 grid grid-cols-1 gap-8 lg:grid-cols-2">
        <div className="border border-whisper-border bg-pure-surface rounded-xl overflow-hidden shadow-whisper-drop">
          <div className="border-b border-whisper-border p-4 bg-canvas-deep">
            <h3 className="label-md text-clinical-white">Verdict Distribution</h3>
          </div>
          <div className="p-6">
            {verdictData.length === 0 ? (
              <EmptyChart />
            ) : (
              <ResponsiveContainer width="100%" height={240}>
                <PieChart>
                  <Pie
                    data={verdictData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={60}
                    outerRadius={90}
                    isAnimationActive={false}
                    stroke="none"
                  >
                    {verdictData.map((entry) => (
                      <Cell key={entry.name} fill={VERDICT_COLORS[entry.name] ?? "#A1A1AA"} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "#18181B",
                      border: "1px solid rgba(255,255,255,0.1)",
                      borderRadius: "8px",
                      fontSize: "12px",
                      color: "#FAFAFA",
                      fontFamily: "JetBrains Mono"
                    }}
                    itemStyle={{ color: "#FAFAFA" }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
            <div className="mt-4 flex justify-center gap-6 text-xs mono-data">
              {verdictData.map((entry) => (
                <span key={entry.name} className="flex items-center gap-2 text-muted-steel">
                  <span
                    className="h-2 w-2 rounded-full"
                    style={{ background: VERDICT_COLORS[entry.name] }}
                  />
                  {entry.name.toUpperCase()} ({entry.value})
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="border border-whisper-border bg-pure-surface rounded-xl overflow-hidden shadow-whisper-drop">
          <div className="border-b border-whisper-border p-4 bg-canvas-deep">
            <h3 className="label-md text-clinical-white">Authentication Failures</h3>
          </div>
          <div className="p-6">
            {authData.every((d) => d.value === 0) ? (
              <EmptyChart />
            ) : (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={authData} layout="vertical" margin={{ left: 16 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                  <XAxis type="number" allowDecimals={false} stroke="#A1A1AA" fontSize={11} fontFamily="JetBrains Mono" />
                  <YAxis
                    type="category"
                    dataKey="name"
                    stroke="#A1A1AA"
                    fontSize={11}
                    fontFamily="JetBrains Mono"
                    width={80}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "#18181B",
                      border: "1px solid rgba(255,255,255,0.1)",
                      borderRadius: "8px",
                      fontSize: "12px",
                      fontFamily: "JetBrains Mono",
                      color: "#FAFAFA"
                    }}
                    cursor={{ fill: 'rgba(255,255,255,0.02)' }}
                  />
                  <Bar
                    dataKey="value"
                    fill="#EF4444"
                    radius={[0, 4, 4, 0]}
                    isAnimationActive={false}
                  />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        <div className="border border-whisper-border bg-pure-surface rounded-xl overflow-hidden shadow-whisper-drop lg:col-span-2">
          <div className="border-b border-whisper-border p-4 bg-canvas-deep">
            <h3 className="label-md text-clinical-white">Anomaly Signature Types</h3>
          </div>
          <div className="p-6">
            {anomalyTypeData.length === 0 ? (
              <EmptyChart />
            ) : (
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={anomalyTypeData} margin={{ bottom: 40 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                  <XAxis
                    dataKey="name"
                    stroke="#A1A1AA"
                    fontSize={10}
                    fontFamily="JetBrains Mono"
                    angle={-25}
                    textAnchor="end"
                    interval={0}
                  />
                  <YAxis allowDecimals={false} stroke="#A1A1AA" fontSize={11} fontFamily="JetBrains Mono" />
                  <Tooltip
                    contentStyle={{
                      background: "#18181B",
                      border: "1px solid rgba(255,255,255,0.1)",
                      borderRadius: "8px",
                      fontSize: "12px",
                      fontFamily: "JetBrains Mono",
                      color: "#FAFAFA"
                    }}
                    cursor={{ fill: 'rgba(255,255,255,0.02)' }}
                  />
                  <Bar
                    dataKey="value"
                    fill="#06B6D4"
                    radius={[4, 4, 0, 0]}
                    isAnimationActive={false}
                  />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      <div className="mt-8 border border-whisper-border bg-pure-surface rounded-xl overflow-hidden shadow-whisper-drop">
        <div className="border-b border-whisper-border p-4 bg-canvas-deep flex justify-between items-center">
          <h3 className="label-md text-clinical-white">Recent Intake Buffer</h3>
          <Link to="/analyses" className="label-md text-technical-cyan hover:text-technical-cyan/80 transition-colors">
            View All Register →
          </Link>
        </div>
        <div className="divide-y divide-whisper-border">
          {recent?.items.length === 0 && (
            <p className="p-6 text-sm text-muted-steel mono-data">Buffer empty. No recent intakes.</p>
          )}
          {recent?.items.map((item) => (
            <Link
              key={item.id}
              to={`/analyses/${item.id}`}
              className="flex items-center justify-between gap-4 p-5 hover:bg-canvas-deep/50 transition-spring group"
            >
              <div className="min-w-0">
                <p className="truncate text-sm font-medium text-clinical-white group-hover:text-technical-cyan transition-colors">{item.subject || "(NO SUBJECT)"}</p>
                <p className="truncate mt-1 text-xs text-muted-steel mono-data">{item.from_address}</p>
              </div>
              <div className="flex shrink-0 items-center gap-4">
                <Badge tone={verdictTone[item.verdict]}>{item.verdict.toUpperCase()}</Badge>
                <span className="text-xs text-muted-steel mono-data w-24 text-right">{formatRelativeTime(item.created_at)}</span>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}

function EmptyChart() {
  return (
    <div className="flex h-[200px] items-center justify-center text-sm text-muted-steel mono-data">
      NO TELEMETRY DATA
    </div>
  );
}
