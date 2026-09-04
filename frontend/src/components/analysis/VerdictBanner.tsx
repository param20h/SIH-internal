import type { AnalysisDetail } from "../../lib/types";
import { Badge, type BadgeTone } from "../ui/Badge";
import { formatDate } from "../../lib/utils";

const verdictTone: Record<AnalysisDetail["verdict"], BadgeTone> = {
  clean: "safe",
  suspicious: "warning",
  malicious: "danger",
};

const verdictLabel: Record<AnalysisDetail["verdict"], string> = {
  clean: "Clean",
  suspicious: "Suspicious",
  malicious: "Malicious",
};

const ringColor: Record<AnalysisDetail["verdict"], string> = {
  clean: "stroke-safe",
  suspicious: "stroke-warning",
  malicious: "stroke-danger",
};

export function VerdictBanner({ analysis }: { analysis: AnalysisDetail }) {
  const circumference = 2 * Math.PI * 42;
  const offset = circumference * (1 - analysis.risk_score / 100);

  return (
    <div className="flex flex-col gap-6 rounded-xl border border-border bg-card p-6 sm:flex-row sm:items-center">
      <div className="relative mx-auto h-28 w-28 shrink-0 sm:mx-0">
        <svg viewBox="0 0 100 100" className="h-28 w-28 -rotate-90">
          <circle cx="50" cy="50" r="42" strokeWidth="8" className="stroke-muted" fill="none" />
          <circle
            cx="50"
            cy="50"
            r="42"
            strokeWidth="8"
            fill="none"
            strokeLinecap="round"
            className={ringColor[analysis.verdict]}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: "stroke-dashoffset 0.6s ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-foreground">{analysis.risk_score}</span>
          <span className="text-[10px] uppercase tracking-wider text-muted-foreground">/ 100</span>
        </div>
      </div>

      <div className="flex-1">
        <div className="flex flex-wrap items-center gap-3">
          <Badge tone={verdictTone[analysis.verdict]} className="text-sm">
            {verdictLabel[analysis.verdict]}
          </Badge>
          <span className="text-sm text-muted-foreground">
            {analysis.anomaly_count} {analysis.anomaly_count === 1 ? "anomaly" : "anomalies"} detected
            across {analysis.hop_count} {analysis.hop_count === 1 ? "hop" : "hops"}
          </span>
        </div>
        <h1 className="mt-2 text-xl font-semibold text-foreground">
          {analysis.subject || "(no subject)"}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          from{" "}
          <span className="text-foreground">
            {analysis.from_display_name ? `${analysis.from_display_name} ` : ""}
            &lt;{analysis.from_address || "unknown"}&gt;
          </span>{" "}
          · {formatDate(analysis.message_date)}
        </p>
        <p className="mt-2 font-mono text-xs text-muted-foreground" title="SHA-256 of the original file">
          {analysis.filename}
        </p>
      </div>
    </div>
  );
}
