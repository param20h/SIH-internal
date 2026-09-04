import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { exportUrl, getAnalysis } from "../lib/api";
import { HopTable } from "../components/analysis/HopTable";
import { IndicatorPanel } from "../components/analysis/IndicatorPanel";
import { RawHeaderViewer } from "../components/analysis/RawHeaderViewer";
import { RelayMap } from "../components/analysis/RelayMap";
import { VerdictBanner } from "../components/analysis/VerdictBanner";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Spinner } from "../components/ui/Spinner";

export default function AnalysisPage() {
  const { id } = useParams<{ id: string }>();
  const {
    data: analysis,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["analysis", id],
    queryFn: () => getAnalysis(id!),
    enabled: !!id,
    refetchInterval: (query) =>
      query.state.data?.status === "pending" || query.state.data?.status === "processing"
        ? 1500
        : false,
  });

  if (isLoading) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center gap-2 text-muted-foreground">
        <Spinner /> Loading analysis…
      </div>
    );
  }

  if (isError || !analysis) {
    return (
      <div className="mx-auto max-w-xl px-4 py-16 text-center">
        <p className="text-danger">{(error as Error)?.message || "Analysis not found."}</p>
        <Link to="/" className="mt-4 inline-block text-accent hover:underline">
          Back to upload
        </Link>
      </div>
    );
  }

  if (analysis.status !== "complete") {
    return (
      <div className="mx-auto flex max-w-xl flex-col items-center gap-3 px-4 py-24 text-center">
        <Spinner className="h-8 w-8" />
        <p className="font-medium text-foreground">
          {analysis.status === "failed" ? "Analysis failed" : "Analysis in progress…"}
        </p>
        {analysis.status === "failed" && (
          <p className="text-sm text-danger">{analysis.status_detail}</p>
        )}
        {analysis.status !== "failed" && (
          <p className="text-sm text-muted-foreground">
            This page will update automatically once the batch job completes.
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 py-8">
      <div className="flex items-center justify-between">
        <Link to="/analyses" className="text-sm text-muted-foreground hover:text-foreground">
          ← All Nexus Events
        </Link>
        <div className="flex items-center gap-2">
          <a href={exportUrl(analysis.id, "eml")} download>
            <Button variant="secondary">Original .eml</Button>
          </a>
          <a href={exportUrl(analysis.id, "txt")} download>
            <Button variant="secondary">Export .txt</Button>
          </a>
          <a href={exportUrl(analysis.id, "json")} download>
            <Button variant="secondary">Export .json</Button>
          </a>
        </div>
      </div>

      <VerdictBanner analysis={analysis} />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
        <div className="lg:col-span-3">
          <RelayMap analysis={analysis} />
        </div>
        <div className="lg:col-span-2">
          <AuthSummary analysis={analysis} />
        </div>
      </div>

      <HopTable analysis={analysis} />
      <IndicatorPanel risk={analysis.risk} anomalies={analysis.anomalies} />
      <RawHeaderViewer analysis={analysis} />
    </div>
  );
}

function AuthSummary({ analysis }: { analysis: Awaited<ReturnType<typeof getAnalysis>> }) {
  const a = analysis.authentication;
  const rows: { label: string; result: string | undefined; reason: string | null | undefined }[] = [
    { label: "SPF", result: a.spf?.result, reason: a.spf?.reason },
    { label: "DKIM", result: a.dkim?.result, reason: a.dkim?.reason },
    { label: "DMARC", result: a.dmarc?.result, reason: a.dmarc?.reason },
  ];

  return (
    <div className="rounded-xl border border-border bg-card">
      <div className="border-b border-border p-4">
        <h2 className="text-base font-semibold text-foreground">Authentication</h2>
      </div>
      <div className="flex flex-col divide-y divide-border">
        {rows.map((row) => (
          <div key={row.label} className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-foreground">{row.label}</span>
              <Badge tone={resultTone(row.result)}>{row.result || "unknown"}</Badge>
            </div>
            {row.reason && <p className="mt-1 text-xs text-muted-foreground">{row.reason}</p>}
          </div>
        ))}
        <div className="p-4 text-xs text-muted-foreground">
          DMARC policy published: <span className="text-foreground">{a.dmarc_policy}</span>
        </div>
        {analysis.sender_domain_intel && (
          <div className="p-4 text-xs text-muted-foreground">
            Sender domain: <span className="text-foreground">{analysis.sender_domain_intel.domain}</span>{" "}
            —{" "}
            {analysis.sender_domain_intel.source === "unavailable"
              ? "age unavailable"
              : `${analysis.sender_domain_intel.age_days} days old (${analysis.sender_domain_intel.source})`}
          </div>
        )}
      </div>
    </div>
  );
}

function resultTone(result: string | undefined): "safe" | "danger" | "warning" | "neutral" {
  if (result === "pass") return "safe";
  if (result === "fail") return "danger";
  if (result === "softfail" || result === "neutral") return "warning";
  return "neutral";
}
