import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { listAnalyses } from "../lib/api";
import type { AnalysisStatus, Verdict } from "../lib/types";
import { cn, formatRelativeTime } from "../lib/utils";
import { Badge, type BadgeTone } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Spinner } from "../components/ui/Spinner";

const verdictTone: Record<Verdict, BadgeTone> = { clean: "safe", suspicious: "warning", malicious: "danger" };
const PAGE_SIZE = 20;

export default function AnalysesListPage() {
  const [offset, setOffset] = useState(0);
  const [statusFilter, setStatusFilter] = useState<AnalysisStatus | undefined>(undefined);

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ["analyses", offset, statusFilter],
    queryFn: () => listAnalyses({ limit: PAGE_SIZE, offset, status: statusFilter }),
    refetchInterval: 5000,
  });

  return (
    <div className="mx-auto max-w-6xl px-4 py-8">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Nexus Events</h1>
          <p className="text-sm text-muted-foreground">Every email analyzed by TVA, newest first.</p>
        </div>
        <div className="flex gap-2">
          {(["pending", "complete", "failed"] as const).map((s) => (
            <button
              key={s}
              onClick={() => {
                setStatusFilter((prev) => (prev === s ? undefined : s));
                setOffset(0);
              }}
              className={cn(
                "rounded-full border px-3 py-1 text-xs font-medium",
                statusFilter === s
                  ? "border-accent bg-accent/15 text-accent"
                  : "border-border text-muted-foreground hover:bg-muted",
              )}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {isLoading && (
        <div className="flex items-center gap-2 py-16 text-muted-foreground">
          <Spinner /> Loading…
        </div>
      )}

      {!isLoading && data && data.items.length === 0 && (
        <div className="rounded-xl border border-dashed border-border py-16 text-center text-muted-foreground">
          No Nexus Events yet. <Link to="/" className="text-accent hover:underline">Analyze an email</Link>{" "}
          to get started.
        </div>
      )}

      {!isLoading && data && data.items.length > 0 && (
        <div className="overflow-hidden rounded-xl border border-border">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50 text-xs uppercase tracking-wide text-muted-foreground">
                <th className="px-4 py-3 font-medium">Verdict</th>
                <th className="px-4 py-3 font-medium">Score</th>
                <th className="px-4 py-3 font-medium">From</th>
                <th className="px-4 py-3 font-medium">Subject</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">When</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((item) => (
                <tr key={item.id} className="border-b border-border last:border-0 hover:bg-muted/30">
                  <td className="px-4 py-3">
                    <Link to={`/analyses/${item.id}`} className="block">
                      <Badge tone={verdictTone[item.verdict]}>{item.verdict}</Badge>
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <Link to={`/analyses/${item.id}`} className="font-mono text-xs">
                      {item.risk_score}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <Link to={`/analyses/${item.id}`} className="block max-w-[200px] truncate">
                      {item.from_address || "unknown"}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <Link to={`/analyses/${item.id}`} className="block max-w-[280px] truncate">
                      {item.subject || "(no subject)"}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <Link to={`/analyses/${item.id}`} className="block text-muted-foreground">
                      {item.status}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <Link to={`/analyses/${item.id}`} className="block text-muted-foreground">
                      {formatRelativeTime(item.created_at)}
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data && data.total > PAGE_SIZE && (
        <div className="mt-4 flex items-center justify-between text-sm text-muted-foreground">
          <span>
            {offset + 1}–{Math.min(offset + PAGE_SIZE, data.total)} of {data.total}
            {isFetching && " · refreshing…"}
          </span>
          <div className="flex gap-2">
            <Button
              variant="secondary"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            >
              Previous
            </Button>
            <Button
              variant="secondary"
              disabled={offset + PAGE_SIZE >= data.total}
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
