import type { AnalysisDetail } from "../../lib/types";
import { cn, formatDate } from "../../lib/utils";
import { Badge } from "../ui/Badge";
import { Card, CardHeader } from "../ui/Card";

export function HopTable({ analysis }: { analysis: AnalysisDetail }) {
  const anomalousSequences = new Set(analysis.anomalies.flatMap((a) => a.hop_sequences));

  return (
    <Card>
      <CardHeader title={`Relay chain (${analysis.hop_count} hops, earliest → latest)`} />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] text-left text-sm">
          <thead>
            <tr className="border-b border-border text-xs uppercase tracking-wide text-muted-foreground">
              <th className="px-4 py-2 font-medium">#</th>
              <th className="px-4 py-2 font-medium">From</th>
              <th className="px-4 py-2 font-medium">By</th>
              <th className="px-4 py-2 font-medium">IP</th>
              <th className="px-4 py-2 font-medium">Timestamp</th>
              <th className="px-4 py-2 font-medium">Location</th>
            </tr>
          </thead>
          <tbody>
            {analysis.hops.map((hop) => {
              const anomalous = anomalousSequences.has(hop.sequence);
              return (
                <tr
                  key={hop.id}
                  className={cn("border-b border-border last:border-0", anomalous && "bg-danger/5")}
                >
                  <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{hop.sequence}</td>
                  <td className="px-4 py-2 font-mono text-xs">{hop.from_host || "?"}</td>
                  <td className="px-4 py-2 font-mono text-xs">{hop.by_host || "?"}</td>
                  <td className="px-4 py-2 font-mono text-xs">
                    <span className={hop.is_bogon ? "text-danger" : ""}>{hop.from_ip || "—"}</span>
                    {hop.is_bogon && (
                      <Badge tone="danger" className="ml-2">
                        bogon
                      </Badge>
                    )}
                  </td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">{formatDate(hop.timestamp)}</td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">
                    {hop.city || hop.country ? `${hop.city || "?"}, ${hop.country || "?"}` : "—"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
