import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";

import { exportUrl } from "../../lib/api";
import type { AnalysisDetail } from "../../lib/types";
import { cn } from "../../lib/utils";
import { Card, CardBody, CardHeader } from "../ui/Card";
import { Spinner } from "../ui/Spinner";

interface HeaderBlock {
  text: string;
  suspicious: boolean;
  reason?: string;
}

function normalize(text: string): string {
  return text.split(/\s+/).filter(Boolean).join(" ").toLowerCase();
}

function splitIntoHeaderBlocks(rawHeaderSection: string): string[] {
  const lines = rawHeaderSection.split(/\r?\n/);
  const blocks: string[] = [];
  for (const line of lines) {
    if (/^\s/.test(line) && blocks.length > 0) {
      blocks[blocks.length - 1] += `\n${line}`;
    } else if (line.trim() !== "") {
      blocks.push(line);
    }
  }
  return blocks;
}

function classifyBlocks(blocks: string[], analysis: AnalysisDetail): HeaderBlock[] {
  const anomalousHopSequences = new Set(analysis.anomalies.flatMap((a) => a.hop_sequences));
  const anomalousHopNormalizedHeaders = analysis.hops
    .filter((h) => anomalousHopSequences.has(h.sequence))
    .map((h) => normalize(h.raw_header));

  const authFailed =
    analysis.authentication.spf?.result === "fail" ||
    analysis.authentication.dkim?.result === "fail" ||
    analysis.authentication.dmarc?.result === "fail";

  return blocks.map((block) => {
    const normalized = normalize(block);
    if (/^received:/i.test(block)) {
      const hit = anomalousHopNormalizedHeaders.some(
        (h) => normalized.includes(h) || h.includes(normalized),
      );
      if (hit) return { text: block, suspicious: true, reason: "Hop flagged by relay-chain analysis" };
    }
    if (/^authentication-results:/i.test(block) && authFailed) {
      return { text: block, suspicious: true, reason: "SPF, DKIM, or DMARC failed" };
    }
    if (/^dkim-signature:/i.test(block) && analysis.authentication.dkim_signature_expired) {
      return { text: block, suspicious: true, reason: "DKIM signature expired" };
    }
    return { text: block, suspicious: false };
  });
}

export function RawHeaderViewer({ analysis }: { analysis: AnalysisDetail }) {
  const [showAll, setShowAll] = useState(true);
  const { data: rawText, isLoading } = useQuery({
    queryKey: ["raw-eml", analysis.id],
    queryFn: async () => {
      const response = await fetch(exportUrl(analysis.id, "eml"));
      if (!response.ok) throw new Error("Failed to fetch raw source");
      return response.text();
    },
  });

  const blocks = useMemo(() => {
    if (!rawText) return [];
    const headerSection = rawText.split(/\r?\n\r?\n/)[0] ?? rawText;
    return classifyBlocks(splitIntoHeaderBlocks(headerSection), analysis);
  }, [rawText, analysis]);

  const suspiciousCount = blocks.filter((b) => b.suspicious).length;
  const visibleBlocks = showAll ? blocks : blocks.filter((b) => b.suspicious);

  return (
    <Card>
      <CardHeader
        title="Raw headers"
        eyebrow="Original source"
        action={
          suspiciousCount > 0 && (
            <button
              onClick={() => setShowAll((v) => !v)}
              className="rounded-md border border-border px-3 py-1 text-xs font-medium text-muted-foreground hover:bg-muted"
            >
              {showAll ? "Show flagged lines only" : "Show all headers"}
            </button>
          )
        }
      />
      <CardBody>
        {isLoading && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Spinner className="h-4 w-4" /> Loading raw source…
          </div>
        )}
        {!isLoading && blocks.length === 0 && (
          <p className="text-sm text-muted-foreground">No headers available.</p>
        )}
        <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono text-xs leading-relaxed">
          {visibleBlocks.map((block, i) => (
            <div
              key={i}
              title={block.reason}
              className={cn(
                "rounded px-2 py-0.5",
                block.suspicious && "border-l-2 border-danger bg-danger/10 text-danger",
              )}
            >
              {block.text}
            </div>
          ))}
        </pre>
      </CardBody>
    </Card>
  );
}
