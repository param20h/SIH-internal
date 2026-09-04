import { useState } from "react";

import type { AnomalyOut, RiskScore } from "../../lib/types";
import { Badge, type BadgeTone } from "../ui/Badge";
import { Card, CardBody, CardHeader } from "../ui/Card";

const severityTone: Record<AnomalyOut["severity"], BadgeTone> = {
  info: "neutral",
  low: "neutral",
  medium: "warning",
  high: "danger",
  critical: "danger",
};

function FactorRow({ factor }: { factor: RiskScore["factors"][number] }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <li className="border-b border-border last:border-0">
      <button
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
        className="flex w-full items-center justify-between gap-4 px-4 py-3 text-left hover:bg-muted/50"
      >
        <span className="flex items-center gap-3">
          <Badge tone={factor.category === "authentication" ? "accent" : "warning"}>
            +{factor.weight}
          </Badge>
          <span className="text-sm text-foreground">{factor.name}</span>
        </span>
        <svg
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          className={`shrink-0 text-muted-foreground transition-transform ${expanded ? "rotate-180" : ""}`}
          aria-hidden="true"
        >
          <path d="M6 9l6 6 6-6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      {expanded && (
        <div className="px-4 pb-3 pl-16">
          <p className="rounded-lg bg-muted p-3 font-mono text-xs text-muted-foreground">
            {factor.evidence}
          </p>
        </div>
      )}
    </li>
  );
}

function AnomalyRow({ anomaly }: { anomaly: AnomalyOut }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <li className="border-b border-border last:border-0">
      <button
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
        className="flex w-full items-center justify-between gap-4 px-4 py-3 text-left hover:bg-muted/50"
      >
        <span className="flex items-center gap-3">
          <Badge tone={severityTone[anomaly.severity]}>{anomaly.severity}</Badge>
          <span className="text-sm text-foreground">{anomaly.summary}</span>
        </span>
        <svg
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          className={`shrink-0 text-muted-foreground transition-transform ${expanded ? "rotate-180" : ""}`}
          aria-hidden="true"
        >
          <path d="M6 9l6 6 6-6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      {expanded && (
        <div className="px-4 pb-3 pl-16">
          <p className="rounded-lg bg-muted p-3 font-mono text-xs text-muted-foreground">
            {anomaly.evidence}
          </p>
          {anomaly.hop_sequences.length > 0 && (
            <p className="mt-2 text-xs text-muted-foreground">
              Hops: {anomaly.hop_sequences.map((s) => `#${s}`).join(", ")}
            </p>
          )}
        </div>
      )}
    </li>
  );
}

export function IndicatorPanel({ risk, anomalies }: { risk: RiskScore; anomalies: AnomalyOut[] }) {
  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader title="Indicator breakdown" eyebrow="Miss Minutes" />
        {risk.factors.length === 0 ? (
          <CardBody>
            <p className="text-sm text-muted-foreground">
              No factors contributed to the score — nothing here raised it above zero.
            </p>
          </CardBody>
        ) : (
          <ul>
            {risk.factors.map((factor, i) => (
              <FactorRow key={i} factor={factor} />
            ))}
          </ul>
        )}
      </Card>

      <Card>
        <CardHeader
          title={`All detected anomalies (${anomalies.length})`}
          eyebrow="Relay-chain analysis"
        />
        {anomalies.length === 0 ? (
          <CardBody>
            <p className="text-sm text-muted-foreground">No anomalies detected in the relay chain.</p>
          </CardBody>
        ) : (
          <ul>
            {anomalies.map((anomaly) => (
              <AnomalyRow key={anomaly.id} anomaly={anomaly} />
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
