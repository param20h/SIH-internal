import type { AttributionConfidence, OriginAttribution } from "../../lib/types";
import { Badge, type BadgeTone } from "../ui/Badge";
import { Card, CardBody, CardHeader } from "../ui/Card";

const confidenceTone: Record<AttributionConfidence, BadgeTone> = {
  high: "safe",
  medium: "warning",
  low: "danger",
  unknown: "neutral",
};

export function AttributionPanel({ attribution }: { attribution: OriginAttribution }) {
  return (
    <Card>
      <CardHeader
        title="Origin attribution"
        eyebrow="Attribution & evidence"
        action={<Badge tone={confidenceTone[attribution.confidence]}>{attribution.confidence} confidence</Badge>}
      />
      <CardBody className="flex flex-col gap-3">
        {attribution.source === "unavailable" ? (
          <p className="text-sm text-muted-foreground">{attribution.reasoning}</p>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-4">
              <Field label="Origin IP" value={attribution.origin_ip} mono />
              <Field
                label="Relay hop"
                value={attribution.origin_hop_sequence !== null ? `#${attribution.origin_hop_sequence}` : null}
              />
              <Field label="ASN" value={attribution.asn !== null ? `AS${attribution.asn}` : null} />
              <Field label="Organization" value={attribution.asn_org} />
              <Field label="Country" value={attribution.country} />
            </div>
            <p className="rounded-lg bg-muted p-3 text-xs text-muted-foreground">{attribution.reasoning}</p>
          </>
        )}
      </CardBody>
    </Card>
  );
}

function Field({ label, value, mono }: { label: string; value: string | null; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className={mono ? "font-mono text-sm text-foreground" : "text-sm text-foreground"}>
        {value ?? "—"}
      </div>
    </div>
  );
}
