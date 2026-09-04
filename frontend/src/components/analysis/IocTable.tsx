import type { Ioc, IocType } from "../../lib/types";
import { exportUrl } from "../../lib/api";
import { Badge, type BadgeTone } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card, CardBody, CardHeader } from "../ui/Card";

const typeTone: Record<IocType, BadgeTone> = {
  ipv4: "accent",
  ipv6: "accent",
  domain: "warning",
  url: "danger",
  sha256: "neutral",
  email: "neutral",
};

export function IocTable({ analysisId, iocs }: { analysisId: string; iocs: Ioc[] }) {
  return (
    <Card>
      <CardHeader
        title={`Indicators of compromise (${iocs.length})`}
        eyebrow="Attribution & evidence"
        action={
          <div className="flex items-center gap-2">
            <a href={exportUrl(analysisId, "stix")} download>
              <Button variant="secondary">STIX 2.1</Button>
            </a>
            <a href={exportUrl(analysisId, "ioc-csv")} download>
              <Button variant="secondary">CSV</Button>
            </a>
          </div>
        }
      />
      {iocs.length === 0 ? (
        <CardBody>
          <p className="text-sm text-muted-foreground">No indicators were extracted from this message.</p>
        </CardBody>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border text-xs uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-2 font-medium">Type</th>
                <th className="px-4 py-2 font-medium">Value</th>
                <th className="px-4 py-2 font-medium">Context</th>
              </tr>
            </thead>
            <tbody>
              {iocs.map((ioc, i) => (
                <tr key={`${ioc.type}-${ioc.value}-${i}`} className="border-b border-border last:border-0">
                  <td className="px-4 py-2">
                    <Badge tone={typeTone[ioc.type]}>{ioc.type}</Badge>
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-foreground">{ioc.value}</td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">{ioc.context}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
