import { useMemo, useState } from "react";
import { ComposableMap, Geographies, Geography, Line, Marker } from "react-simple-maps";
// world-atlas ships plain topojson data; importing it directly keeps the
// map fully offline (no runtime fetch to a map-tile/geo CDN), matching the
// hard offline-operation constraint.
import worldTopology from "world-atlas/countries-110m.json?url";

import type { AnalysisDetail, HopOut } from "../../lib/types";
import { cn, formatDate } from "../../lib/utils";
import { Card, CardBody, CardHeader } from "../ui/Card";

type GeoHop = HopOut & { latitude: number; longitude: number };

function hasCoords(hop: HopOut): hop is GeoHop {
  return hop.latitude !== null && hop.longitude !== null;
}

export function RelayMap({ analysis }: { analysis: AnalysisDetail }) {
  const [hovered, setHovered] = useState<GeoHop | null>(null);
  const anomalousSequences = useMemo(
    () => new Set(analysis.anomalies.flatMap((a) => a.hop_sequences)),
    [analysis.anomalies],
  );
  const geoHops = useMemo(() => analysis.hops.filter(hasCoords), [analysis.hops]);

  if (geoHops.length === 0) {
    return (
      <Card>
        <CardHeader title="Relay path" eyebrow="Geolocation" />
        <CardBody>
          <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-border py-10 text-center">
            <p className="text-sm font-medium text-foreground">No hop geolocation available</p>
            <p className="max-w-sm text-xs text-muted-foreground">
              GeoIP enrichment is offline until a licensed GeoLite2-City.mmdb is placed at{" "}
              <code className="rounded bg-muted px-1 py-0.5">data/geoip/</code>. The relay chain
              itself (below) was still fully reconstructed and analyzed without it.
            </p>
          </div>
        </CardBody>
      </Card>
    );
  }

  const segments: { from: GeoHop; to: GeoHop }[] = [];
  for (let i = 1; i < geoHops.length; i++) {
    const from = geoHops[i - 1];
    const to = geoHops[i];
    if (from && to) segments.push({ from, to });
  }

  return (
    <Card>
      <CardHeader
        title="Relay path"
        eyebrow="Geolocation"
        action={
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-accent" /> normal
            </span>
            <span className="flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-danger" /> anomalous
            </span>
          </div>
        }
      />
      <CardBody className="relative">
        <ComposableMap
          projection="geoNaturalEarth1"
          className="h-auto w-full"
          style={{ background: "transparent" }}
        >
          <Geographies geography={worldTopology}>
            {({ geographies }) =>
              geographies.map((geo) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill="hsl(var(--muted))"
                  stroke="hsl(var(--border))"
                  strokeWidth={0.5}
                  style={{
                    default: { outline: "none" },
                    hover: { outline: "none", fill: "hsl(var(--muted))" },
                    pressed: { outline: "none" },
                  }}
                />
              ))
            }
          </Geographies>

          {segments.map((segment, i) => {
            const anomalous =
              anomalousSequences.has(segment.from.sequence) || anomalousSequences.has(segment.to.sequence);
            return (
              <Line
                key={i}
                from={[segment.from.longitude, segment.from.latitude]}
                to={[segment.to.longitude, segment.to.latitude]}
                stroke={anomalous ? "hsl(var(--danger))" : "hsl(var(--accent))"}
                strokeWidth={1.5}
                strokeLinecap="round"
                className={anomalous ? "relay-line-anomalous" : "relay-line"}
              />
            );
          })}

          {geoHops.map((hop) => {
            const anomalous = anomalousSequences.has(hop.sequence);
            return (
              <Marker
                key={hop.id}
                coordinates={[hop.longitude, hop.latitude]}
                onMouseEnter={() => setHovered(hop)}
                onMouseLeave={() => setHovered(null)}
              >
                <circle
                  r={anomalous ? 5 : 4}
                  className={cn(
                    "cursor-pointer stroke-background stroke-2",
                    anomalous ? "fill-danger" : "fill-accent",
                  )}
                />
                {anomalous && (
                  <circle r={5} className="origin-center fill-none stroke-danger opacity-60 animate-ping" />
                )}
                <text
                  textAnchor="middle"
                  y={-10}
                  className="fill-muted-foreground font-mono text-[8px]"
                >
                  #{hop.sequence}
                </text>
              </Marker>
            );
          })}
        </ComposableMap>

        {hovered && (
          <div className="pointer-events-none absolute bottom-3 left-3 max-w-xs rounded-lg border border-border bg-card p-3 text-xs shadow-lg">
            <p className="font-semibold text-foreground">
              Hop #{hovered.sequence} {anomalousSequences.has(hovered.sequence) && "⚠"}
            </p>
            <p className="mt-1 text-muted-foreground">
              {hovered.city || "unknown city"}, {hovered.country || "unknown country"}
            </p>
            <p className="text-muted-foreground">IP: {hovered.from_ip || "unknown"}</p>
            <p className="text-muted-foreground">
              ASN: {hovered.asn ? `AS${hovered.asn}` : "unknown"} {hovered.asn_org || ""}
            </p>
            <p className="text-muted-foreground">{formatDate(hovered.timestamp)}</p>
          </div>
        )}
      </CardBody>
    </Card>
  );
}
