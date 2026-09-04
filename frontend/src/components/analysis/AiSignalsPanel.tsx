import type { AiSignals, LookalikeAnalysis } from "../../lib/types";
import { Badge, type BadgeTone } from "../ui/Badge";
import { Card, CardBody, CardHeader } from "../ui/Card";

function LookalikeBadges({ lookalike }: { lookalike: LookalikeAnalysis }) {
  if (lookalike.matches.length === 0) return null;
  return (
    <div className="mt-2 flex flex-wrap gap-2">
      {lookalike.matches.map((m, i) => (
        <Badge key={i} tone="danger">
          looks like {m.matched_brand} ({m.method.replace(/_/g, " ")})
        </Badge>
      ))}
      {lookalike.is_punycode && <Badge tone="warning">punycode / IDN</Badge>}
    </div>
  );
}

function PhishingCard({ phishing }: { phishing: AiSignals["phishing"] }) {
  if (phishing.source === "unavailable") {
    return (
      <div className="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">
        Phishing classifier unavailable{phishing.detail ? ` — ${phishing.detail}` : ""}. Run{" "}
        <code className="rounded bg-muted px-1 py-0.5 text-xs">ml/scripts/train_phishing_classifier.py</code>{" "}
        to enable it.
      </div>
    );
  }
  const pct = (phishing.phishing_probability ?? 0) * 100;
  const tone: BadgeTone = phishing.label === "phishing" ? "danger" : "safe";
  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border border-border p-4">
      <div>
        <p className="text-sm font-medium text-foreground">DistilBERT phishing classifier</p>
        <p className="text-xs text-muted-foreground">
          model-estimated phishing probability, one factor among many — see ml/README.md for
          honestly-reported precision/recall and known limitations
        </p>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        <div className="w-24 overflow-hidden rounded-full bg-muted">
          <div
            className={`h-2 ${tone === "danger" ? "bg-danger" : "bg-safe"}`}
            style={{ width: `${pct}%` }}
          />
        </div>
        <Badge tone={tone}>{pct.toFixed(0)}%</Badge>
      </div>
    </div>
  );
}

function AiTextCard({ aiText }: { aiText: AiSignals["ai_text"] }) {
  if (aiText.source !== "onnx-model") {
    return (
      <div className="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">
        AI-text scoring unavailable
        {aiText.source === "text-too-short" ? " — body too short to score" : ""}
        {aiText.detail ? ` — ${aiText.detail}` : ""}.
      </div>
    );
  }
  return (
    <div className="rounded-lg border border-border p-4">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-foreground">AI-generated-text signal</p>
        {aiText.low_perplexity_flag && <Badge tone="warning">worth a second look</Badge>}
      </div>
      <p className="mt-1 text-xs text-muted-foreground">
        perplexity {aiText.perplexity?.toFixed(1)} against a small reference language model — a
        genuinely weak, noisy signal (see module docs); never a confident classification, and
        weighted accordingly in the score
      </p>
    </div>
  );
}

export function AiSignalsPanel({ signals }: { signals: AiSignals }) {
  const flaggedUrls = signals.urls.urls.filter(
    (u) => u.is_ip_literal || u.anchor_text_mismatch || (u.lookalike && u.lookalike.matches.length > 0),
  );

  return (
    <Card>
      <CardHeader title="AI & content signals" eyebrow="Phase 4" />
      <CardBody className="flex flex-col gap-4">
        <PhishingCard phishing={signals.phishing} />

        {signals.sender_domain_lookalike && signals.sender_domain_lookalike.matches.length > 0 && (
          <div className="rounded-lg border border-danger/30 bg-danger/5 p-4">
            <p className="text-sm font-medium text-foreground">
              Sender domain resembles a known brand: {signals.sender_domain_lookalike.domain}
            </p>
            <LookalikeBadges lookalike={signals.sender_domain_lookalike} />
          </div>
        )}

        {signals.urls.urls.length > 0 && (
          <div>
            <p className="mb-2 text-sm font-medium text-foreground">
              Links found ({signals.urls.urls.length}
              {flaggedUrls.length > 0 ? `, ${flaggedUrls.length} flagged` : ""})
            </p>
            <ul className="flex flex-col gap-2">
              {signals.urls.urls.map((url, i) => (
                <li key={i} className="rounded-lg border border-border p-3 text-xs">
                  <p className="break-all font-mono text-foreground">{url.raw_url}</p>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    {url.is_ip_literal && <Badge tone="danger">IP-literal</Badge>}
                    {url.anchor_text_mismatch && (
                      <Badge tone="danger">
                        text says {url.anchor_claimed_domain}, links to {url.host}
                      </Badge>
                    )}
                    {url.unwrapped_target && (
                      <Badge tone="warning">unwraps to {url.unwrapped_target}</Badge>
                    )}
                    {url.is_newly_registered && <Badge tone="warning">newly registered domain</Badge>}
                  </div>
                  {url.lookalike && <LookalikeBadges lookalike={url.lookalike} />}
                </li>
              ))}
            </ul>
          </div>
        )}

        <AiTextCard aiText={signals.ai_text} />
      </CardBody>
    </Card>
  );
}
