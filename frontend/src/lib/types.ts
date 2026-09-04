// Mirrors backend/app/schemas/analysis.py and backend/app/forensics/models.py.
// Field names match the JSON the API actually returns (snake_case, no
// aliasing on the Pydantic side) so this file is a direct transcription,
// not a reinterpretation.

export type AnalysisStatus = "pending" | "processing" | "complete" | "failed";
export type Verdict = "clean" | "suspicious" | "malicious";
export type AnomalySeverity = "info" | "low" | "medium" | "high" | "critical";
export type ScoreCategory =
  | "authentication"
  | "relay_chain"
  | "phishing_classifier"
  | "lookalike_domain"
  | "url_analysis"
  | "ai_text";
export type AuthResultValue =
  | "pass"
  | "fail"
  | "softfail"
  | "neutral"
  | "none"
  | "temperror"
  | "permerror"
  | "policy"
  | "unknown";

export type AttributionConfidence = "low" | "medium" | "high" | "unknown";
export type IocType = "ipv4" | "ipv6" | "domain" | "url" | "sha256" | "email";

export interface ParseIssue {
  field: string;
  detail: string;
}

export interface AttachmentInfo {
  filename: string;
  content_type: string | null;
  size_bytes: number;
  sha256: string;
}

export interface ParsedEmailMeta {
  from_display_name: string | null;
  from_address: string | null;
  to_addresses: string[];
  subject: string | null;
  date_raw: string | null;
  date_parsed: string | null;
  message_id: string | null;
  return_path: string | null;
  content_type: string | null;
  has_attachments: boolean;
  attachment_names: string[];
  attachments: AttachmentInfo[];
  parse_confidence: number;
  issues: ParseIssue[];
  source_format: "eml" | "msg";
  sha256: string;
}

export interface AuthResult {
  mechanism: "spf" | "dkim" | "dmarc";
  result: AuthResultValue;
  reason: string | null;
  domain: string | null;
  raw_segment: string;
}

export interface AuthenticationSummary {
  spf: AuthResult | null;
  dkim: AuthResult | null;
  dmarc: AuthResult | null;
  source: "authentication-results-header" | "unavailable";
  raw_header: string | null;
  dkim_signature_present: boolean;
  dkim_signature_expired: boolean;
  dkim_expiry: string | null;
  dmarc_policy: "none" | "quarantine" | "reject" | "unknown";
}

export interface HopOut {
  id: string;
  sequence: number;
  raw_header: string;
  from_host: string | null;
  from_ip: string | null;
  by_host: string | null;
  protocol: string | null;
  timestamp_raw: string | null;
  timestamp: string | null;
  parse_confidence: number;
  asn: number | null;
  asn_org: string | null;
  country: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  enrichment_source: "geolite2-local" | "unavailable";
  is_bogon: boolean;
}

export interface AnomalyOut {
  id: string;
  type: string;
  severity: AnomalySeverity;
  hop_sequences: number[];
  summary: string;
  evidence: string;
}

export interface ScoreFactor {
  name: string;
  weight: number;
  evidence: string;
  category: ScoreCategory;
}

export interface RiskScore {
  score: number;
  verdict: Verdict;
  factors: ScoreFactor[];
}

export interface DomainIntel {
  domain: string;
  registration_date: string | null;
  age_days: number | null;
  source: "live" | "cached" | "unavailable";
  detail: string | null;
}

export interface AnalysisSummary {
  id: string;
  filename: string;
  source_format: string;
  status: AnalysisStatus;
  status_detail: string | null;
  parse_confidence: number;
  from_display_name: string | null;
  from_address: string | null;
  subject: string | null;
  message_date: string | null;
  spf_result: string | null;
  dkim_result: string | null;
  dmarc_result: string | null;
  dmarc_policy: string;
  dkim_signature_expired: boolean;
  risk_score: number;
  verdict: Verdict;
  hop_count: number;
  anomaly_count: number;
  highest_anomaly_severity: AnomalySeverity | null;
  phishing_probability: number | null;
  analyst_notes: string | null;
  created_at: string;
}

// --- Phase 4: AI/content signals ---

export type LookalikeMethod = "homoglyph_skeleton" | "levenshtein" | "jaro_winkler" | "brand_substring";

export interface LookalikeMatch {
  matched_brand: string;
  method: LookalikeMethod;
  detail: string;
}

export interface LookalikeAnalysis {
  domain: string;
  is_punycode: boolean;
  decoded_unicode: string | null;
  matches: LookalikeMatch[];
}

export interface ExtractedUrl {
  raw_url: string;
  scheme: string | null;
  host: string | null;
  is_ip_literal: boolean;
  anchor_text: string | null;
  anchor_claimed_domain: string | null;
  anchor_text_mismatch: boolean;
  unwrapped_target: string | null;
  lookalike: LookalikeAnalysis | null;
  domain_intel: DomainIntel | null;
  is_newly_registered: boolean | null;
}

export interface UrlAnalysis {
  urls: ExtractedUrl[];
}

export interface PhishingClassification {
  source: "onnx-model" | "unavailable";
  phishing_probability: number | null;
  label: "phishing" | "ham" | null;
  detail: string | null;
}

export interface AiTextScore {
  source: "onnx-model" | "unavailable" | "text-too-short";
  perplexity: number | null;
  low_perplexity_flag: boolean;
  detail: string | null;
}

export interface AiSignals {
  sender_domain_lookalike: LookalikeAnalysis | null;
  urls: UrlAnalysis;
  phishing: PhishingClassification;
  ai_text: AiTextScore;
}

// --- Phase 5: attribution & evidence export ---

export interface OriginAttribution {
  source: "heuristic" | "unavailable";
  origin_ip: string | null;
  origin_hop_sequence: number | null;
  asn: number | null;
  asn_org: string | null;
  country: string | null;
  confidence: AttributionConfidence;
  reasoning: string;
}

export interface Ioc {
  type: IocType;
  value: string;
  context: string;
}

export interface IocListResponse {
  case_id: string;
  iocs: Ioc[];
}

export interface AnalysisDetail extends AnalysisSummary {
  meta: ParsedEmailMeta;
  authentication: AuthenticationSummary;
  hops: HopOut[];
  anomalies: AnomalyOut[];
  risk: RiskScore;
  sender_domain_intel: DomainIntel | null;
  ai_signals: AiSignals;
  attribution: OriginAttribution;
}

export interface AnalysisListResponse {
  total: number;
  limit: number;
  offset: number;
  items: AnalysisSummary[];
}

export interface BatchUploadItem {
  analysis_id: string;
  filename: string;
  status: AnalysisStatus;
}

export interface SkippedUpload {
  filename: string;
  reason: string;
}

export interface BatchUploadResponse {
  items: BatchUploadItem[];
  skipped: SkippedUpload[];
}

export interface StatsResponse {
  total_analyses: number;
  status_breakdown: Record<string, number>;
  verdict_breakdown: Record<string, number>;
  spf_breakdown: Record<string, number>;
  dkim_breakdown: Record<string, number>;
  dmarc_breakdown: Record<string, number>;
  anomaly_type_breakdown: Record<string, number>;
  anomaly_severity_breakdown: Record<string, number>;
  analyses_last_24h: number;
}
