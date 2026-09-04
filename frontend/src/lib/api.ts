import type {
  AnalysisDetail,
  AnalysisListResponse,
  BatchUploadResponse,
  IocListResponse,
  StatsResponse,
} from "./types";

export const API_BASE_URL: string = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
const API_V1 = `${API_BASE_URL}/api/v1`;

export interface ComponentHealth {
  name: string;
  status: "ok" | "degraded" | "unavailable";
  detail: string | null;
}

export interface HealthResponse {
  status: "ok" | "degraded";
  app_name: string;
  version: string;
  components: ComponentHealth[];
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

async function parseErrorDetail(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json();
    if (body && typeof body === "object" && "detail" in body) {
      const detail = (body as { detail: unknown }).detail;
      if (typeof detail === "string") return detail;
    }
  } catch {
    // fall through to generic message
  }
  return `request failed with status ${response.status}`;
}

export async function fetchHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE_URL}/health`);
  if (!response.ok) {
    throw new ApiError(response.status, await parseErrorDetail(response));
  }
  return (await response.json()) as HealthResponse;
}

export async function uploadAnalysis(file: File): Promise<AnalysisDetail> {
  const formData = new FormData();
  formData.append("file", file);
  const response = await fetch(`${API_V1}/analyses`, { method: "POST", body: formData });
  if (!response.ok) {
    throw new ApiError(response.status, await parseErrorDetail(response));
  }
  return (await response.json()) as AnalysisDetail;
}

export async function uploadBatch(files: File[]): Promise<BatchUploadResponse> {
  const formData = new FormData();
  for (const file of files) formData.append("files", file);
  const response = await fetch(`${API_V1}/analyses/batch`, { method: "POST", body: formData });
  if (!response.ok) {
    throw new ApiError(response.status, await parseErrorDetail(response));
  }
  return (await response.json()) as BatchUploadResponse;
}

export async function getAnalysis(id: string): Promise<AnalysisDetail> {
  const response = await fetch(`${API_V1}/analyses/${id}`);
  if (!response.ok) {
    throw new ApiError(response.status, await parseErrorDetail(response));
  }
  return (await response.json()) as AnalysisDetail;
}

export interface ListAnalysesParams {
  limit?: number;
  offset?: number;
  status?: string;
  spf_result?: string;
  dkim_result?: string;
  dmarc_result?: string;
}

export async function listAnalyses(params: ListAnalysesParams = {}): Promise<AnalysisListResponse> {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) query.set(key, String(value));
  }
  const response = await fetch(`${API_V1}/analyses?${query.toString()}`);
  if (!response.ok) {
    throw new ApiError(response.status, await parseErrorDetail(response));
  }
  return (await response.json()) as AnalysisListResponse;
}

export async function fetchStats(): Promise<StatsResponse> {
  const response = await fetch(`${API_V1}/stats`);
  if (!response.ok) {
    throw new ApiError(response.status, await parseErrorDetail(response));
  }
  return (await response.json()) as StatsResponse;
}

export async function getIocs(id: string): Promise<IocListResponse> {
  const response = await fetch(`${API_V1}/analyses/${id}/iocs`);
  if (!response.ok) {
    throw new ApiError(response.status, await parseErrorDetail(response));
  }
  return (await response.json()) as IocListResponse;
}

export async function updateAnalystNotes(id: string, notes: string): Promise<AnalysisDetail> {
  const response = await fetch(`${API_V1}/analyses/${id}/notes`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ notes }),
  });
  if (!response.ok) {
    throw new ApiError(response.status, await parseErrorDetail(response));
  }
  return (await response.json()) as AnalysisDetail;
}

export function exportUrl(
  id: string,
  format: "json" | "txt" | "eml" | "pdf" | "stix" | "ioc-csv",
): string {
  return `${API_V1}/analyses/${id}/export?format=${format}`;
}
