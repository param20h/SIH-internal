export const API_BASE_URL: string = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

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

export async function fetchHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE_URL}/health`);
  if (!response.ok) {
    throw new Error(`Health check failed with status ${response.status}`);
  }
  return (await response.json()) as HealthResponse;
}
