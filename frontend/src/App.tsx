import { useQuery } from "@tanstack/react-query";

import { fetchHealth } from "./lib/api";

const statusColor: Record<string, string> = {
  ok: "text-safe",
  degraded: "text-warning",
  unavailable: "text-danger",
};

export default function App() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
    refetchInterval: 10_000,
  });

  return (
    <main className="min-h-screen flex flex-col items-center justify-center gap-6 px-4">
      <div className="text-center">
        <h1 className="text-4xl font-bold tracking-tight text-accent">TVA</h1>
        <p className="text-sm text-foreground/60 mt-1">
          Threat Variance Authority — For All Mail. Always.
        </p>
      </div>

      <div className="w-full max-w-md rounded-lg border border-border bg-card p-6">
        <h2 className="text-lg font-semibold mb-4">System Status</h2>
        {isLoading && <p className="text-foreground/60">Checking system status...</p>}
        {isError && <p className="text-danger">Unable to reach the API.</p>}
        {data && (
          <ul className="space-y-2">
            <li className="flex justify-between">
              <span>overall</span>
              <span className={statusColor[data.status]}>{data.status}</span>
            </li>
            {data.components.map((component) => (
              <li key={component.name} className="flex justify-between">
                <span>{component.name}</span>
                <span className={statusColor[component.status]}>{component.status}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </main>
  );
}
