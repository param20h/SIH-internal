import { useQuery } from "@tanstack/react-query";
import { NavLink } from "react-router-dom";

import { fetchHealth } from "../../lib/api";
import { cn } from "../../lib/utils";

const links = [
  { to: "/", label: "Upload", end: true },
  { to: "/analyses", label: "Nexus Events" },
  { to: "/dashboard", label: "Dashboard" },
];

function HealthDot() {
  const { data } = useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
    refetchInterval: 15_000,
    retry: false,
  });
  const status = data?.status ?? "down";
  const color =
    status === "ok" ? "bg-safe" : status === "degraded" ? "bg-warning" : "bg-danger";
  const label =
    status === "ok" ? "All systems operational" : status === "degraded" ? "Degraded" : "Unreachable";
  return (
    <span className="flex items-center gap-1.5 text-xs text-muted-foreground" title={label}>
      <span className={cn("h-2 w-2 rounded-full", color)} />
      <span className="hidden sm:inline">{label}</span>
    </span>
  );
}

export function Nav() {
  return (
    <header className="sticky top-0 z-10 border-b border-border bg-background/95 backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3">
        <NavLink to="/" className="flex items-baseline gap-2" end>
          <span className="text-lg font-bold tracking-tight text-accent">TVA</span>
          <span className="hidden text-xs text-muted-foreground sm:inline">
            Threat Variance Authority
          </span>
        </NavLink>
        <div className="flex items-center gap-4">
          <nav className="flex items-center gap-1" aria-label="Primary">
            {links.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                end={link.end}
                className={({ isActive }) =>
                  cn(
                    "rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                    isActive
                      ? "bg-accent/15 text-accent"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground",
                  )
                }
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
          <HealthDot />
        </div>
      </div>
    </header>
  );
}
