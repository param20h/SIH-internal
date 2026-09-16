import { useQuery } from "@tanstack/react-query";
import { NavLink } from "react-router-dom";
import { useEffect, useState } from "react";

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

function ThemeToggle() {
  const [isDark, setIsDark] = useState(() => {
    // Check local storage or default to dark
    const saved = localStorage.getItem("theme");
    if (saved) return saved === "dark";
    // default to dark mode for the forensic look
    return true; 
  });

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add("dark");
      localStorage.setItem("theme", "dark");
    } else {
      document.documentElement.classList.remove("dark");
      localStorage.setItem("theme", "light");
    }
  }, [isDark]);

  return (
    <button
      onClick={() => setIsDark(!isDark)}
      className="p-1.5 text-muted-foreground hover:text-foreground transition-colors"
      title="Toggle theme"
    >
      {isDark ? (
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>
      ) : (
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>
      )}
    </button>
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
          <div className="h-4 w-px bg-border mx-1" />
          <ThemeToggle />
          <HealthDot />
        </div>
      </div>
    </header>
  );
}
