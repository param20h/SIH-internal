import type { ReactNode } from "react";

import { cn } from "../../lib/utils";

export type BadgeTone = "neutral" | "accent" | "danger" | "warning" | "safe";

const toneClasses: Record<BadgeTone, string> = {
  neutral: "bg-muted text-muted-foreground border-border",
  accent: "bg-accent/15 text-accent border-accent/30",
  danger: "bg-danger/15 text-danger border-danger/30",
  warning: "bg-warning/15 text-warning border-warning/30",
  safe: "bg-safe/15 text-safe border-safe/30",
};

export function Badge({
  children,
  tone = "neutral",
  className,
}: {
  children: ReactNode;
  tone?: BadgeTone;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium",
        toneClasses[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}
