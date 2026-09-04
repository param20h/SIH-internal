import type { HTMLAttributes, ReactNode } from "react";

import { cn } from "../../lib/utils";

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-xl border border-border bg-card", className)} {...props} />;
}

export function CardHeader({
  title,
  eyebrow,
  action,
  className,
}: {
  title: ReactNode;
  eyebrow?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-start justify-between gap-4 border-b border-border p-4", className)}>
      <div>
        {eyebrow && (
          <div className="mb-1 text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {eyebrow}
          </div>
        )}
        <h2 className="text-base font-semibold text-foreground">{title}</h2>
      </div>
      {action}
    </div>
  );
}

export function CardBody({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("p-4", className)} {...props} />;
}
