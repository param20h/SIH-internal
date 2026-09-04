import type { ButtonHTMLAttributes } from "react";

import { cn } from "../../lib/utils";

export type ButtonVariant = "primary" | "secondary" | "ghost";

const variantClasses: Record<ButtonVariant, string> = {
  primary: "bg-accent text-background hover:bg-accent/90",
  secondary: "bg-muted text-foreground border border-border hover:bg-muted/70",
  ghost: "text-foreground hover:bg-muted",
};

export function Button({
  variant = "primary",
  className,
  disabled,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-medium",
        "transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        variantClasses[variant],
        className,
      )}
      disabled={disabled}
      {...props}
    />
  );
}
