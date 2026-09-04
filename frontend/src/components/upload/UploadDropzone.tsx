import { type DragEvent, useCallback, useRef, useState } from "react";

import { cn } from "../../lib/utils";

export function UploadDropzone({
  onFiles,
  disabled,
}: {
  onFiles: (files: File[]) => void;
  disabled?: boolean;
}) {
  const [isDragging, setIsDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback(
    (event: DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      setIsDragging(false);
      if (disabled) return;
      const files = Array.from(event.dataTransfer.files);
      if (files.length > 0) onFiles(files);
    },
    [disabled, onFiles],
  );

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label="Upload .eml or .msg files by dropping them here or pressing Enter to browse"
      onClick={() => inputRef.current?.click()}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
      }}
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setIsDragging(true);
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      className={cn(
        "flex cursor-pointer flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed p-12 text-center transition-colors",
        isDragging ? "border-accent bg-accent/5" : "border-border bg-muted/30 hover:border-accent/50",
        disabled && "pointer-events-none opacity-50",
      )}
    >
      <svg
        width="40"
        height="40"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        className="text-muted-foreground"
        aria-hidden="true"
      >
        <path d="M12 16V4M12 4l-4 4M12 4l4 4" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <div>
        <p className="font-medium text-foreground">Drop .eml or .msg files here</p>
        <p className="mt-1 text-sm text-muted-foreground">or click to browse — multiple files queue as a batch</p>
      </div>
      <input
        ref={inputRef}
        type="file"
        multiple
        accept=".eml,.msg,message/rfc822"
        className="sr-only"
        onChange={(e) => {
          const files = Array.from(e.target.files ?? []);
          if (files.length > 0) onFiles(files);
          e.target.value = "";
        }}
      />
    </div>
  );
}
