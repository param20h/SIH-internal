import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { uploadAnalysis, uploadBatch } from "../lib/api";
import { UploadDropzone } from "../components/upload/UploadDropzone";
import { Button } from "../components/ui/Button";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { Spinner } from "../components/ui/Spinner";

type Mode = "upload" | "paste";

export default function UploadPage() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<Mode>("upload");
  const [pasted, setPasted] = useState("");
  const [error, setError] = useState<string | null>(null);

  const singleMutation = useMutation({
    mutationFn: uploadAnalysis,
    onSuccess: (detail) => navigate(`/analyses/${detail.id}`),
    onError: (err: Error) => setError(err.message),
  });

  const batchMutation = useMutation({
    mutationFn: uploadBatch,
    onSuccess: () => navigate("/analyses"),
    onError: (err: Error) => setError(err.message),
  });

  const isPending = singleMutation.isPending || batchMutation.isPending;

  function handleFiles(files: File[]) {
    setError(null);
    const [first] = files;
    if (files.length === 1 && first) {
      singleMutation.mutate(first);
    } else {
      batchMutation.mutate(files);
    }
  }

  function handlePasteSubmit() {
    setError(null);
    if (!pasted.trim()) {
      setError("Paste some raw headers or a full email source first.");
      return;
    }
    const file = new File([pasted], "pasted-email.eml", { type: "message/rfc822" });
    singleMutation.mutate(file);
  }

  return (
    <div className="mx-auto max-w-3xl px-4 py-10">
      <div className="mb-8 text-center">
        <h1 className="text-3xl font-bold tracking-tight text-foreground">Analyze an email</h1>
        <p className="mt-2 text-muted-foreground">
          Upload a raw <code className="rounded bg-muted px-1 py-0.5 text-xs">.eml</code> or{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-xs">.msg</code> file, or paste the raw
          source directly. Everything runs against the deterministic forensics engine offline.
        </p>
      </div>

      <Card>
        <CardHeader
          title={mode === "upload" ? "Upload files" : "Paste raw email source"}
          eyebrow="New Nexus Event"
          action={
            <div className="flex gap-1 rounded-lg border border-border bg-muted p-1" role="tablist">
              <button
                role="tab"
                aria-selected={mode === "upload"}
                onClick={() => setMode("upload")}
                className={`rounded-md px-3 py-1 text-sm font-medium transition-colors ${
                  mode === "upload" ? "bg-accent text-background" : "text-muted-foreground"
                }`}
              >
                Upload
              </button>
              <button
                role="tab"
                aria-selected={mode === "paste"}
                onClick={() => setMode("paste")}
                className={`rounded-md px-3 py-1 text-sm font-medium transition-colors ${
                  mode === "paste" ? "bg-accent text-background" : "text-muted-foreground"
                }`}
              >
                Paste headers
              </button>
            </div>
          }
        />
        <CardBody>
          {mode === "upload" ? (
            <UploadDropzone onFiles={handleFiles} disabled={isPending} />
          ) : (
            <div className="flex flex-col gap-3">
              <label htmlFor="raw-headers" className="text-sm text-muted-foreground">
                Paste the full raw email source (headers plus body). This is treated exactly like an
                uploaded <code>.eml</code> file.
              </label>
              <textarea
                id="raw-headers"
                value={pasted}
                onChange={(e) => setPasted(e.target.value)}
                disabled={isPending}
                rows={14}
                spellCheck={false}
                placeholder={"Received: from mail.example.test ...\nFrom: sender@example.test\nSubject: ...\n\nbody..."}
                className="w-full rounded-lg border border-border bg-background p-3 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:border-accent"
              />
              <div>
                <Button onClick={handlePasteSubmit} disabled={isPending}>
                  {isPending && <Spinner className="h-4 w-4" />}
                  Analyze pasted source
                </Button>
              </div>
            </div>
          )}

          {isPending && mode === "upload" && (
            <div className="mt-4 flex items-center justify-center gap-2 text-sm text-muted-foreground">
              <Spinner className="h-4 w-4" />
              Running the deterministic forensics pipeline…
            </div>
          )}

          {error && (
            <p role="alert" className="mt-4 rounded-lg border border-danger/30 bg-danger/10 p-3 text-sm text-danger">
              {error}
            </p>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
