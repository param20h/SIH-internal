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
    <div className="mx-auto max-w-4xl px-4 py-16">
      <div className="mb-12">
        <h1 className="text-4xl font-semibold tracking-tight text-clinical-white">Telemetry Intake</h1>
        <p className="mt-4 text-muted-steel max-w-2xl text-lg">
          Initialize a new forensic pipeline. Upload a raw <code className="mono-data bg-surface-pure px-2 py-0.5 rounded border border-whisper-border">.eml</code> or{" "}
          <code className="mono-data bg-surface-pure px-2 py-0.5 rounded border border-whisper-border">.msg</code> file, or paste the raw
          source directly. The deterministic forensics engine runs strictly offline.
        </p>
      </div>

      <div className="border border-whisper-border bg-surface-pure rounded-xl overflow-hidden shadow-whisper-drop transition-spring">
        <div className="border-b border-whisper-border p-4 bg-canvas-deep flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-2 w-2 rounded-full bg-technical-cyan animate-pulse" />
            <span className="label-md text-muted-steel uppercase tracking-widest">Intake Vector</span>
          </div>
          <div className="flex gap-2" role="tablist">
            <button
              role="tab"
              aria-selected={mode === "upload"}
              onClick={() => setMode("upload")}
              className={`label-md px-4 py-2 rounded-md transition-spring ${
                mode === "upload" 
                  ? "bg-technical-cyan/10 text-technical-cyan border border-technical-cyan/30" 
                  : "text-muted-steel hover:bg-canvas-deep border border-transparent"
              }`}
            >
              File Drop
            </button>
            <button
              role="tab"
              aria-selected={mode === "paste"}
              onClick={() => setMode("paste")}
              className={`label-md px-4 py-2 rounded-md transition-spring ${
                mode === "paste" 
                  ? "bg-technical-cyan/10 text-technical-cyan border border-technical-cyan/30" 
                  : "text-muted-steel hover:bg-canvas-deep border border-transparent"
              }`}
            >
              Raw Input
            </button>
          </div>
        </div>
        
        <div className="p-8">
          {mode === "upload" ? (
            <UploadDropzone onFiles={handleFiles} disabled={isPending} />
          ) : (
            <div className="flex flex-col gap-4">
              <label htmlFor="raw-headers" className="text-sm text-muted-steel">
                Raw source data (headers + payload). Parsed exactly as standard telemetry.
              </label>
              <textarea
                id="raw-headers"
                value={pasted}
                onChange={(e) => setPasted(e.target.value)}
                disabled={isPending}
                rows={16}
                spellCheck={false}
                placeholder={"Received: from mail.example.test ...\nFrom: sender@example.test\nSubject: ...\n\n[Payload...]"}
                className="w-full rounded-lg border border-whisper-border bg-canvas-deep p-4 mono-data text-muted-steel focus:border-technical-cyan focus:ring-1 focus:ring-technical-cyan transition-spring outline-none resize-y"
              />
              <div className="flex justify-end pt-2">
                <Button onClick={handlePasteSubmit} disabled={isPending} className="active-spring bg-technical-cyan text-canvas-deep hover:bg-technical-cyan/90">
                  {isPending && <Spinner className="h-4 w-4 mr-2" />}
                  Execute Analysis
                </Button>
              </div>
            </div>
          )}

          {isPending && mode === "upload" && (
            <div className="mt-6 flex items-center justify-center gap-3 text-sm text-technical-cyan mono-data">
              <Spinner className="h-4 w-4" />
              Initializing deterministic forensics pipeline...
            </div>
          )}

          {error && (
            <div role="alert" className="mt-6 rounded-lg border border-forensic-red/30 bg-forensic-red/10 p-4 flex items-center gap-3">
              <div className="h-2 w-2 rounded-full bg-forensic-red" />
              <p className="text-sm text-forensic-red mono-data">{error}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
