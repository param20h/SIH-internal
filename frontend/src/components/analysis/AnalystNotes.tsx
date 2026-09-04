import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { updateAnalystNotes } from "../../lib/api";
import type { AnalysisDetail } from "../../lib/types";
import { Button } from "../ui/Button";
import { Card, CardBody, CardHeader } from "../ui/Card";
import { Spinner } from "../ui/Spinner";

export function AnalystNotes({ analysis }: { analysis: AnalysisDetail }) {
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState(analysis.analyst_notes ?? "");

  // Keep the draft in sync when a different analysis (or a fresh server
  // value) loads -- but not while the user is actively typing here.
  useEffect(() => {
    setDraft(analysis.analyst_notes ?? "");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysis.id]);

  const mutation = useMutation({
    mutationFn: (notes: string) => updateAnalystNotes(analysis.id, notes),
    onSuccess: (updated) => {
      queryClient.setQueryData(["analysis", analysis.id], updated);
    },
  });

  const dirty = draft !== (analysis.analyst_notes ?? "");

  return (
    <Card>
      <CardHeader title="Analyst notes" eyebrow="Case file" />
      <CardBody className="flex flex-col gap-3">
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          maxLength={4096}
          rows={4}
          placeholder="Record findings, escalation status, or other case context…"
          className="w-full resize-y rounded-lg border border-border bg-muted p-3 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent/50"
        />
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground">
            {draft.length}/4096
            {mutation.isError && (
              <span className="ml-2 text-danger">{(mutation.error as Error).message}</span>
            )}
            {mutation.isSuccess && !dirty && <span className="ml-2 text-safe">Saved.</span>}
          </span>
          <Button
            variant="secondary"
            disabled={!dirty || mutation.isPending}
            onClick={() => mutation.mutate(draft)}
          >
            {mutation.isPending && <Spinner className="h-4 w-4" />}
            Save notes
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}
