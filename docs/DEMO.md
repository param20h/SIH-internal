# 3-minute demo script

A timed walkthrough for SIH26106 judging. Assumes the stack is already
running and seeded (see "Before you go on stage" below) — don't run either
step live in front of judges, it wastes clock time on a spinner.

## Before you go on stage

```bash
docker compose up --build -d
make migrate
make demo        # wipes and re-seeds all 20 sample analyses, ~15s
```

Open `http://localhost:5173/dashboard` in a browser tab and leave it there
— that's where the demo starts. Confirm `http://localhost:5173` shows
"All systems operational" in the header before you start talking.

## 0:00 – 0:20 — The problem, in one line

> "Security teams get a flagged email and a black-box score. They can't
> tell a judge, a client, or their own analyst *why* it's flagged, or
> where it actually came from. TVA answers both — offline, and every
> number on screen is traceable to real evidence."

Stay on the **Dashboard**. Point at the verdict-breakdown chart: 20 real
sample emails, already analyzed, sitting in front of you with no network
call made to score any of them.

## 0:20 – 1:10 — Upload → explainable verdict (the "Miss Minutes" money shot)

Click into the malicious case from the recent list
(`13_forged_received_header_injected.eml` — a password-reset phish with an
injected Received header). On the analysis page:

- Point at the **100/100 MALICIOUS** ring — say the number out loud.
- Scroll to **Indicator breakdown** (eyebrow: "Miss Minutes"). Click open
  two or three factor rows — DMARC fail, SPF fail, phishing classifier.
  Each row expands to the *exact* evidence string that produced its
  weight. "No hidden score. Every point on that 100 is this list."

## 1:10 – 1:50 — Relay path & origin attribution (the map money shot)

Scroll to **Relay chain** and **Origin attribution**. Narrate:

- The relay chain shows 3 hops with a chain-continuity break flagged
  between hop 1 and hop 2 — "the claimed handoff doesn't match, which is
  what a forged Received header looks like structurally."
- Attribution panel: **low confidence**, and read one sentence of the
  reasoning text. "TVA doesn't just point at an IP — it tells you *why*
  it's not sure, because the chain shows signs of tampering. A tool that
  claims high confidence here would be lying to you."

If a `GeoLite2-City.mmdb` is installed, switch to a sample with clean geo
data (e.g. `11_long_relay_chain_9hops.eml`) to show the actual world map;
otherwise stay on the honest "no hop geolocation available" state — it's
not a bug, it's the offline-degradation contract working as designed.

## 1:50 – 2:25 — AI signals catching what auth checks miss

Navigate to `09_homoglyph_domain_paypal.eml` — SPF/DKIM/DMARC all *pass*
on this one. "Under a rules-only tool, this would score zero." Point at
the **AI & content signals** panel: sender domain lookalike
(`paypaI.com` → `paypal.com`, flagged by name-confusable-character
detection) and the phishing classifier's probability. Verdict: 57,
suspicious — "caught entirely by the additive AI layer, still fully
explained."

## 2:25 – 2:50 — Evidence export (the forensic case)

Back on the `13_forged_...` analysis: click **Forensic PDF report** —
let it download, open it, flip to page 1 (chain of custody + verdict) and
page 2 (indicators + IOCs). "This is what goes to a client or a court —
SHA-256 of the original file, full reasoning, not a screenshot." Point at
the **IOC table** and its **STIX 2.1** button — "drops straight into a
SIEM or threat-intel platform."

## 2:50 – 3:00 — Close

> "Deterministic core, zero models required. AI is additive, never a
> black box. Fully offline. One `docker compose up`. That's TVA — for all
> mail, always."

## If something goes wrong on stage

- **Blank dashboard / empty list** — `make demo` wasn't run, or was run
  against a different Postgres volume than the one the browser is
  pointed at. Re-run it; it's idempotent and takes under 15 seconds.
- **AI panel shows "unavailable"** — the ONNX models weren't trained
  into `data/models/` on this machine (see the root README's Phase 4
  section). The deterministic score and verdict are still fully correct
  without them; say so rather than treating it as a bug.
- **No geolocation on the map** — `data/geoip/GeoLite2-City.mmdb` isn't
  installed on this machine (MaxMind license terms mean it's never
  bundled — see `data/geoip/README.md`). This is the designed degrade
  path, not a failure; the relay chain and every other panel still work.
- **A judge asks "is this really offline?"** — see "Offline-mode
  verification" in the root README for the exact `docker run --network
  none` command that proves it, runnable live if there's time.
