# Design System: TVA (Threat Variance Authority)

## 1. Visual Theme & Atmosphere
A restrained, high-density forensic interface with a technical "dark mode" atmosphere. It feels like a clinical security operations center — dark surfaces, precise lines, and fluid spring-physics motion. The atmosphere is stark, authoritative, and data-driven, using strict monospace typography for forensic indicators to elevate trust and readability.

## 2. Color Palette & Roles
- **Canvas Deep** (#09090B) — Primary background surface, absolute depth. (Zinc-950)
- **Pure Surface** (#18181B) — Card and container fill. (Zinc-900)
- **Clinical White** (#FAFAFA) — Primary text, headlines. (Zinc-50)
- **Muted Steel** (#A1A1AA) — Secondary text, descriptions, metadata, timestamps. (Zinc-400)
- **Whisper Border** (rgba(255,255,255,0.1)) — Card borders, 1px structural lines.
- **Technical Cyan** (#06B6D4) — Single accent for CTAs, active states, focus rings. (Cyan-500)
- **Forensic Red** (#EF4444) — Semantic color for malicious verdicts and critical anomalies. (Red-500)
- **Forensic Amber** (#F59E0B) — Semantic color for suspicious verdicts. (Amber-500)
- **Forensic Green** (#10B981) — Semantic color for clean verdicts. (Emerald-500)

## 3. Typography Rules
- **Display:** `Geist` — Track-tight, controlled scale, weight-driven hierarchy. Used for headers and primary UI text.
- **Body:** `Geist` — Relaxed leading, 65ch max-width, neutral secondary color.
- **Mono:** `JetBrains Mono` — For code, metadata, timestamps, IP addresses, hashes, and high-density numbers.
- **Banned:** `Inter`, emojis, pure black (`#000000`), generic system fonts, serifs.

## 4. Component Stylings
* **Buttons:** Flat, no outer glow. Tactile -1px translate on active state (hardware accelerated). Accent fill for primary, ghost/outline with whisper border for secondary.
* **Cards:** Generously rounded corners (1rem). Diffused whisper shadow (very subtle inset or drop). Used only when elevation serves hierarchy. For high-density tables (hops, IOCs), replace cards with border-top dividers or negative space.
* **Inputs:** Label above, error below. Focus ring in Technical Cyan. No floating labels.
* **Loaders:** Skeletal shimmer matching exact layout dimensions. No circular spinners.
* **Empty States:** Composed, clinical configurations — clear "No hop geolocation available" with structured layout, not just centered text.
* **Badges:** Pill-shaped, subtle background opacity (15%), solid border.

## 5. Layout Principles
- Grid-first responsive architecture.
- Asymmetric splits for Dashboard and Analysis sections.
- Strict single-column collapse below 768px. No horizontal scroll.
- Max-width containment (1400px centered).
- No flexbox percentage math. Generous internal padding between layout zones.
- No overlapping elements — every element occupies its own clear spatial zone.

## 6. Motion & Interaction
- **Spring physics** for all interactive elements (stiffness: 100, damping: 20).
- Staggered cascade reveals for table rows (hops, IOCs).
- Perpetual micro-loops on active dashboard components (e.g., very slow pulse on the verdict radial gauge).
- Hardware-accelerated transforms (`transform`, `opacity`) only.

## 7. Anti-Patterns (Banned)
- No emojis anywhere.
- No `Inter` font.
- No generic serif fonts.
- No pure black (`#000000`).
- No neon/outer glow shadows.
- No oversaturated accents (except specific semantic threat colors).
- No excessive gradient text on large headers.
- No custom mouse cursors.
- No overlapping elements.
- No 3-column equal card layouts.
- No generic AI copywriting clichés ("Elevate", "Seamless", "Unleash").
- No filler UI text ("Scroll to explore", bouncing chevrons).
