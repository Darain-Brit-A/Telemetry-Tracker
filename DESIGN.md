# TeleTracker Frontend Design System (`DESIGN.md`)

Guide for contributors working on the **Tier 2 SaaS Dashboard** (`saas/static/`) and **Tier 1 Local Collector Console** (`collector/ui.html`, `collector/ui.js`).

All styling uses centralized CSS custom properties with **zero external dependencies or CDNs** so both consoles work offline and comply with the strict Content Security Policy in `common/web.py`.

---

## 1. Core Design Principle

> **Slate Blue (`#4263A3`) communicates interaction. Emerald Green (`#16843D`) communicates health and success.**

Do **not** recolor health/success badges to blue, and do **not** use emerald green for primary buttons, active tabs, or focus rings. Keeping interaction and health visually separate makes the operational console immediately scannable.

---

## 2. Tier 2 SaaS Dashboard Palette (`saas/static/style.css`)

### Surfaces & Typography
| Token | Emerald Default | Teal Variant (`[data-theme="medcity"]`) | Usage |
|---|---|---|---|
| `--color-background` | `#FCFBF7` | `#F6F9F8` | Page canvas (warm cream / cool clinical off-white) |
| `--color-surface` | `#FFFFFF` | `#FFFFFF` | Cards, header, login panel, inputs |
| `--color-surface-subtle` | `#F6F9F6` | `#EFF6F5` | Table headers, code blocks, expanded incident panels, chart backgrounds |
| `--color-surface-muted` | `#EAF6E9` | `#E6F4F2` | Subtle botanical/mint washes |
| `--color-text-primary` | `#173329` | `#0F2B27` | Headings, primary data values, primary body copy |
| `--color-text-secondary` | `#43594E` | `#2E524D` | Supporting descriptions, labels |
| `--color-text-muted` | `#65766C` | `#4B6E68` | Timestamps, footnotes, secondary captions |
| `--border-subtle` | `#E1EAE3` | `#D8E6E4` | Card borders, table dividers, header divider |
| `--border-strong` | `#C5D8CA` | `#B4CECA` | Input borders, ghost button borders |

### Interactive Accent — Slate Blue (Shared Across Both Themes)
| Token | Hex | Usage |
|---|---|---|
| `--color-primary` | `#4263A3` | Active nav tab, primary buttons (`Sign in`, `Save thresholds`, `Approve & run`, `Search SaaS store`), active theme switcher pill, links, focus rings, confidence bar, selected source border, primary chart line |
| `--color-primary-hover` | `#34528D` | Hover state for primary buttons and active controls |
| `--color-primary-active` | `#294778` | Active/pressed state for primary buttons |
| `--color-primary-subtle` | `#EAF1FF` | Secondary button fill, selected table row highlight, hover background on tabs/ghost buttons/incident rows, metadata `.tag` pills, focus ring halo |
| `--color-primary-subtle-hover` | `#DCE7FA` | Hover fill for `.sec` buttons and active ghost buttons |
| `--color-primary-border` | `#CFDCF3` | Border for `.sec` buttons, `.tag` pills, `.action` container, hovered incidents |
| `--color-primary-text` | `#294778` | High-contrast text on `--color-primary-subtle` |
| `--color-primary-secondary-text` | `#526477` | Inactive nav tab text, inactive switcher button text, confidence label |

### Brand & Success — Emerald Green
| Token | Hex | Usage |
|---|---|---|
| `--color-success` | `#16843D` | Brand tier sub-label, passing SLOs (`.okc`), `0` sequence gaps, `0` secret matches, policy checkmarks (`✓`), `Saved (audited)` confirmation, Excellent chart threshold line |
| `--color-success-dark` | `#14532D` | Tier chip text on login screen |
| `--color-success-subtle` | `#EAF6E9` | Tier chip background, Excellent state background |
| `--color-success-border` | `#BBDFC0` | Tier chip border |

### Semantic Health & Severity States
Every health state has a distinct color **and** an explicit text label (color is never the sole indicator, including in the Health Map):

| State | Text | Dot | Background | Border | Notes |
|---|---|---|---|---|---|
| **Excellent** (`.s-Excellent`) | `#166534` | `#16843D` | `#EAF6E9` | `#B7DFBC` | Emerald green — healthy |
| **Good** (`.s-Good`, Emerald theme) | `#0F5F68` | `#148791` | `#E6F4F6` | `#B3DDE2` | Distinct teal |
| **Good** (`.s-Good`, Teal theme) | `#075985` | `#0284C7` | `#EFF8FF` | `#BAE6FD` | Distinct sky-blue |
| **Fair** (`.s-Fair` / `.sev-high`) | `#9A4B06` | `#D97706` | `#FFFBEB` | `#FDE68A` | Amber — elevated / stale (>10 s) |
| **Poor** (`.s-Poor` / `.sev-critical`) | `#B91C1C` | `#DC2626` | `#FEF2F2` | `#FECACA` | Red — critical / offline (>30 s) |
| **Unknown / Offline / Unmeasured** (`.s-Unknown`, `.s-Offline`, `.s-Unmeasured`) | `#475569` | `#64748B` | `#F1F5F9` | `#CBD5E1` | Neutral grey fallback |

Destructive actions (e.g., `Roll back` via `button.danger`) use `--danger-bg: #B91C1C`, `--danger-hover: #991B1B`, `--danger-active: #7F1D1D`.

---

## 3. Tier 1 Local Collector Console (`collector/ui.html`)

Tier 1 intentionally uses a **Deep Evergreen Dark** companion palette so operators and judges can distinguish **Tier 1 (Customer Local Environment — Raw Data Stays Here)** from **Tier 2 (Central SaaS — Metadata Only)** at a glance when opened side-by-side:

- **Ground / Surfaces:** `#07241A` ground, `#0F392B` cards (`20px` radius), `#144A37` elevated controls, `#1C5A44` borders.
- **Text & Accents:** `#F0FDF4` primary text, `#9BC4B1` muted text, `#22C55E` connected / redacted markers, `#F59E0B` Tier 1 warning badge & pending payloads, `#F43F5E` / `#FDA4AF` highlighted raw secrets & outage state.

---

## 4. Typography, Geometry & Layout Rules

- **Fonts (offline-safe stacks):**
  - Body / UI (`--font-sans`): `"Inter", "Segoe UI Variable Text", "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, sans-serif`
  - Headings / KPIs (`--font-display`): `"Plus Jakarta Sans", "Segoe UI Variable Display", "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif`
  - Code / Hashes / Pseudonyms (`--font-mono`): `"Cascadia Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace`
- **Tabular Numerals:** `font-variant-numeric: tabular-nums` is enabled globally on `body` so live 1-second metric refreshes do not shift column alignment.
- **Radii:** `--radius-card: 20px`, `--radius-inner: 14px`, `--radius-ctl: 12px`, `--radius-pill: 9999px`.
- **Responsive Breakpoints:**
  - `≤ 1040px`: `.two` / `.two.narrow` stack to 1 column; `.grid4` switches to 2 columns.
  - `≤ 640px`: `.grid4` switches to 1 column; outer padding tightens to `14px`.
- **Visual Restraint:**
  - No CSS gradients, no `backdrop-filter` glassmorphism, no purple accents, and no decorative hover lift (`translateY`) animations on the SaaS dashboard.
  - All primary foreground/background pairs meet **WCAG AA (≥ 4.5:1)** contrast.

---

## 5. Theme Switcher & Charts (`saas/static/app.js`)

- **Theme Switcher:** The header pill (`Emerald` / `Teal`) calls `setTheme('humming' | 'medcity')`, toggling `data-theme="medcity"` on `<html>` and persisting the choice in `localStorage` (`hd-theme`).
- **Canvas Charts (`drawLines`):** Charts read live CSS variables via `cssVar(...)` instead of hardcoding hex values:
  - Primary metric series: `--color-primary` (`#4263A3`)
  - Secondary sparkline (latency): `--status-fair-dot` (`#D97706`)
  - Threshold guides: `--color-success`, `--status-fair-dot`, `--status-poor-dot`
  - Alert window shading: `--status-poor-dot` at `0.14` alpha

---

## 6. Contributor Rules (Do Not Break)

1. **Always use CSS variables** from `:root` in `saas/static/style.css` — never hardcode ad-hoc hex colors in HTML or JS.
2. **Respect strict CSP (`common/web.py`):**
   - Never add inline `onclick="..."` handlers or inline `<script>` tags. Register interactive actions in the `CALLS` map in `saas/static/app.js` / `collector/ui.js` and bind via `data-call="..."`.
   - Never add external font, icon, or CSS CDN links (`default-src 'self'`).
3. **Preserve DOM IDs & API contracts:** Keep all existing element IDs (`#summary`, `#incidents`, `#healthmap`, `#alerts`, `#history`, `#collectors`, `#sources`, `#detail`, `#payloads`, `#slo`, `#reliab`, `#thr`, `#audit`, etc.) intact.
4. **Verify before pushing:**
   ```powershell
   node --check saas/static/app.js
   node --check collector/ui.js
   python -m unittest discover -s tests -t tests
   ```
