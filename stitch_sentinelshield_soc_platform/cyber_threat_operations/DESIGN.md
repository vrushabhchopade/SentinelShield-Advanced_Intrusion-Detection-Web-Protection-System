---
name: Cyber Threat Operations
colors:
  surface: '#0f131d'
  surface-dim: '#0f131d'
  surface-bright: '#353944'
  surface-container-lowest: '#0a0e18'
  surface-container-low: '#171b26'
  surface-container: '#1c1f2a'
  surface-container-high: '#262a35'
  surface-container-highest: '#313540'
  on-surface: '#dfe2f1'
  on-surface-variant: '#c2c6d6'
  inverse-surface: '#dfe2f1'
  inverse-on-surface: '#2c303b'
  outline: '#8c909f'
  outline-variant: '#424754'
  surface-tint: '#adc6ff'
  primary: '#adc6ff'
  on-primary: '#002e6a'
  primary-container: '#4d8eff'
  on-primary-container: '#00285d'
  inverse-primary: '#005ac2'
  secondary: '#4edea3'
  on-secondary: '#003824'
  secondary-container: '#00a572'
  on-secondary-container: '#00311f'
  tertiary: '#d0bcff'
  on-tertiary: '#3c0091'
  tertiary-container: '#a078ff'
  on-tertiary-container: '#340080'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#d8e2ff'
  primary-fixed-dim: '#adc6ff'
  on-primary-fixed: '#001a42'
  on-primary-fixed-variant: '#004395'
  secondary-fixed: '#6ffbbe'
  secondary-fixed-dim: '#4edea3'
  on-secondary-fixed: '#002113'
  on-secondary-fixed-variant: '#005236'
  tertiary-fixed: '#e9ddff'
  tertiary-fixed-dim: '#d0bcff'
  on-tertiary-fixed: '#23005c'
  on-tertiary-fixed-variant: '#5516be'
  background: '#0f131d'
  on-background: '#dfe2f1'
  surface-variant: '#313540'
typography:
  display-xl:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 40px
    letterSpacing: -0.02em
  display-xl-mobile:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '700'
    lineHeight: 32px
    letterSpacing: -0.01em
  headline-lg:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  headline-md:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '600'
    lineHeight: 24px
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 18px
  mono-metric:
    fontFamily: JetBrains Mono
    fontSize: 28px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.03em
  mono-data:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 20px
  mono-code:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '400'
    lineHeight: 16px
  label-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.04em
  label-sm:
    fontFamily: JetBrains Mono
    fontSize: 10px
    fontWeight: '600'
    lineHeight: 14px
    letterSpacing: 0.06em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-compact: 0.5rem
  margin: 1.5rem
  margin-mobile: 0.75rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1rem
  space-xl: 1.5rem
  space-2xl: 2rem
---

## Brand & Style

This design system embodies high-stakes operational clarity, precision engineering, and situational awareness tailored for Security Operations Center (SOC) engineers, incident responders, and threat analysts. The interface targets high-stress, data-dense monitoring environments where split-second triage and absolute legibility dictate operational outcomes.

The overarching design aesthetic blends **Technical Minimalism** with **Tactical High-Density Utility**. Rather than relying on purely decorative effects, depth is communicated through distinct structural panels, razor-sharp architectural borders, and deliberate optical contrast. High-frequency telemetry (threat feeds, IP tables, request inspectors) receives maximum spatial economy while critical state escalations pierce the dark visual plane with intense, unambiguous signal colors.

## Colors

The palette is engineered around dark-room SOC ergonomics, reducing eye fatigue during sustained 24/7 observation while maintaining strict WCAG AAA contrast ratios for vital telemetry data.

### Structural Neutrals
- **Canvas Base (`#0B0F19`)**: Deep pitch navy base layer for root applications and terminal backgrounds.
- **Surface Elevation 1 (`#0F172A`)**: Base workspace canvas, grid tracks, and page headers.
- **Surface Elevation 2 (`#162032`)**: Sidebars, metric card containers, and static inspection panels.
- **Surface Elevation 3 (`#1E293B`)**: Interactive data rows, popovers, active tabs, and modals.
- **Border Structural (`#334155`)**: Crisp 1px perimeter outlines, dividers, and table row separators.
- **Border Subtle (`#1E293B`)**: Low-emphasis structural demarcations inside sub-components.

### Text & Glyph Hierarchy
- **Text Primary (`#F8FAFC`)**: Absolute white for high-priority values, threat titles, and active input.
- **Text Secondary (`#94A3B8`)**: Mid-tone slate for supporting copy, column headers, and breadcrumbs.
- **Text Muted (`#64748B`)**: De-emphasized timestamps, inactive toggles, and metadata labels.

### Operational Signal Tokens
- **Primary / Active Action (`#3B82F6`, `#2563EB`)**: Telemetry selections, primary triggers, and focused states.
- **Safe / Resolved / Allowed (`#10B981`, `#059669`)**: Whitelisted packets, healthy microservices, resolved alerts.
- **Warning / Suspicious (`#F59E0B`)**: Anomalous telemetry, behavioral deviations, Medium severity.
- **Critical / Blocked (`#EF4444`, `#DC2626`)**: Zero-day threats, active WAF blocks, Critical severity.
- **Throttled / Rate Limited (`#8B5CF6`)**: DDoS containment, circuit-breaker engagements, and policy rate limits.

## Typography

The typographic hierarchy implements a dual-typeface system configured specifically for dense observability applications. 

- **Primary UI & Headings (`Inter`)**: Utilized for standard navigation, contextual narration, modal layouts, and headers. Inter’s tall x-height and neutral geometry optimize rapid scanning without drawing attention away from raw data.
- **Telemetry & Technical Indicators (`JetBrains Mono`)**: Strict tabular alignment (`tnum`), zero-ambiguity characters (slashed zeros, clear 1/l/I distinctions), and fixed character widths are mandatory for all IP addresses (IPv4/IPv6), CIDR blocks, SHA-256 hashes, timestamps, request payloads, and status badges.

All tabular numbers must enable OpenType tabular figures (`font-variant-numeric: tabular-nums`) across both font families to prevent UI jittering during real-time event updates.

## Layout & Spacing

The layout philosophy operates on an **adaptive density, fluid modular grid**. To optimize monitor screen real estate on large command-and-control displays while supporting mobile incident alerts, layout density dynamically compresses.

- **Desktop (1440px+)**: Multi-pane layout consisting of a 64px collapsed / 240px expanded navigation rail, fluid 12-column content space, and a sticky 420px contextual flyout pane (for threat packet payload analysis).
- **Tablet (768px - 1439px)**: 8-column layout. The threat inspection pane collapses into an overlay drawer.
- **Mobile (< 768px)**: 4-column flow with persistent top-level incident indicators, collapsed table cards, and stacked metric panels.

Spacing adheres to a strict 4px grid. Standard interactive controls and tabular line-heights prefer condensed values (`space-sm` and `space-md`) to ensure critical incident rows display above the fold without forced pagination.

## Elevation & Depth

This design system avoids blurry diffused drop shadows, which introduce muddy visual artifacts on deep dark screens. Depth is created via **Tonal Surface Layering** and **Crisp Luminescent Outlines**.

1. **Level 0 (App Shell)**: `#0B0F19` — flat background.
2. **Level 1 (Card/Grid Panels)**: `#162032` with a uniform 1px solid border (`#334155`). Zero box shadow.
3. **Level 2 (Hovered Cards / Raised Controls)**: `#1E293B` surrounded by an intensified border (`#475569`). A tactical dark-ambient halo (`0 4px 12px rgba(0, 0, 0, 0.45)`) may be used.
4. **Level 3 (Modals / Overlays / Flyout Panes)**: `#0F172A` backed by an active overlay blur (`backdrop-filter: blur(8px)` with `rgba(11, 15, 25, 0.8)` tint) and framed with a crisp border (`#334155`).
5. **Level 4 (Alert Highlight Overlays)**: Injected perimeter rim lights (`box-shadow: inset 0 0 0 1px #EF4444` or `#3B82F6`) designate state prioritization without altering component geometry.

## Shapes

The design system implements a **Soft-Edged Industrial Form Factor** (`roundedness: 1`). Radii are deliberately understated to maintain high component density, align with monospaced terminal grids, and evoke an enterprise-grade hardware appliance.

- **Base Radius (`0.25rem` / 4px)**: Buttons, inputs, table row highlights, severity badges, and code snippets.
- **Medium Radius (`0.5rem` / 8px)**: KPI cards, alert dialog containers, inspector panes, and floating popovers.
- **Pill Radius (`9999px`)**: Reserved exclusively for dynamic status beacons (`LIVE`, `OFFLINE`) to visually segregate operational lifecycle states from static data filters.

## Components

### Buttons
- **Primary**: Solid electric blue (`#2563EB`), white text, 4px corner radius. On hover: `#3B82F6`. Active: `#1D4ED8`. Focus outline: 2px offset ring (`#60A5FA`).
- **Secondary / Ghost**: Transparent fill, 1px border (`#334155`), slate text (`#94A3B8`). On hover: background `#1E293B`, text `#F8FAFC`.
- **Destructive**: Base background `#7F1D1D`, 1px border `#DC2626`, text `#FEF2F2`.

### Threat Severity Badges & Status Pills
- **Threat Badges**: Rendered with `label-sm` monospaced uppercase typography, 4px border radius, and high-contrast background-to-border pairings:
  - *Critical*: `#450A0A` background, `#DC2626` border, `#FCA5A5` text.
  - *High*: `#431407` background, `#EA580C` border, `#FDBA74` text.
  - *Medium*: `#451A03` background, `#D97706` border, `#FCD34D` text.
  - *Low*: `#1E293B` background, `#475569` border, `#94A3B8` text.
  - *Info*: `#172554` background, `#2563EB` border, `#93C5FD` text.
- **Status Pills**: Pill-shaped (`rounded-full`) containing a 6px circular pulsing indicator dot:
  - *LIVE*: Emerald glow (`#10B981` dot with CSS pulse animation).
  - *BLOCKED*: Crimson dot (`#EF4444`).
  - *RATE LIMITED*: Amethyst dot (`#8B5CF6`).

### KPI Metric Cards
- Surface `#162032`, perimeter 1px `#334155`. 
- Structural layout: Upper row contains small muted title (`label-md`) and severity tag; center features tabular figure (`mono-metric`) in `#F8FAFC`; footer hosts comparative differential micro-charts or percentage delta arrows.

### Data Tables & Log Streamers
- Alternating row styling: Default rows use transparent background; zebra or hover rows transition to `#1E293B`.
- Row separation: 1px bottom border (`#1E293B`).
- Cells containing IP addresses, user agents, endpoints, and timestamps strictly utilize `mono-data`.
- Sticky header container: `#0F172A` with strong 1px solid border (`#334155`).

### Request Inspector & Collapsible Drawer
- Split-screen drawer anchored to the right side of the screen (`#0F172A`).
- Segmented JSON/Raw headers viewer with syntax-highlighted monospaced tokens.
- Persistent header ribbon displaying quick mitigation actions (e.g., "Add IP to Blocklist", "Issue Challenge", "Trace Packet").

### Inputs & Filter Bars
- Inputs feature `#0F172A` fill with a `#334155` border. Text in `#F8FAFC`, placeholder in `#64748B`.
- Integrated tokenized filter bar allowing composite queries (e.g., `status:403 ip:192.168.1.1/24`) with quick-dismiss tags.