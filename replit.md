# Forensic Document Examiner

A professional-grade web app for detecting forged or fabricated documents submitted as legal evidence. Upload a PDF, describe what it claims to be, and get an AI-powered forensic verdict.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 8080)
- `pnpm --filter @workspace/forensic-examiner run dev` — run the frontend (port 20398)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string
- Required env: `AI_INTEGRATIONS_OPENAI_BASE_URL`, `AI_INTEGRATIONS_OPENAI_API_KEY` — auto-set by Replit AI Integrations

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- AI: OpenAI via Replit AI Integrations (`gpt-5.6-terra`)
- PDF parsing: `pdf-parse` v1 (Node.js compatible)
- File uploads: `multer`
- Frontend: React + Vite, `@tanstack/react-query`, `wouter`
- Build: esbuild (CJS bundle)

## Where things live

- `lib/api-spec/openapi.yaml` — OpenAPI spec (source of truth)
- `lib/db/src/schema/documents.ts` — Document analysis DB table
- `artifacts/api-server/src/lib/forensic-analysis.ts` — Core analysis logic (heuristics + AI)
- `artifacts/api-server/src/routes/documents/` — Document API routes
- `artifacts/forensic-examiner/src/` — React frontend

## Architecture decisions

- File uploads go via native `multer` middleware; generated Orval hooks can't handle multipart so the frontend uses raw `fetch + FormData`
- Analysis runs in the background (`setImmediate`) after the 202 response; the frontend polls every 2 seconds until `status === "complete"`
- Heuristic rules run first (software fingerprints, timestamp conflicts, template text detection), then AI analysis augments with additional findings
- `pdf-parse` v1 used (not v2) — v2 bundles pdfjs-dist which requires `DOMMatrix` (a browser API) and crashes in Node.js
- Temp files are cleaned up after analysis completes or fails

## Product

- **Upload page** (`/`): Drag-and-drop PDF + description of what the document claims to be
- **Results page** (`/results/:id`): Verdict (AUTHENTIC / SUSPICIOUS / LIKELY FORGED / INCONCLUSIVE), confidence score, AI-written summary, categorized findings with severity, raw PDF metadata
- **History page** (`/history`): All past analyses with stats

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._

## Gotchas

- Always use `pdf-parse@1` (not v2) — v2 breaks in Node.js due to pdfjs-dist DOMMatrix dependency
- After any OpenAPI spec change: `pnpm --filter @workspace/api-spec run codegen`, then `pnpm run typecheck:libs`
- Multer file uploads are stored in `os.tmpdir()` and cleaned up post-analysis
- The `lib/integrations-openai-ai-react` package is installed but not referenced in the root tsconfig (not needed for this app — no voice features)

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
