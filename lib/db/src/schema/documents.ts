import { pgTable, serial, text, integer, jsonb, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const documentsTable = pgTable("documents", {
  id: serial("id").primaryKey(),
  status: text("status").notNull().default("pending"), // pending | analyzing | complete | error
  fileName: text("file_name").notNull(),
  fileSize: integer("file_size").notNull(),
  claimedIdentity: text("claimed_identity").notNull(),
  verdict: text("verdict"), // authentic | suspicious | likely_forged | inconclusive
  confidenceScore: integer("confidence_score"), // 0-100
  summary: text("summary"),
  findings: jsonb("findings").default([]).$type<Finding[]>(),
  metadata: jsonb("metadata").$type<DocumentMetadata | null>(),
  filePath: text("file_path"),
  errorMessage: text("error_message"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export interface Finding {
  category: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  description: string;
}

export interface FontInfo {
  name: string;
  type: string | null;
  encoding: string | null;
  embedded: boolean;
  subset: boolean;
}

export interface XmpHistoryEntry {
  action: string | null;
  instanceId: string | null;
  when: string | null;
  softwareAgent: string | null;
  changed: string | null;
}

export interface EmbeddedUrl {
  url: string;
  context: string | null;
}

export interface ProvenanceEvent {
  timestamp: string | null;   // ISO-ish datetime
  event: string;              // "created" | "saved" | "converted" | "printed" | "modified" | "exported"
  agent: string | null;       // Software that performed the action
  detail: string | null;      // Human-readable extra context
}

export interface DocumentTimelineSignal {
  source: string;
  date: string;                // ISO 8601 — at minimum YYYY-MM-DD
  type: "stated_creation" | "stated_modification" | "not_before" | "not_after";
  confidence: "high" | "medium" | "low";
  detail: string;              // Human-readable explanation of what this signal means
}

export interface DocumentTimeline {
  statedCreationDate: string | null;   // From PDF/XMP metadata
  statedModDate: string | null;        // From PDF/XMP metadata
  earliestPossibleDate: string | null; // Lowest "not before" bound from software version
  latestPossibleDate: string;          // Upload timestamp — hard upper bound
  dominantDate: string | null;         // Best single date answer
  confidence: "exact" | "bounded" | "unknown";
  summary: string;                     // Plain-English sentence ready for display or chat
  signals: DocumentTimelineSignal[];
}

export interface MergedComponent {
  index: number;
  title: string | null;
  author: string | null;
  creator: string | null;
  producer: string | null;
  creationDate: string | null;
  modificationDate: string | null;
  documentId: string | null;
  instanceId: string | null;
  detectionMethod: string;    // "xmpIngredients" | "infoDictionary"
}

export interface DocumentMetadata {
  rawText?: string | null;
  // ── File integrity ────────────────────────────────────────────────────────
  sha256: string | null;

  // ── Basic Info Dictionary ──────────────────────────────────────────────────
  author: string | null;
  creator: string | null;
  producer: string | null;
  creationDate: string | null;
  modificationDate: string | null;
  pageCount: number | null;
  fileSize: number;
  pdfVersion: string | null;

  // ── ExifTool — XMP core ───────────────────────────────────────────────────
  xmpToolkit: string | null;
  xmpCreatorTool: string | null;      // e.g. "Microsoft Word 16.0.14026.20298"
  xmpCreateDate: string | null;
  xmpModifyDate: string | null;
  xmpMetadataDate: string | null;
  documentId: string | null;          // xmpMM:DocumentID — persists across saves
  instanceId: string | null;          // xmpMM:InstanceID — changes on every save
  originalDocumentId: string | null;  // xmpMM:OriginalDocumentID

  // ── ExifTool — Content ────────────────────────────────────────────────────
  title: string | null;
  subject: string | null;
  description: string | null;
  keywords: string | null;
  rights: string | null;
  language: string | null;

  // ── ExifTool — Document flags ─────────────────────────────────────────────
  linearized: boolean | null;         // Prepared for fast web delivery
  tagged: boolean | null;             // Tagged PDF (accessibility)
  pageLayout: string | null;
  pageMode: string | null;
  pageSize: string | null;
  pdfSecurity: string | null;

  // ── Encryption ────────────────────────────────────────────────────────────
  encrypted: boolean;
  encryptionMethod: string | null;
  encryptionKeyLength: number | null;
  userAccess: string | null;          // Human-readable permission set

  // ── Digital signatures ────────────────────────────────────────────────────
  hasDigitalSignature: boolean;
  signatureCount: number;

  // ── Raw binary structural analysis ───────────────────────────────────────
  incrementalSaveCount: number;       // Times doc was saved after initial creation
  hasJavaScript: boolean;
  hasEmbeddedFiles: boolean;
  hasLaunchActions: boolean;
  hasAcroForm: boolean;
  hasObjectStreams: boolean;          // /ObjStm — compressed object streams
  hasXRefStreams: boolean;            // /XRef — modern cross-reference format
  hasExternalLinks: boolean;
  embeddedUrls: EmbeddedUrl[];
  rawObjectCount: number | null;

  // ── Font analysis ─────────────────────────────────────────────────────────
  fonts: FontInfo[];
  fontCount: number;
  embeddedFontCount: number;
  suspectFonts: string[];             // Fonts inconsistent with claimed origin

  // ── XMP edit history ─────────────────────────────────────────────────────
  xmpHistory: XmpHistoryEntry[];
  totalEditSessions: number;

  // ── All raw ExifTool output ───────────────────────────────────────────────
  exiftoolRaw: Record<string, unknown> | null;

  // ── Document History / Provenance ─────────────────────────────────────────
  sourceUrl: string | null;           // URL the document was downloaded from, if detected
  originType: string | null;          // "web-download" | "print-to-pdf" | "native-app" | "cloud-service" | "converted" | "scanned" | "unknown"
  originApp: string | null;           // e.g. "Google Chrome", "Microsoft Word"
  softwareChain: string[];            // Every piece of software that touched the doc, in order
  provenanceTimeline: ProvenanceEvent[];

  // ── Merged document analysis ──────────────────────────────────────────────
  isMergedDocument: boolean;
  mergedComponents: MergedComponent[];
  derivedFromId: string | null;       // xmpMM:DerivedFrom DocumentID

  // ── Creation timeline (synthesized from all date signals) ─────────────────
  documentTimeline?: DocumentTimeline | null;
}

export const insertDocumentSchema = createInsertSchema(documentsTable).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertDocument = z.infer<typeof insertDocumentSchema>;
export type Document = typeof documentsTable.$inferSelect;
