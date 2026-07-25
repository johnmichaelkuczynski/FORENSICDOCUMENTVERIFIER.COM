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

export interface DocumentMetadata {
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
}

export const insertDocumentSchema = createInsertSchema(documentsTable).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertDocument = z.infer<typeof insertDocumentSchema>;
export type Document = typeof documentsTable.$inferSelect;
