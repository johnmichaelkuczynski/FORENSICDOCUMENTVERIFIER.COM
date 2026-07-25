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
  filePath: text("file_path"), // server-side storage path
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

export interface DocumentMetadata {
  author: string | null;
  creator: string | null;
  producer: string | null;
  creationDate: string | null;
  modificationDate: string | null;
  pageCount: number | null;
  fileSize: number;
  encrypted: boolean;
  hasDigitalSignature: boolean;
  pdfVersion: string | null;
}

export const insertDocumentSchema = createInsertSchema(documentsTable).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertDocument = z.infer<typeof insertDocumentSchema>;
export type Document = typeof documentsTable.$inferSelect;
