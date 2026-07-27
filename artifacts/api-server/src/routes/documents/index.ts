import path from "path";
import fs from "fs";
import os from "os";
import { Router, type IRouter } from "express";
import multer from "multer";
import { eq, desc, count, sql } from "drizzle-orm";
import { db, documentsTable } from "@workspace/db";
import {
  GetDocumentParams,
  DeleteDocumentParams,
  ReanalyzeDocumentParams,
  ListDocumentsResponseItem,
  ListDocumentsResponse,
  GetDocumentStatsResponse,
  GetDocumentResponse,
  AnalyzeDocumentResponse,
  ReanalyzeDocumentResponse,
} from "@workspace/api-zod";
import { analyzeDocument, chatWithDocument } from "../../lib/forensic-analysis";
import { logger } from "../../lib/logger";

const router: IRouter = Router();

// Permanent upload directory — files are kept so re-analysis and hashing always work
const UPLOAD_DIR = path.join(process.cwd(), "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const unique = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    cb(null, `${unique}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_")}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB
  fileFilter(_req, file, cb) {
    if (file.mimetype === "application/pdf" || file.originalname.toLowerCase().endsWith(".pdf")) {
      cb(null, true);
    } else {
      cb(new Error("Only PDF files are accepted"));
    }
  },
});

// Helper: map DB row to API shape
function toApiShape(doc: typeof documentsTable.$inferSelect) {
  return {
    id: doc.id,
    status: doc.status as "pending" | "analyzing" | "complete" | "error",
    fileName: doc.fileName,
    fileSize: doc.fileSize,
    claimedIdentity: doc.claimedIdentity,
    verdict: (doc.verdict ?? null) as "authentic" | "suspicious" | "likely_forged" | "inconclusive" | null,
    confidenceScore: doc.confidenceScore ?? null,
    summary: doc.summary ?? null,
    findings: (doc.findings ?? []) as any[],
    metadata: (doc.metadata ?? null) as any,
    errorMessage: doc.errorMessage ?? null,
    createdAt: doc.createdAt.toISOString(),
    updatedAt: doc.updatedAt.toISOString(),
  };
}

// Background analysis runner — non-blocking
async function runAnalysis(docId: number, filePath: string, fileName: string, fileSize: number, claimedIdentity: string) {
  try {
    await db.update(documentsTable).set({ status: "analyzing" }).where(eq(documentsTable.id, docId));

    const result = await analyzeDocument(filePath, fileName, fileSize, claimedIdentity);

    await db
      .update(documentsTable)
      .set({
        status: "complete",
        verdict: result.verdict,
        confidenceScore: result.confidenceScore,
        summary: result.summary,
        findings: result.findings,
        metadata: result.metadata,
      })
      .where(eq(documentsTable.id, docId));

    logger.info({ docId, verdict: result.verdict }, "Analysis complete");
  } catch (err) {
    logger.error({ err, docId }, "Analysis failed");
    await db
      .update(documentsTable)
      .set({ status: "error", errorMessage: String(err) })
      .where(eq(documentsTable.id, docId));
  }
  // Files are kept permanently for re-analysis and SHA-256 re-computation
}

// GET /documents
router.get("/documents", async (_req, res): Promise<void> => {
  const docs = await db
    .select()
    .from(documentsTable)
    .orderBy(desc(documentsTable.createdAt));
  res.json(ListDocumentsResponse.parse(docs.map(toApiShape)));
});

// GET /documents/stats
router.get("/documents/stats", async (_req, res): Promise<void> => {
  const [totalRow] = await db.select({ total: count() }).from(documentsTable);
  const [recentRow] = await db
    .select({ recent: count() })
    .from(documentsTable)
    .where(sql`${documentsTable.createdAt} > now() - interval '7 days'`);

  const verdictRows = await db
    .select({ verdict: documentsTable.verdict, cnt: count() })
    .from(documentsTable)
    .groupBy(documentsTable.verdict);

  const statusRows = await db
    .select({ status: documentsTable.status, cnt: count() })
    .from(documentsTable)
    .groupBy(documentsTable.status);

  const byVerdict: Record<string, number> = { authentic: 0, suspicious: 0, likely_forged: 0, inconclusive: 0 };
  for (const row of verdictRows) {
    if (row.verdict && byVerdict[row.verdict] !== undefined) {
      byVerdict[row.verdict] = Number(row.cnt);
    }
  }

  const byStatus: Record<string, number> = { pending: 0, analyzing: 0, complete: 0, error: 0 };
  for (const row of statusRows) {
    if (row.status && byStatus[row.status] !== undefined) {
      byStatus[row.status] = Number(row.cnt);
    }
  }

  res.json(
    GetDocumentStatsResponse.parse({
      total: Number(totalRow?.total ?? 0),
      byVerdict,
      byStatus,
      recentCount: Number(recentRow?.recent ?? 0),
    })
  );
});

// POST /documents/analyze
router.post("/documents/analyze", upload.single("file"), async (req, res): Promise<void> => {
  if (!req.file) {
    res.status(400).json({ error: "A PDF file is required" });
    return;
  }

  const claimedIdentity = typeof req.body?.claimedIdentity === "string" ? req.body.claimedIdentity.trim() : "";

  const [doc] = await db
    .insert(documentsTable)
    .values({
      status: "pending",
      fileName: req.file.originalname,
      fileSize: req.file.size,
      claimedIdentity,
      filePath: req.file.path,
    })
    .returning();

  // Fire and forget — client polls for completion
  setImmediate(() => {
    runAnalysis(doc.id, req.file!.path, req.file!.originalname, req.file!.size, claimedIdentity).catch((err) => {
      logger.error({ err }, "Unhandled error in background analysis");
    });
  });

  res.status(202).json(AnalyzeDocumentResponse.parse(toApiShape(doc)));
});

// GET /documents/:id
router.get("/documents/:id", async (req, res): Promise<void> => {
  const params = GetDocumentParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const [doc] = await db
    .select()
    .from(documentsTable)
    .where(eq(documentsTable.id, params.data.id));

  if (!doc) {
    res.status(404).json({ error: "Document not found" });
    return;
  }

  res.json(GetDocumentResponse.parse(toApiShape(doc)));
});

// DELETE /documents/:id
router.delete("/documents/:id", async (req, res): Promise<void> => {
  const params = DeleteDocumentParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const [doc] = await db
    .delete(documentsTable)
    .where(eq(documentsTable.id, params.data.id))
    .returning();

  if (!doc) {
    res.status(404).json({ error: "Document not found" });
    return;
  }

  res.sendStatus(204);
});

// POST /documents/:id/reanalyze
router.post("/documents/:id/reanalyze", async (req, res): Promise<void> => {
  const params = ReanalyzeDocumentParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const [doc] = await db
    .select()
    .from(documentsTable)
    .where(eq(documentsTable.id, params.data.id));

  if (!doc) {
    res.status(404).json({ error: "Document not found" });
    return;
  }

  if (doc.status === "analyzing") {
    res.status(409).json({ error: "Analysis is already in progress" });
    return;
  }

  // We need a fresh file — if the file was already cleaned up, indicate that
  if (!doc.filePath || !fs.existsSync(doc.filePath)) {
    res.status(422).json({
      error: "Original file is no longer available for re-analysis. Please re-upload the document.",
    });
    return;
  }

  await db
    .update(documentsTable)
    .set({ status: "pending", verdict: null, confidenceScore: null, summary: null, findings: [], errorMessage: null })
    .where(eq(documentsTable.id, doc.id));

  setImmediate(() => {
    runAnalysis(doc.id, doc.filePath!, doc.fileName, doc.fileSize, doc.claimedIdentity).catch((err) => {
      logger.error({ err }, "Unhandled error in re-analysis");
    });
  });

  const [updated] = await db.select().from(documentsTable).where(eq(documentsTable.id, doc.id));
  res.status(202).json(ReanalyzeDocumentResponse.parse(toApiShape(updated)));
});

// POST /documents/:id/chat
router.post("/documents/:id/chat", async (req, res): Promise<void> => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid document id" }); return; }

  const question = typeof req.body?.question === "string" ? req.body.question.trim() : "";
  if (!question) { res.status(400).json({ error: "question is required" }); return; }

  const history: { role: "user" | "assistant"; content: string }[] =
    Array.isArray(req.body?.history) ? req.body.history.slice(-10) : [];

  const [doc] = await db.select().from(documentsTable).where(eq(documentsTable.id, id));
  if (!doc) { res.status(404).json({ error: "Document not found" }); return; }
  if (doc.status !== "complete") { res.status(422).json({ error: "Analysis must be complete before querying" }); return; }

  try {
    const answer = await chatWithDocument(
      doc.filePath ?? "",
      (doc.metadata ?? {}) as any,
      doc.claimedIdentity,
      question,
      history,
    );
    res.json({ answer });
  } catch (err) {
    logger.error({ err, id }, "Chat query failed");
    res.status(500).json({ error: "Failed to generate response" });
  }
});

export default router;
