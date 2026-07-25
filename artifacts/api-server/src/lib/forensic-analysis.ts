import fs from "fs";
import os from "os";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import pdfParse from "pdf-parse";
import { openai } from "@workspace/integrations-openai-ai-server";
import type { DocumentMetadata, Finding, FontInfo, XmpHistoryEntry, EmbeddedUrl } from "@workspace/db";
import { logger } from "./logger";

const execFileAsync = promisify(execFile);

export interface AnalysisResult {
  verdict: "authentic" | "suspicious" | "likely_forged" | "inconclusive";
  confidenceScore: number;
  summary: string;
  findings: Finding[];
  metadata: DocumentMetadata;
}

// ─── ExifTool layer ─────────────────────────────────────────────────────────

async function runExiftool(filePath: string): Promise<Record<string, unknown>> {
  try {
    const { stdout } = await execFileAsync("exiftool", [
      "-j",        // JSON output
      "-a",        // Allow duplicate tags
      "-u",        // Extract unknown tags
      "-G1",       // Show group name
      "-l",        // Long format (value + description)
      "-n",        // Numeric values (don't convert)
      filePath,
    ], { timeout: 30_000, maxBuffer: 10 * 1024 * 1024 });

    const parsed = JSON.parse(stdout);
    return (Array.isArray(parsed) ? parsed[0] : parsed) as Record<string, unknown>;
  } catch (err) {
    logger.warn({ err }, "ExifTool extraction failed");
    return {};
  }
}

function exifVal(raw: Record<string, unknown>, ...keys: string[]): string | null {
  for (const k of keys) {
    // ExifTool -l wraps values as { val, desc } — try both
    const v = raw[k];
    if (v == null) continue;
    if (typeof v === "object" && v !== null && "val" in v) {
      const val = (v as { val: unknown }).val;
      if (val != null && String(val).trim()) return String(val).trim();
    }
    const s = String(v).trim();
    if (s && s !== "0" || typeof v === "number") return s;
  }
  return null;
}

function exifBool(raw: Record<string, unknown>, ...keys: string[]): boolean | null {
  for (const k of keys) {
    const v = raw[k];
    if (v == null) continue;
    if (typeof v === "object" && v !== null && "val" in v) {
      const val = (v as { val: unknown }).val;
      if (val === 1 || val === "Yes" || val === true) return true;
      if (val === 0 || val === "No" || val === false) return false;
    }
    if (v === 1 || v === "Yes" || v === true) return true;
    if (v === 0 || v === "No" || v === false) return false;
  }
  return null;
}

function parseXmpHistory(raw: Record<string, unknown>): XmpHistoryEntry[] {
  // ExifTool serialises XMP history as numbered keys like
  // "XMP-xmpMM:History[1] Action", "XMP-xmpMM:History[1] When", etc.
  const entries: Record<number, Partial<XmpHistoryEntry>> = {};
  for (const [k, v] of Object.entries(raw)) {
    const m = k.match(/History\[(\d+)\]\s+(.+)/i);
    if (!m) continue;
    const idx = parseInt(m[1]);
    const field = m[2].toLowerCase().trim();
    if (!entries[idx]) entries[idx] = {};
    const str = v == null ? null : String(v).trim() || null;
    if (field === "action")        entries[idx].action = str;
    if (field === "instanceid")    entries[idx].instanceId = str;
    if (field === "when")          entries[idx].when = str;
    if (field === "softwareagent") entries[idx].softwareAgent = str;
    if (field === "changed")       entries[idx].changed = str;
  }
  return Object.values(entries)
    .filter((e) => e.action || e.when || e.softwareAgent)
    .map((e) => ({
      action:        e.action        ?? null,
      instanceId:    e.instanceId    ?? null,
      when:          e.when          ?? null,
      softwareAgent: e.softwareAgent ?? null,
      changed:       e.changed       ?? null,
    }));
}

// ─── Raw binary layer ────────────────────────────────────────────────────────

interface BinaryAnalysis {
  incrementalSaveCount: number;
  hasJavaScript: boolean;
  hasEmbeddedFiles: boolean;
  hasLaunchActions: boolean;
  hasAcroForm: boolean;
  hasObjectStreams: boolean;
  hasXRefStreams: boolean;
  hasDigitalSignature: boolean;
  signatureCount: number;
  encrypted: boolean;
  rawObjectCount: number | null;
  fonts: FontInfo[];
  embeddedUrls: EmbeddedUrl[];
}

function analyzeBinary(buf: Buffer): BinaryAnalysis {
  const str = buf.toString("binary");

  // Count %%EOF — each one marks a PDF body section; >1 means incremental saves
  const eofMatches = str.match(/%%EOF/g);
  const eofCount = eofMatches ? eofMatches.length : 1;

  // Detect structural features via marker scanning
  const has = (pattern: string | RegExp) =>
    typeof pattern === "string" ? str.includes(pattern) : pattern.test(str);

  const hasSig = has("/Sig ") || has("/DocTimeStamp") || has("/Type /Sig");
  const sigCount = (str.match(/\/Type\s*\/Sig\b/g) ?? []).length;

  // Count xref entries for approximate object count
  const xrefEntryCount = (str.match(/\d{10} \d{5} [fn]/g) ?? []).length;

  // Font extraction — scan for /BaseFont entries
  const fonts: FontInfo[] = [];
  const fontSeen = new Set<string>();
  const fontRe = /\/BaseFont\s*\/([^\s/\[\]()<>{}]+)/g;
  const fontTypeRe = /\/Subtype\s*\/(Type[0123]|TrueType|OpenType|CIDFontType[02]|MMType1|Type1C)/g;
  const encodingRe = /\/Encoding\s*\/([^\s/\[\]()<>{}]+)/g;

  let fm: RegExpExecArray | null;
  while ((fm = fontRe.exec(str)) !== null) {
    const raw = fm[1];
    if (!raw || fontSeen.has(raw)) continue;
    fontSeen.add(raw);

    const isSubset = /^[A-Z]{6}\+/.test(raw);
    const cleanName = isSubset ? raw.slice(7) : raw;

    // Look for type tag near this match (within 800 chars before)
    const nearby = str.slice(Math.max(0, fm.index - 800), fm.index + 200);
    let type: string | null = null;
    const tm = nearby.match(/\/Subtype\s*\/(Type[0123]|TrueType|OpenType|CIDFontType[02]|MMType1|Type1C)/);
    if (tm) type = tm[1];

    const em = nearby.match(/\/Encoding\s*\/([^\s/\[\]()<>{}]+)/);
    const encoding = em ? em[1] : null;

    const isEmbedded = nearby.includes("/FontFile") || nearby.includes("/FontFile2") || nearby.includes("/FontFile3");

    fonts.push({ name: cleanName, type, encoding, embedded: isEmbedded, subset: isSubset });
  }

  // URL extraction
  const embeddedUrls: EmbeddedUrl[] = [];
  const urlRe = /\/URI\s*\(([^)]+)\)/g;
  let um: RegExpExecArray | null;
  while ((um = urlRe.exec(str)) !== null) {
    const url = um[1].trim();
    if (url && !embeddedUrls.some((u) => u.url === url)) {
      embeddedUrls.push({ url, context: null });
    }
  }

  return {
    incrementalSaveCount: Math.max(0, eofCount - 1),
    hasJavaScript: has("/JavaScript") || has("/JS "),
    hasEmbeddedFiles: has("/EmbeddedFile"),
    hasLaunchActions: has("/Launch"),
    hasAcroForm: has("/AcroForm"),
    hasObjectStreams: has("/ObjStm"),
    hasXRefStreams: has("/Type /XRef") || has("/Type/XRef"),
    hasDigitalSignature: hasSig,
    signatureCount: sigCount,
    encrypted: has("/Encrypt"),
    rawObjectCount: xrefEntryCount > 0 ? xrefEntryCount : null,
    fonts: fonts.slice(0, 100),  // cap to 100 fonts
    embeddedUrls: embeddedUrls.slice(0, 50),
  };
}

// ─── Main metadata extractor ─────────────────────────────────────────────────

function normalizeDate(raw: unknown): string | null {
  if (!raw || typeof raw !== "string") return null;
  const m = raw.match(/^D:(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?/);
  if (m) {
    const [, yr, mo, dy, hh, mm, ss] = m;
    if (hh) return `${yr}-${mo}-${dy} ${hh}:${mm ?? "00"}:${ss ?? "00"}`;
    return `${yr}-${mo}-${dy}`;
  }
  // ISO-ish
  if (/^\d{4}-\d{2}-\d{2}/.test(raw)) return raw.slice(0, 19);
  return raw.slice(0, 50);
}

// Permissions bitmask → human-readable list
function decodeUserAccess(raw: Record<string, unknown>): string | null {
  const val = exifVal(raw,
    "PDF:UserAccess", "PDF-PDF:UserAccess",
    "XMP-pdf:UserAccess", "System:UserAccess"
  );
  return val;
}

export async function extractPdfMetadata(
  buf: Buffer,
  filePath: string,
  fileSize: number
): Promise<{ metadata: DocumentMetadata; rawText: string }> {
  // Run all three extractors in parallel
  const [exifRaw, binary, pdfInfo] = await Promise.all([
    runExiftool(filePath),
    Promise.resolve(analyzeBinary(buf)),
    pdfParse(buf).catch((err) => {
      logger.warn({ err }, "pdf-parse failed; continuing");
      return null;
    }),
  ]);

  const info = (pdfInfo?.info ?? {}) as Record<string, unknown>;
  const rawText = pdfInfo?.text ?? "";

  // XMP history
  const xmpHistory = parseXmpHistory(exifRaw);

  // Suspect fonts for institutional documents
  const suspectFontNames = [
    "comic", "impact", "papyrus", "brush", "handwriting", "crayon",
    "marker", "chalkboard", "kidprint", "schoolbook",
  ];
  const suspectFonts = binary.fonts
    .filter((f) => suspectFontNames.some((s) => f.name.toLowerCase().includes(s)))
    .map((f) => f.name);

  const metadata: DocumentMetadata = {
    // Basic Info dictionary
    author:           exifVal(exifRaw, "PDF:Author", "XMP-dc:Creator") ?? (info["Author"] as string | null) ?? null,
    creator:          exifVal(exifRaw, "PDF:Creator", "XMP-xmp:CreatorTool") ?? (info["Creator"] as string | null) ?? null,
    producer:         exifVal(exifRaw, "PDF:Producer") ?? (info["Producer"] as string | null) ?? null,
    creationDate:     normalizeDate(exifVal(exifRaw, "PDF:CreateDate", "XMP-xmp:CreateDate") ?? info["CreationDate"] as string),
    modificationDate: normalizeDate(exifVal(exifRaw, "PDF:ModifyDate", "XMP-xmp:ModifyDate") ?? info["ModDate"] as string),
    pageCount:        pdfInfo?.numpages ?? null,
    fileSize,
    pdfVersion:       exifVal(exifRaw, "PDF:PDFVersion") ?? pdfInfo?.version ?? null,

    // XMP core
    xmpToolkit:          exifVal(exifRaw, "XMP-x:XMPToolkit", "XMP:XMPToolkit") ?? null,
    xmpCreatorTool:      exifVal(exifRaw, "XMP-xmp:CreatorTool", "XMP:CreatorTool") ?? null,
    xmpCreateDate:       normalizeDate(exifVal(exifRaw, "XMP-xmp:CreateDate", "XMP:CreateDate")),
    xmpModifyDate:       normalizeDate(exifVal(exifRaw, "XMP-xmp:ModifyDate", "XMP:ModifyDate")),
    xmpMetadataDate:     normalizeDate(exifVal(exifRaw, "XMP-xmp:MetadataDate", "XMP:MetadataDate")),
    documentId:          exifVal(exifRaw, "XMP-xmpMM:DocumentID", "XMP:DocumentID") ?? null,
    instanceId:          exifVal(exifRaw, "XMP-xmpMM:InstanceID", "XMP:InstanceID") ?? null,
    originalDocumentId:  exifVal(exifRaw, "XMP-xmpMM:OriginalDocumentID", "XMP:OriginalDocumentID") ?? null,

    // Content
    title:       exifVal(exifRaw, "PDF:Title", "XMP-dc:Title") ?? (info["Title"] as string | null) ?? null,
    subject:     exifVal(exifRaw, "PDF:Subject", "XMP-dc:Subject") ?? (info["Subject"] as string | null) ?? null,
    description: exifVal(exifRaw, "XMP-dc:Description") ?? null,
    keywords:    exifVal(exifRaw, "PDF:Keywords", "XMP-dc:Subject") ?? (info["Keywords"] as string | null) ?? null,
    rights:      exifVal(exifRaw, "XMP-dc:Rights", "XMP-xmpRights:WebStatement") ?? null,
    language:    exifVal(exifRaw, "XMP-dc:Language", "PDF:Language") ?? null,

    // Document flags
    linearized: exifBool(exifRaw, "PDF:Linearized"),
    tagged:     exifBool(exifRaw, "PDF:Tagged"),
    pageLayout: exifVal(exifRaw, "PDF:PageLayout") ?? null,
    pageMode:   exifVal(exifRaw, "PDF:PageMode") ?? null,
    pageSize:   exifVal(exifRaw, "PDF:PageSize", "Composite:ImageSize") ?? null,
    pdfSecurity: exifVal(exifRaw, "PDF:PDFSecurity") ?? null,

    // Encryption
    encrypted:            binary.encrypted,
    encryptionMethod:     exifVal(exifRaw, "PDF:Encryption", "PDF:EncryptionType") ?? null,
    encryptionKeyLength:  null,
    userAccess:           decodeUserAccess(exifRaw),

    // Digital signatures
    hasDigitalSignature: binary.hasDigitalSignature,
    signatureCount:      binary.signatureCount,

    // Binary structural
    incrementalSaveCount: binary.incrementalSaveCount,
    hasJavaScript:        binary.hasJavaScript,
    hasEmbeddedFiles:     binary.hasEmbeddedFiles,
    hasLaunchActions:     binary.hasLaunchActions,
    hasAcroForm:          binary.hasAcroForm,
    hasObjectStreams:      binary.hasObjectStreams,
    hasXRefStreams:        binary.hasXRefStreams,
    hasExternalLinks:     binary.embeddedUrls.length > 0,
    embeddedUrls:         binary.embeddedUrls,
    rawObjectCount:       binary.rawObjectCount,

    // Fonts
    fonts:              binary.fonts,
    fontCount:          binary.fonts.length,
    embeddedFontCount:  binary.fonts.filter((f) => f.embedded).length,
    suspectFonts,

    // XMP history
    xmpHistory,
    totalEditSessions: xmpHistory.length,

    // Raw dump (trimmed to 200 keys max)
    exiftoolRaw: Object.fromEntries(Object.entries(exifRaw).slice(0, 200)),
  };

  return { metadata, rawText };
}

// ─── Heuristic findings ──────────────────────────────────────────────────────

export function buildHeuristicFindings(
  m: DocumentMetadata,
  claimedIdentity: string,
  rawText: string
): Finding[] {
  const findings: Finding[] = [];
  const claimed = claimedIdentity.toLowerCase();

  const isInstitutional = /bank|financial|government|federal|state|court|official|institution|authority|agency|legal|law|police|notary|hospital|insurance/.test(claimed);

  // ── Software fingerprint ─────────────────────────────────────────────────
  const consumerApps = ["microsoft word", "libreoffice", "openoffice", "google docs", "wps office", "pages", "google slides", "keynote"];
  const creatorTool = (m.xmpCreatorTool ?? m.creator ?? "").toLowerCase();
  const producer = (m.producer ?? "").toLowerCase();

  const matchedApp = consumerApps.find((a) => creatorTool.includes(a) || producer.includes(a));
  if (matchedApp && isInstitutional) {
    findings.push({
      category: "software",
      severity: "critical",
      title: `Institutional document created with consumer office software`,
      description: `The XMP CreatorTool metadata field identifies "${m.xmpCreatorTool ?? m.creator ?? m.producer}" as the authoring application. Legitimate documents from banks, courts, government agencies, and regulated institutions are generated by enterprise document management systems (Documentum, OpenText, SharePoint with regulated templates), not personal desktop office suites. This is one of the most reliable forgery indicators.`,
    });
  } else if (matchedApp && !isInstitutional) {
    findings.push({
      category: "software",
      severity: "low",
      title: `Document created with personal office software`,
      description: `Created in "${m.xmpCreatorTool ?? m.creator}", a consumer office application. May be expected depending on the document's claimed source.`,
    });
  }

  // ── Incremental saves ────────────────────────────────────────────────────
  if (m.incrementalSaveCount > 0) {
    const severity = m.incrementalSaveCount >= 3 ? "high" : m.incrementalSaveCount >= 1 ? "medium" : "low";
    findings.push({
      category: "structure",
      severity,
      title: `Document was modified ${m.incrementalSaveCount} time${m.incrementalSaveCount > 1 ? "s" : ""} after initial creation`,
      description: `PDF files record every save as a separate "%%EOF" section appended to the end of the file. This document contains ${m.incrementalSaveCount + 1} body sections, meaning it was saved ${m.incrementalSaveCount} additional time${m.incrementalSaveCount > 1 ? "s" : ""} after its initial creation. This is a significant structural signal when the modification dates conflict with the claimed issuance date, or when the document claims to be a signed original.`,
    });
  }

  // ── Date conflicts ───────────────────────────────────────────────────────
  const yearMatch = claimedIdentity.match(/\b(19|20)\d{2}\b/);
  const metaDate = m.xmpCreateDate ?? m.creationDate;
  if (yearMatch && metaDate) {
    const claimedYear = parseInt(yearMatch[0]);
    const metaYear = parseInt(metaDate.slice(0, 4));
    if (Math.abs(claimedYear - metaYear) > 1) {
      findings.push({
        category: "timestamp",
        severity: "high",
        title: `Claimed date (${claimedYear}) conflicts with embedded creation date (${metaYear})`,
        description: `The submitter claims this document is from ${claimedYear}, but the embedded XMP/PDF metadata shows a creation date of ${metaDate}. A discrepancy of ${Math.abs(claimedYear - metaYear)} year(s) between the claimed issuance date and the document's internal timestamps is a significant inconsistency that cannot be explained by timezone differences or file system copying. If the document were genuinely from ${claimedYear}, the metadata would reflect that — unless the metadata was intentionally altered.`,
      });
    }
  }

  // ── XMP ≠ Info dictionary date conflict ─────────────────────────────────
  if (m.xmpCreateDate && m.creationDate) {
    const xmpYear = m.xmpCreateDate.slice(0, 10);
    const infoYear = m.creationDate.slice(0, 10);
    if (xmpYear !== infoYear) {
      findings.push({
        category: "timestamp",
        severity: "medium",
        title: `XMP creation date differs from PDF Info dictionary creation date`,
        description: `The document contains two independent date records that disagree: the XMP metadata says "${m.xmpCreateDate}" while the PDF Info dictionary says "${m.creationDate}". Legitimate PDF generators write both timestamps in lockstep. This discrepancy suggests the PDF Info dictionary was manually edited after the document was created — a common technique in document tampering.`,
      });
    }
  }

  // ── Personal name as author in institutional document ─────────────────
  if (m.author && isInstitutional) {
    const isPersonalName = /^[A-Z][a-z]+ [A-Z][a-z]+$/.test(m.author.trim());
    if (isPersonalName) {
      findings.push({
        category: "metadata",
        severity: "high",
        title: `Personal name in Author field for an institutional document`,
        description: `The Author metadata field contains "${m.author}", which appears to be an individual's personal name. Official institutional documents authored through enterprise systems carry the organization name or department in the Author field — not a personal name embedded in the PDF properties. This pattern is consistent with a document created on a personal computer by an individual, not produced by an institutional system.`,
      });
    }
  }

  // ── JavaScript ────────────────────────────────────────────────────────────
  if (m.hasJavaScript) {
    findings.push({
      category: "structure",
      severity: "critical",
      title: `Embedded JavaScript detected`,
      description: `The PDF contains one or more JavaScript (/JS) objects embedded in its structure. Legitimate institutional documents — letters, contracts, statements — have no reason to contain executable code. The presence of JavaScript is associated with PDF exploits, phishing, automated form manipulation, and anti-forensic techniques. This document should be treated as potentially malicious and analyzed in an isolated environment.`,
    });
  }

  // ── Launch actions ────────────────────────────────────────────────────────
  if (m.hasLaunchActions) {
    findings.push({
      category: "structure",
      severity: "critical",
      title: `Launch actions detected — potential malicious payload`,
      description: `The document contains a /Launch action that can execute external programs or open other files when the PDF is viewed. This is a well-known attack vector used in targeted phishing campaigns. No legitimate document from a bank or government agency embeds launch actions.`,
    });
  }

  // ── Suspect fonts ─────────────────────────────────────────────────────────
  if (m.suspectFonts.length > 0 && isInstitutional) {
    findings.push({
      category: "content",
      severity: "medium",
      title: `Non-professional fonts detected in institutional document`,
      description: `The following fonts are embedded in the document: ${m.suspectFonts.join(", ")}. These are informal, decorative, or novelty fonts not used in professional institutional documents. Their presence suggests the document was not produced by an organization's official document system.`,
    });
  }

  // ── No fonts at all ───────────────────────────────────────────────────────
  if (m.fontCount === 0 && (rawText?.length ?? 0) > 100) {
    findings.push({
      category: "structure",
      severity: "medium",
      title: `No font metadata despite extractable text`,
      description: `The document contains readable text but no font objects in its structure. This can indicate the document was rendered from a scanner or image (reducing text reliability) or that the font metadata was stripped, which is uncommon in legitimately produced PDFs.`,
    });
  }

  // ── No embedded fonts in institutional document ───────────────────────────
  if (m.fontCount > 0 && m.embeddedFontCount === 0 && isInstitutional) {
    findings.push({
      category: "structure",
      severity: "low",
      title: `No embedded font data`,
      description: `The document uses ${m.fontCount} font(s) but none are embedded in the file. Proper institutional PDFs embed their fonts to ensure accurate rendering. Missing font embedding can cause display differences across systems and is less common in professionally produced documents.`,
    });
  }

  // ── XMP history ───────────────────────────────────────────────────────────
  if (m.xmpHistory.length > 0) {
    const agents = [...new Set(m.xmpHistory.map((h) => h.softwareAgent).filter(Boolean))];
    if (agents.length > 1) {
      findings.push({
        category: "metadata",
        severity: "medium",
        title: `Document edited by multiple different applications`,
        description: `The XMP edit history shows this document was worked on by ${agents.length} different applications: ${agents.slice(0, 5).join("; ")}. If this is claimed to be a freshly issued institutional document, it should have a single creation event from one system — not an edit trail from multiple tools.`,
      });
    }
    const sessionCount = m.xmpHistory.length;
    if (sessionCount > 3) {
      findings.push({
        category: "metadata",
        severity: "low",
        title: `${sessionCount} edit sessions recorded in XMP history`,
        description: `The XMP metadata contains a history of ${sessionCount} documented save/edit operations. Freshly issued institutional documents typically have 1 creation event. Extensive editing history may indicate the document was iteratively modified, which warrants scrutiny when the document is claimed to be an original.`,
      });
    }
  }

  // ── DocumentID vs InstanceID same ────────────────────────────────────────
  if (m.documentId && m.instanceId && m.documentId === m.instanceId) {
    findings.push({
      category: "metadata",
      severity: "info",
      title: `DocumentID and InstanceID are identical`,
      description: `In the XMP metadata model, DocumentID is a permanent GUID assigned at document creation and InstanceID is updated on every save. When they are identical it typically means the document was created and never re-saved through a proper XMP-aware application — consistent with a first-time save, but unusual if the document has been through multiple edits.`,
    });
  }

  // ── Embedded files ────────────────────────────────────────────────────────
  if (m.hasEmbeddedFiles) {
    findings.push({
      category: "structure",
      severity: "medium",
      title: `Embedded file attachments detected`,
      description: `The PDF contains one or more embedded file attachments (/EmbeddedFile objects). While legitimate in some workflows (e.g., XML invoice payloads), embedded files in documents purporting to be simple letters or statements are unusual and should be extracted and examined separately.`,
    });
  }

  // ── External URLs ─────────────────────────────────────────────────────────
  if (m.embeddedUrls.length > 0) {
    const urls = m.embeddedUrls.map((u) => u.url).slice(0, 5).join(", ");
    findings.push({
      category: "structure",
      severity: "low",
      title: `${m.embeddedUrls.length} embedded URL${m.embeddedUrls.length > 1 ? "s" : ""} found`,
      description: `The document contains embedded hyperlinks: ${urls}${m.embeddedUrls.length > 5 ? ` (+${m.embeddedUrls.length - 5} more)` : ""}. These URLs may be used to track document opens, redirect to phishing sites, or load external content. Each URL should be verified against the claimed institution's official domains.`,
    });
  }

  // ── Template text ─────────────────────────────────────────────────────────
  const templatePhrases = ["[insert", "lorem ipsum", "sample text", "placeholder", "your name here", "[your", "[date]", "click here to"];
  const foundTemplate = templatePhrases.filter((p) => rawText.toLowerCase().includes(p));
  if (foundTemplate.length > 0) {
    findings.push({
      category: "content",
      severity: "critical",
      title: `Unresolved template placeholder text detected`,
      description: `The document text contains unfilled template markers: ${foundTemplate.map((p) => `"${p}"`).join(", ")}. This conclusively indicates the document was not finalized — it was submitted directly from a document template with placeholder text left intact, a strong indicator of fabrication.`,
    });
  }

  return findings;
}

// ─── AI analysis layer ───────────────────────────────────────────────────────

async function runAiAnalysis(
  m: DocumentMetadata,
  claimedIdentity: string,
  rawText: string,
  heuristicFindings: Finding[]
): Promise<{ aiFindings: Finding[]; summary: string; verdict: AnalysisResult["verdict"]; confidence: number }> {
  const hSum = heuristicFindings.length > 0
    ? heuristicFindings.map((f) => `[${f.severity.toUpperCase()}] ${f.category}: ${f.title}`).join("\n")
    : "(none)";

  const fontList = m.fonts.slice(0, 20).map((f) =>
    `${f.name} (${f.type ?? "?"}, ${f.embedded ? "embedded" : "not embedded"}${f.subset ? ", subset" : ""})`
  ).join("; ");

  const historyList = m.xmpHistory.slice(0, 5).map((h) =>
    `[${h.when ?? "?"}] ${h.action ?? "?"} by ${h.softwareAgent ?? "?"}`
  ).join("\n");

  const urlList = m.embeddedUrls.slice(0, 10).map((u) => u.url).join(", ");

  const prompt = `You are a forensic document examiner and PDF forensics expert with FBI-level training. Analyze the following evidence for signs of fabrication, forgery, or tampering.

CLAIMED IDENTITY: "${claimedIdentity}"

═══ PDF INFO DICTIONARY ═══
Author: ${m.author ?? "None"}
Creator: ${m.creator ?? "None"}
Producer: ${m.producer ?? "None"}
Creation Date: ${m.creationDate ?? "Unknown"}
Modification Date: ${m.modificationDate ?? "Unknown"}
PDF Version: ${m.pdfVersion ?? "Unknown"}
Page Count: ${m.pageCount ?? "Unknown"}

═══ XMP METADATA ═══
XMP Creator Tool: ${m.xmpCreatorTool ?? "None"}
XMP Toolkit: ${m.xmpToolkit ?? "None"}
XMP Create Date: ${m.xmpCreateDate ?? "None"}
XMP Modify Date: ${m.xmpModifyDate ?? "None"}
XMP Metadata Date: ${m.xmpMetadataDate ?? "None"}
Document GUID: ${m.documentId ?? "None"}
Instance ID: ${m.instanceId ?? "None"}
Original Document ID: ${m.originalDocumentId ?? "None"}
Title: ${m.title ?? "None"}
Subject: ${m.subject ?? "None"}
Keywords: ${m.keywords ?? "None"}
Rights: ${m.rights ?? "None"}
Language: ${m.language ?? "None"}

═══ STRUCTURAL ANALYSIS ═══
Incremental saves after creation: ${m.incrementalSaveCount}
Object streams (/ObjStm): ${m.hasObjectStreams}
XRef streams: ${m.hasXRefStreams}
Linearized (web-optimized): ${m.linearized}
Tagged (accessibility): ${m.tagged}
Page layout: ${m.pageLayout ?? "None"}
Page size: ${m.pageSize ?? "Unknown"}
Approximate object count: ${m.rawObjectCount ?? "Unknown"}

═══ SECURITY FEATURES ═══
Encrypted: ${m.encrypted}
Encryption method: ${m.encryptionMethod ?? "None"}
User access permissions: ${m.userAccess ?? "None"}
Digital signature present: ${m.hasDigitalSignature} (count: ${m.signatureCount})

═══ EMBEDDED CONTENT ═══
JavaScript: ${m.hasJavaScript}
Embedded files: ${m.hasEmbeddedFiles}
Launch actions: ${m.hasLaunchActions}
Form fields (AcroForm): ${m.hasAcroForm}
External links (${m.embeddedUrls.length}): ${urlList || "None"}

═══ FONT ANALYSIS ═══
Total fonts: ${m.fontCount}
Embedded fonts: ${m.embeddedFontCount}
Font list: ${fontList || "None"}
Suspect fonts: ${m.suspectFonts.join(", ") || "None"}

═══ XMP EDIT HISTORY ═══
Total edit sessions: ${m.totalEditSessions}
${historyList || "(No XMP history recorded)"}

═══ RULE-BASED FINDINGS (already detected) ═══
${hSum}

═══ DOCUMENT TEXT (first 2500 chars) ═══
${rawText.slice(0, 2500) || "(No extractable text)"}

ANALYSIS INSTRUCTIONS:
1. Cross-reference all metadata layers for internal consistency.
2. Evaluate whether the XMP creator tool, producer, version, font set, and structural features are consistent with what the claimed institution would plausibly use.
3. Look for anachronisms — software versions that postdate the claimed document date.
4. Assess language, terminology, formatting, and content for consistency with genuine documents of this type.
5. Do NOT repeat findings already listed in the rule-based section. Only add NEW insights.
6. Be specific: name the exact metadata field and value that raises concern.

Return ONLY valid JSON (no markdown fences):
{
  "verdict": "authentic" | "suspicious" | "likely_forged" | "inconclusive",
  "confidence": <0-100>,
  "summary": "<two to three professional sentences suitable for submission to a court or attorney — cite specific metadata values>",
  "additionalFindings": [
    {
      "category": "metadata|software|timestamp|content|language|structure|signature",
      "severity": "info|low|medium|high|critical",
      "title": "<concise title>",
      "description": "<specific, evidence-based description citing exact field names and values>"
    }
  ]
}

Verdict guide: authentic=signals consistently align with claimed origin; suspicious=moderate red flags warranting further investigation; likely_forged=multiple strong independent indicators; inconclusive=insufficient data to determine.`;

  const response = await openai.chat.completions.create({
    model: "gpt-5.6-terra",
    max_completion_tokens: 3000,
    messages: [{ role: "user", content: prompt }],
  });

  const raw = response.choices[0]?.message?.content ?? "{}";
  let parsed: { verdict?: string; confidence?: number; summary?: string; additionalFindings?: Finding[] } = {};
  try {
    const clean = raw.replace(/^```json\s*/i, "").replace(/```\s*$/i, "").trim();
    parsed = JSON.parse(clean);
  } catch {
    logger.warn({ raw }, "Failed to parse AI response JSON");
  }

  const validVerdicts = ["authentic", "suspicious", "likely_forged", "inconclusive"];
  const verdict = validVerdicts.includes(parsed.verdict ?? "")
    ? (parsed.verdict as AnalysisResult["verdict"])
    : "inconclusive";

  return {
    verdict,
    confidence: typeof parsed.confidence === "number" ? Math.min(100, Math.max(0, parsed.confidence)) : 50,
    summary: parsed.summary ?? "Analysis completed. See individual findings for details.",
    aiFindings: Array.isArray(parsed.additionalFindings) ? parsed.additionalFindings : [],
  };
}

// ─── Orchestrator ─────────────────────────────────────────────────────────────

export async function analyzeDocument(
  filePath: string,
  fileName: string,
  fileSize: number,
  claimedIdentity: string
): Promise<AnalysisResult> {
  const buf = fs.readFileSync(filePath);
  const { metadata, rawText } = await extractPdfMetadata(buf, filePath, fileSize);
  const heuristicFindings = buildHeuristicFindings(metadata, claimedIdentity, rawText);
  const { verdict, confidence, summary, aiFindings } = await runAiAnalysis(metadata, claimedIdentity, rawText, heuristicFindings);

  const allFindings: Finding[] = [...heuristicFindings];
  for (const af of aiFindings) {
    const alreadyPresent = allFindings.some((f) => f.title.toLowerCase() === af.title?.toLowerCase());
    if (!alreadyPresent && af.title && af.description) {
      allFindings.push({
        category: af.category ?? "metadata",
        severity: (["info", "low", "medium", "high", "critical"].includes(af.severity)
          ? af.severity : "low") as Finding["severity"],
        title: af.title,
        description: af.description,
      });
    }
  }

  return { verdict, confidenceScore: confidence, summary, findings: allFindings, metadata };
}
