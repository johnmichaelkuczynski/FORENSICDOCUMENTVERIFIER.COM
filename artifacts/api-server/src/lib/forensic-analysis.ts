import fs from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";
import pdfParse from "pdf-parse";
import { openai } from "@workspace/integrations-openai-ai-server";
import type { DocumentMetadata, Finding, FontInfo, XmpHistoryEntry, EmbeddedUrl, ProvenanceEvent, MergedComponent } from "@workspace/db";
import { logger } from "./logger";

const execFileAsync = promisify(execFile);

export interface AnalysisResult {
  verdict: "strong_match" | "partial_match" | "weak_match" | "inconsistent" | "inconclusive";
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

function coerceToString(v: unknown): string | null {
  if (v == null) return null;
  // ExifTool -l wraps values as { val, desc }
  if (typeof v === "object" && !Array.isArray(v) && v !== null && "val" in v) {
    return coerceToString((v as { val: unknown }).val);
  }
  // XMP lang-alt objects e.g. { "lang": "x-default", "_": "..." } or { "x-default": "..." }
  if (typeof v === "object" && !Array.isArray(v) && v !== null) {
    const obj = v as Record<string, unknown>;
    const candidate = obj["_"] ?? obj["x-default"] ?? obj["value"] ?? Object.values(obj)[0];
    if (candidate != null && typeof candidate !== "object") return String(candidate).trim() || null;
    return null;
  }
  // Arrays — take first element
  if (Array.isArray(v)) {
    return v.length > 0 ? coerceToString(v[0]) : null;
  }
  const s = String(v).trim();
  return (s && s !== "0") || typeof v === "number" ? s : null;
}

function exifVal(raw: Record<string, unknown>, ...keys: string[]): string | null {
  for (const k of keys) {
    const result = coerceToString(raw[k]);
    if (result) return result;
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

// ─── Provenance & origin detection ──────────────────────────────────────────

function detectOrigin(
  creator: string,
  producer: string,
  creatorTool: string,
  rawText: string,
): { originType: string; originApp: string } {
  const all = `${creator} ${producer} ${creatorTool}`.toLowerCase();
  const prod = producer.toLowerCase();

  if (/microsoft\s*print\s*to\s*pdf|microsoft:print/.test(all))
    return { originType: "print-to-pdf", originApp: "Microsoft Print to PDF" };
  if (/skia/.test(prod)) {
    if (/edge/.test(all))            return { originType: "web-download",  originApp: "Microsoft Edge" };
    if (/chrome|chromium/.test(all)) return { originType: "web-download",  originApp: "Google Chrome" };
    if (/google\s*docs/.test(all))   return { originType: "cloud-service", originApp: "Google Docs" };
    return { originType: "web-download", originApp: "Chromium-based Browser" };
  }
  if (/mozilla|firefox/.test(all))
    return { originType: "web-download",  originApp: "Mozilla Firefox" };
  if (/safari/.test(all) && !/mozilla/.test(all))
    return { originType: "web-download",  originApp: "Apple Safari" };
  if (/quartz|mac\s*os\s*x|macos/.test(all))
    return { originType: "print-to-pdf",  originApp: "macOS (Print / Preview)" };
  if (/microsoft word/.test(all))
    return { originType: "native-app",    originApp: "Microsoft Word" };
  if (/microsoft excel/.test(all))
    return { originType: "native-app",    originApp: "Microsoft Excel" };
  if (/microsoft powerpoint/.test(all))
    return { originType: "native-app",    originApp: "Microsoft PowerPoint" };
  if (/microsoft office/.test(all))
    return { originType: "native-app",    originApp: "Microsoft Office" };
  if (/libreoffice|openoffice/.test(all))
    return { originType: "native-app",    originApp: "LibreOffice / OpenOffice" };
  if (/acrobat distiller|adobe acrobat/.test(all))
    return { originType: "native-app",    originApp: "Adobe Acrobat" };
  if (/adobe indesign/.test(all))
    return { originType: "native-app",    originApp: "Adobe InDesign" };
  if (/adobe illustrator/.test(all))
    return { originType: "native-app",    originApp: "Adobe Illustrator" };
  if (/canva/.test(all))
    return { originType: "cloud-service", originApp: "Canva" };
  if (/google/.test(all))
    return { originType: "cloud-service", originApp: "Google Workspace" };
  if (/pdfcreator/.test(all))
    return { originType: "print-to-pdf",  originApp: "PDFCreator" };
  if (/cups.pdf/.test(all))
    return { originType: "print-to-pdf",  originApp: "CUPS-PDF (Linux)" };
  if (/ghostscript/.test(all))
    return { originType: "converted",     originApp: "Ghostscript" };
  if (/wkhtmltopdf/.test(all))
    return { originType: "converted",     originApp: "wkhtmltopdf" };
  if (/aspose/.test(all))
    return { originType: "converted",     originApp: "Aspose PDF" };
  if (/itext/.test(all))
    return { originType: "converted",     originApp: "iText PDF Library" };
  if (/reportlab/.test(all))
    return { originType: "converted",     originApp: "ReportLab" };
  if (/fpdf/.test(all))
    return { originType: "converted",     originApp: "FPDF Library" };
  if (!rawText || rawText.trim().length < 30)
    return { originType: "scanned",       originApp: "Scanner / OCR" };
  return { originType: "unknown", originApp: "Unknown" };
}

function buildProvenanceProfile(
  exifRaw: Record<string, unknown>,
  m: DocumentMetadata,
  rawText: string,
): {
  sourceUrl: string | null;
  originType: string;
  originApp: string;
  softwareChain: string[];
  provenanceTimeline: ProvenanceEvent[];
} {
  // Source URL — browsers often embed this when saving a PDF from the web
  const sourceUrl =
    exifVal(exifRaw,
      "PDF:URL", "XMP-pdf:Source", "XMP-dc:Source",
      "XMP-xap:Identifier", "SourceURL", "PDF:SourceURL",
    ) ?? null;

  const { originType, originApp } = detectOrigin(
    m.creator ?? "", m.producer ?? "", m.xmpCreatorTool ?? "", rawText,
  );

  // Software chain — ordered: creator tool → creator → history agents → producer
  const seenLower = new Set<string>();
  const softwareChain: string[] = [];
  const addSw = (s: string | null | undefined) => {
    if (!s) return;
    const c = s.trim();
    if (!c || seenLower.has(c.toLowerCase())) return;
    seenLower.add(c.toLowerCase());
    softwareChain.push(c);
  };
  addSw(m.xmpCreatorTool);
  addSw(m.creator);
  const sortedHist = [...m.xmpHistory].sort((a, b) =>
    (a.when ?? "").localeCompare(b.when ?? ""),
  );
  for (const h of sortedHist) addSw(h.softwareAgent);
  addSw(m.producer);

  // Provenance timeline
  const events: ProvenanceEvent[] = [];
  const push = (ts: string | null, ev: string, agent: string | null, detail: string | null) => {
    events.push({ timestamp: ts, event: ev, agent, detail });
  };

  if (m.creationDate)
    push(m.creationDate, "created", m.xmpCreatorTool ?? m.creator,
      originApp !== "Unknown" ? `Created with ${originApp}` : null);

  for (const h of sortedHist)
    push(h.when, h.action ?? "modified", h.softwareAgent,
      h.changed ? `Changed: ${h.changed}` : null);

  if (m.modificationDate && m.modificationDate !== m.creationDate) {
    const covered = events.some(
      (e) => e.timestamp === m.modificationDate && e.event !== "created",
    );
    if (!covered)
      push(m.modificationDate, "modified", m.producer ?? null,
        "Last recorded modification");
  }

  events.sort((a, b) => (a.timestamp ?? "9999").localeCompare(b.timestamp ?? "9999"));

  return { sourceUrl, originType, originApp, softwareChain, provenanceTimeline: events };
}

// ─── Merged PDF component extractor ─────────────────────────────────────────

function extractMergedComponents(
  buf: Buffer,
  exifRaw: Record<string, unknown>,
  mainCreationDate: string | null,
): { isMerged: boolean; components: MergedComponent[]; derivedFromId: string | null } {
  const str = buf.toString("binary");
  const components: MergedComponent[] = [];

  // ── Method 1: XMP Ingredients (explicit merge marker) ───────────────────
  const ingredients: Record<number, Record<string, string | null>> = {};
  for (const [k, v] of Object.entries(exifRaw)) {
    const m = k.match(/Ingredients\[(\d+)\]\s+(.+)/i);
    if (!m) continue;
    const idx = parseInt(m[1]);
    const field = m[2].replace(/\s+/g, "").toLowerCase();
    if (!ingredients[idx]) ingredients[idx] = {};
    ingredients[idx][field] = v == null ? null : String(v).trim() || null;
  }
  for (const [idxStr, fields] of Object.entries(ingredients)) {
    if (!fields["documentid"] && !fields["instanceid"]) continue;
    const idx = parseInt(idxStr);
    components.push({
      index: idx,
      title: fields["title"] ?? null,
      author: fields["author"] ?? null,
      creator: fields["creator"] ?? null,
      producer: fields["producer"] ?? null,
      creationDate: normalizeDate(fields["createdate"] ?? fields["creationdate"] ?? null),
      modificationDate: normalizeDate(fields["modifydate"] ?? fields["modificationdate"] ?? null),
      documentId: fields["documentid"] ?? null,
      instanceId: fields["instanceid"] ?? null,
      detectionMethod: "xmpIngredients",
    });
  }

  // ── Method 2: Binary Info dictionary scanning ────────────────────────────
  // Find obj blocks that contain multiple PDF Info dictionary keys
  const objRe = /\d+\s+\d+\s+obj\s*<<([\s\S]{20,2000}?)>>\s*endobj/g;
  const seenCreation = new Set<string>(mainCreationDate ? [mainCreationDate] : []);
  const infoMarkers = ["/Author", "/Creator", "/Producer", "/Title", "/CreationDate", "/ModDate"];
  let objMatch: RegExpExecArray | null;

  const extractParenField = (block: string, field: string): string | null => {
    const re = new RegExp(`/${field}\\s*\\(([^)]{1,300})\\)`);
    const m = block.match(re);
    return m ? m[1].trim() : null;
  };

  while ((objMatch = objRe.exec(str)) !== null) {
    const block = objMatch[1];
    if (infoMarkers.filter((f) => block.includes(f)).length < 2) continue;

    const creation = normalizeDate(extractParenField(block, "CreationDate"));
    if (!creation || seenCreation.has(creation)) continue;
    seenCreation.add(creation);

    const alreadyCaptured = components.some(
      (c) => c.creationDate === creation && c.detectionMethod === "xmpIngredients",
    );
    if (alreadyCaptured) continue;

    components.push({
      index: components.length + 1,
      title:            extractParenField(block, "Title"),
      author:           extractParenField(block, "Author"),
      creator:          extractParenField(block, "Creator"),
      producer:         extractParenField(block, "Producer"),
      creationDate:     creation,
      modificationDate: normalizeDate(extractParenField(block, "ModDate")),
      documentId: null,
      instanceId: null,
      detectionMethod: "infoDictionary",
    });
  }

  components.sort((a, b) => (a.creationDate ?? "").localeCompare(b.creationDate ?? ""));

  const derivedFromId =
    exifVal(exifRaw, "XMP-xmpMM:DerivedFrom DocumentID", "XMP-xmpMM:DerivedFrom") ?? null;

  const isMerged = components.length > 1 || Object.keys(ingredients).length > 0;
  return { isMerged, components, derivedFromId };
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
  const sha256 = crypto.createHash("sha256").update(buf).digest("hex");

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
    sha256,

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

    // Provenance (populated below after base metadata is assembled)
    sourceUrl: null,
    originType: null,
    originApp: null,
    softwareChain: [],
    provenanceTimeline: [],

    // Merged components (populated below)
    isMergedDocument: false,
    mergedComponents: [],
    derivedFromId: null,
  };

  // ── Provenance profile ─────────────────────────────────────────────────────
  const provenance = buildProvenanceProfile(exifRaw, metadata, rawText);
  metadata.sourceUrl = provenance.sourceUrl;
  metadata.originType = provenance.originType;
  metadata.originApp = provenance.originApp;
  metadata.softwareChain = provenance.softwareChain;
  metadata.provenanceTimeline = provenance.provenanceTimeline;

  // ── Merged PDF analysis ────────────────────────────────────────────────────
  const merged = extractMergedComponents(buf, exifRaw, metadata.creationDate);
  metadata.isMergedDocument = merged.isMerged;
  metadata.mergedComponents = merged.components;
  metadata.derivedFromId = merged.derivedFromId;

  return { metadata, rawText };
}

// ─── Heuristic findings ──────────────────────────────────────────────────────

export function buildHeuristicFindings(
  m: DocumentMetadata,
  claimedIdentity: string,
  rawText: string
): Finding[] {
  const findings: Finding[] = [];
  const hasClaim = claimedIdentity.trim().length > 0;
  const claimed = claimedIdentity.toLowerCase();

  const isInstitutional = hasClaim && /bank|financial|government|federal|state|court|official|institution|authority|agency|legal|law|police|notary|hospital|insurance|university|ministry|department/.test(claimed);

  // ── Technical Profile (neutral structural facts — always emitted) ─────────
  {
    const fontDetail = m.fontCount > 0
      ? `${m.fontCount} font object${m.fontCount > 1 ? "s" : ""} (${m.embeddedFontCount} embedded, ${m.fonts.filter(f => f.subset).length} subsetted)`
      : "0 font objects detected";
    const structureFlags: string[] = [];
    if (m.linearized)          structureFlags.push("Linearized (web-optimized)");
    if (m.hasAcroForm)         structureFlags.push("AcroForm present");
    if (m.hasDigitalSignature) structureFlags.push(`Digital signatures: ${m.signatureCount}`);
    if (m.hasJavaScript)       structureFlags.push("JavaScript embedded");
    if (m.hasEmbeddedFiles)    structureFlags.push("Embedded file attachments");
    if (m.hasObjectStreams)    structureFlags.push("Object streams (/ObjStm)");
    if (m.hasXRefStreams)      structureFlags.push("XRef streams");
    if (m.encrypted)           structureFlags.push(`Encrypted (${m.encryptionMethod ?? "method unknown"})`);
    if (m.incrementalSaveCount > 0)
      structureFlags.push(`${m.incrementalSaveCount + 1} %%EOF sections (${m.incrementalSaveCount} post-creation modification${m.incrementalSaveCount > 1 ? "s" : ""})`);

    findings.push({
      category: "technical-profile",
      severity: "info",
      title: "Technical Profile",
      description: [
        `Fonts: ${fontDetail}.`,
        structureFlags.length > 0 ? `Structural features: ${structureFlags.join("; ")}.` : "No unusual structural features detected.",
        m.pageCount != null ? `Pages: ${m.pageCount}. PDF version: ${m.pdfVersion ?? "unknown"}. File size: ${m.fileSize ? (m.fileSize / 1024).toFixed(1) + " KB" : "unknown"}.` : "",
      ].filter(Boolean).join(" "),
    });
  }

  // ── Software fingerprint ─────────────────────────────────────────────────
  const consumerApps = ["microsoft word", "libreoffice", "openoffice", "google docs", "wps office", "pages", "google slides", "keynote", "canva"];
  const creatorTool = (m.xmpCreatorTool ?? m.creator ?? "").toLowerCase();
  const producer = (m.producer ?? "").toLowerCase();
  const softwareName = m.xmpCreatorTool ?? m.creator ?? m.producer;

  const matchedApp = consumerApps.find((a) => creatorTool.includes(a) || producer.includes(a));
  if (matchedApp && isInstitutional) {
    findings.push({
      category: "software",
      severity: "critical",
      title: `Creator Tool is consumer office software, inconsistent with institutional claim`,
      description: `The XMP CreatorTool field identifies "${softwareName}" as the authoring application. If this document is genuinely "${claimedIdentity}", it would be expected to originate from an enterprise document management system (e.g., Documentum, OpenText, regulated SharePoint templates, or an institution-specific PDF generator) — not a personal desktop office suite. Consumer office software is one of the most reliable indicators that a document was privately prepared rather than institutionally issued.`,
    });
  } else if (matchedApp && hasClaim) {
    findings.push({
      category: "software",
      severity: "info",
      title: `Document created with ${softwareName}`,
      description: `The authoring tool is identified as "${softwareName}". For the claimed document type ("${claimedIdentity}"), use of this application is consistent with personal or informal document creation.`,
    });
  } else if (matchedApp) {
    findings.push({
      category: "software",
      severity: "info",
      title: `Document created with ${softwareName}`,
      description: `The authoring tool is identified as "${softwareName}", a consumer office application.`,
    });
  }

  // ── Incremental saves — exact count, claim-relative ───────────────────────
  if (m.incrementalSaveCount > 0) {
    const total = m.incrementalSaveCount + 1;
    const severity = m.incrementalSaveCount >= 3 ? "high" : "medium";
    const claimNote = hasClaim
      ? ` For a document claimed to be "${claimedIdentity}", post-creation modifications are significant if the claimed issuance date precedes the modification dates, or if the document is represented as a signed, unaltered original.`
      : "";
    findings.push({
      category: "structure",
      severity,
      title: `${m.incrementalSaveCount} post-creation modification${m.incrementalSaveCount > 1 ? "s" : ""} (${total} %%EOF sections)`,
      description: `PDF files record each save as a separate body section terminated by "%%EOF". This document contains ${total} %%EOF markers, meaning it was modified ${m.incrementalSaveCount} time${m.incrementalSaveCount > 1 ? "s" : ""} after its initial creation.${claimNote}`,
    });
  }

  // ── Date conflicts (only meaningful with a claim) ────────────────────────
  if (hasClaim) {
    const yearMatch = claimedIdentity.match(/\b(19|20)\d{2}\b/);
    const metaDate = m.xmpCreateDate ?? m.creationDate;
    if (yearMatch && metaDate) {
      const claimedYear = parseInt(yearMatch[0]);
      const metaYear = parseInt(metaDate.slice(0, 4));
      if (Math.abs(claimedYear - metaYear) > 1) {
        findings.push({
          category: "timestamp",
          severity: "high",
          title: `Creation date (${metaYear}) does not match claimed year (${claimedYear})`,
          description: `The claim states this is a document from ${claimedYear}, but the embedded metadata records a creation date of ${metaDate}. This ${Math.abs(claimedYear - metaYear)}-year discrepancy between the claimed issuance date and the document's internal timestamps cannot be explained by timezone differences or file-system copying, and directly undermines the claim "${claimedIdentity}".`,
        });
      }
    }
  }

  // ── XMP ≠ Info dictionary date conflict ─────────────────────────────────
  if (m.xmpCreateDate && m.creationDate) {
    const xmpDay = m.xmpCreateDate.slice(0, 10);
    const infoDay = m.creationDate.slice(0, 10);
    if (xmpDay !== infoDay) {
      const claimNote = hasClaim ? ` In the context of the claim "${claimedIdentity}", this inconsistency warrants scrutiny of which timestamp is accurate.` : "";
      findings.push({
        category: "timestamp",
        severity: "medium",
        title: `XMP creation date (${xmpDay}) differs from PDF Info dictionary date (${infoDay})`,
        description: `Two independent date records within the same document disagree. The XMP metadata records "${m.xmpCreateDate}" while the PDF Info dictionary records "${m.creationDate}". Legitimate PDF generators write both timestamps in lockstep; divergence suggests the Info dictionary was manually edited after the XMP metadata was set.${claimNote}`,
      });
    }
  }

  // ── Personal name as author in institutional document ────────────────────
  if (m.author && isInstitutional) {
    const isPersonalName = /^[A-Z][a-z]+[, ][A-Z]/.test(m.author.trim()) || /^[A-Z][a-z]+ [A-Z][a-z]+$/.test(m.author.trim());
    if (isPersonalName) {
      findings.push({
        category: "metadata",
        severity: "high",
        title: `Author field contains an individual name, not an institutional identity`,
        description: `The PDF Author field contains "${m.author}", which appears to be a personal name. If this document is genuinely "${claimedIdentity}", the Author field would be expected to contain the organization name, department identifier, or automated system name — not the name of an individual. Institutional documents authored through enterprise content management systems do not carry personal names in this field.`,
      });
    }
  }

  // ── JavaScript ────────────────────────────────────────────────────────────
  if (m.hasJavaScript) {
    findings.push({
      category: "structure",
      severity: "critical",
      title: `Embedded JavaScript detected`,
      description: `The PDF contains one or more JavaScript (/JS) objects. Legitimate documents${hasClaim ? ` of the type claimed ("${claimedIdentity}")` : ""} have no reason to include executable code. JavaScript in PDFs is associated with exploits, phishing, automated form manipulation, and anti-forensic techniques.`,
    });
  }

  // ── Launch actions ────────────────────────────────────────────────────────
  if (m.hasLaunchActions) {
    findings.push({
      category: "structure",
      severity: "critical",
      title: `Launch actions detected — potential malicious payload`,
      description: `The document contains a /Launch action that can execute external programs or open other files when the PDF is opened. This is a well-known attack vector in targeted phishing campaigns and is not consistent with any legitimate document type.`,
    });
  }

  // ── Suspect fonts ─────────────────────────────────────────────────────────
  if (m.suspectFonts.length > 0 && isInstitutional) {
    findings.push({
      category: "content",
      severity: "medium",
      title: `Non-professional fonts inconsistent with institutional claim`,
      description: `The document contains the following informal or decorative fonts: ${m.suspectFonts.join(", ")}. These fonts are not consistent with the professional typography standards expected of "${claimedIdentity}". Institutional documents from banks, courts, and regulated entities use standardized corporate font sets.`,
    });
  } else if (m.suspectFonts.length > 0) {
    findings.push({
      category: "content",
      severity: "info",
      title: `Informal fonts detected: ${m.suspectFonts.slice(0, 3).join(", ")}`,
      description: `The document uses these informal or decorative fonts: ${m.suspectFonts.join(", ")}.`,
    });
  }

  // ── Zero font objects despite extractable text ────────────────────────────
  // Only flag when the binary scan found genuinely zero /BaseFont or /Font objects
  // alongside text content — not when fonts exist but merely aren't embedded.
  if (m.fontCount === 0 && (rawText?.length ?? 0) > 100) {
    const claimNote = hasClaim ? ` For a document claimed to be "${claimedIdentity}", this is atypical.` : "";
    findings.push({
      category: "structure",
      severity: "medium",
      title: `Zero font objects found despite extractable text`,
      description: `The binary scan found no /Font dictionary entries (no /BaseFont names, no font resource objects) in this PDF, yet the document contains extractable text content. Standard PDF generators always record font objects even for text-only pages. This may indicate the font dictionary was stripped, the document was produced by a non-standard tool, or text was embedded using an unusual encoding method.${claimNote}`,
    });
  }

  // ── No embedded fonts in institutional document ───────────────────────────
  if (m.fontCount > 0 && m.embeddedFontCount === 0 && isInstitutional) {
    findings.push({
      category: "structure",
      severity: "low",
      title: `No fonts are embedded — relies on viewer font substitution`,
      description: `The document references ${m.fontCount} font${m.fontCount > 1 ? "s" : ""} but none are embedded (no /FontFile, /FontFile2, or /FontFile3 streams). Enterprise PDFs intended for official distribution — consistent with "${claimedIdentity}" — typically embed all fonts to guarantee exact rendering across different systems.`,
    });
  }

  // ── XMP history ───────────────────────────────────────────────────────────
  if (m.xmpHistory.length > 0) {
    const agents = [...new Set(m.xmpHistory.map((h) => h.softwareAgent).filter(Boolean))];
    if (agents.length > 1) {
      const claimNote = hasClaim ? ` In the context of the claim "${claimedIdentity}", the presence of multiple editing tools may indicate the document was assembled from separate sources or altered after initial creation.` : "";
      findings.push({
        category: "metadata",
        severity: hasClaim ? "medium" : "info",
        title: `XMP history records ${agents.length} different editing applications`,
        description: `The XMP edit history shows this document passed through: ${agents.slice(0, 5).join("; ")}.${claimNote}`,
      });
    }
    if (m.xmpHistory.length > 3) {
      findings.push({
        category: "metadata",
        severity: "low",
        title: `${m.xmpHistory.length} XMP edit sessions recorded`,
        description: `The XMP metadata contains a history of ${m.xmpHistory.length} documented save/edit operations, suggesting iterative authoring.`,
      });
    }
  }

  // ── DocumentID === InstanceID ─────────────────────────────────────────────
  if (m.documentId && m.instanceId && m.documentId === m.instanceId) {
    findings.push({
      category: "metadata",
      severity: "info",
      title: `DocumentID and InstanceID are identical`,
      description: `In the XMP metadata model, DocumentID is a permanent GUID set at creation and InstanceID is updated on every save. Their equality suggests the document was created and exported in a single operation without subsequent re-saving through an XMP-aware application.`,
    });
  }

  // ── Embedded files ────────────────────────────────────────────────────────
  if (m.hasEmbeddedFiles) {
    findings.push({
      category: "structure",
      severity: "medium",
      title: `Embedded file attachments detected`,
      description: `The PDF contains one or more embedded file attachments (/EmbeddedFile objects). These should be extracted and examined separately${hasClaim ? ` to determine if they are consistent with the claimed document type "${claimedIdentity}"` : ""}.`,
    });
  }

  // ── External URLs ─────────────────────────────────────────────────────────
  if (m.embeddedUrls.length > 0) {
    const urls = m.embeddedUrls.map((u) => u.url).slice(0, 5).join(", ");
    findings.push({
      category: "structure",
      severity: "low",
      title: `${m.embeddedUrls.length} embedded URL${m.embeddedUrls.length > 1 ? "s" : ""}`,
      description: `Embedded hyperlinks: ${urls}${m.embeddedUrls.length > 5 ? ` (+${m.embeddedUrls.length - 5} more)` : ""}.`,
    });
  }

  // ── Template text ─────────────────────────────────────────────────────────
  const templatePhrases = ["[insert", "lorem ipsum", "sample text", "placeholder", "your name here", "[your", "[date]", "click here to"];
  const foundTemplate = templatePhrases.filter((p) => rawText.toLowerCase().includes(p));
  if (foundTemplate.length > 0) {
    findings.push({
      category: "content",
      severity: "critical",
      title: `Unresolved template placeholder text`,
      description: `The document text contains unfilled template markers: ${foundTemplate.map((p) => `"${p}"`).join(", ")}. This conclusively shows the document was not finalized${hasClaim ? ` and directly contradicts the claim "${claimedIdentity}"` : ""}.`,
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

━━━ CORE DIRECTIVE — READ CAREFULLY ━━━
Your ONLY job is to determine whether this document IS what it CLAIMS to be.
The verdict must answer ONE question: "Does the evidence support or contradict the claimed identity?"

THE VERDICT IS NOT ABOUT:
- Whether the document is professionally produced
- Whether the content seems complete or well-written
- Whether the document is inherently suspicious-looking
- Whether you personally would trust this document

THE VERDICT IS STRICTLY ABOUT:
- Do the metadata fields (creator, producer, author, dates, tools) match what the claimant says?
- Is there evidence of tampering, alteration, or misrepresentation relative to the claim?
- Are there internal contradictions that make the claim implausible?

EXAMPLES OF CORRECT REASONING:
- Claim: "Letter from Bank of America" → Metadata shows Creator = "Microsoft Word 365, personal edition" → SUSPICIOUS (bank letters come from enterprise systems, not personal Word)
- Claim: "DOC BY JMKUCZYNSKI" → Metadata shows Author = "JM Kuczynski", Creator = personal software → AUTHENTIC (metadata matches; personal software is expected for a personal document)
- Claim: "Official court document 2020" → XMP CreateDate = 2024 → LIKELY_FORGED (date anachronism directly contradicts claim)
- Claim: "Personal notes by John" → Random content, no institutional markers → AUTHENTIC (matches a personal document)

DO NOT penalize a document for being simple, short, or having minimal content — those are irrelevant to whether it is what it claims to be.
DO NOT penalize missing fonts, sparse text, or non-institutional styling when the claim itself is non-institutional.

ANALYSIS INSTRUCTIONS:
1. Identify what KIND of document the claim describes (personal, institutional, official, informal, etc.).
2. Check whether the metadata author, creator, producer, and dates are consistent with that KIND of document from that CLAIMED ORIGIN.
3. Flag any direct contradictions between the claim and the evidence.
4. Look for anachronisms — software versions that postdate the claimed document date.
5. Do NOT repeat findings already listed in the rule-based section. Only add NEW insights.
6. Be specific: name the exact metadata field and value that raises or clears concern.

Return ONLY valid JSON (no markdown fences):
{
  "verdict": "strong_match" | "partial_match" | "weak_match" | "inconsistent" | "inconclusive",
  "confidence": <0-100>,
  "summary": "<two to three professional sentences evaluating how well the document evidence supports the claimed identity — cite specific metadata fields and values, and explain exactly what supports or undermines the claim>",
  "additionalFindings": [
    {
      "category": "metadata|software|timestamp|content|language|structure|signature",
      "severity": "info|low|medium|high|critical",
      "title": "<concise title that references the claim>",
      "description": "<evidence-based description citing exact field names and values, and explaining what this means for the specific claim>"
    }
  ]
}

Verdict guide — how well does the document's evidence MATCH the claimed identity?
  strong_match   = metadata, software, dates, and structure are all consistent with the claim; no material contradictions
  partial_match  = mostly consistent but with minor gaps, unexplained fields, or data that cannot be independently verified — needs corroboration
  weak_match     = one or more metadata fields or structural signals are directly inconsistent with the claim
  inconsistent   = multiple independent indicators clearly and directly contradict the claim
  inconclusive   = genuinely insufficient metadata to form any opinion about the claim (use only as last resort)`;

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

  const validVerdicts = ["strong_match", "partial_match", "weak_match", "inconsistent", "inconclusive"];
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

// ─── Exploration-mode AI analysis (no claim) ─────────────────────────────────

async function runExplorationAnalysis(
  m: DocumentMetadata,
  rawText: string,
  heuristicFindings: Finding[]
): Promise<{ aiFindings: Finding[]; summary: string; verdict: AnalysisResult["verdict"]; confidence: number }> {
  const hSum = heuristicFindings.length > 0
    ? heuristicFindings.map((f) => `[${f.severity.toUpperCase()}] ${f.category}: ${f.title}`).join("\n")
    : "(none)";

  const fontList = m.fonts.slice(0, 20).map((f) =>
    `${f.name} (${f.type ?? "?"}, ${f.embedded ? "embedded" : "not embedded"})`
  ).join("; ");

  const historyList = m.xmpHistory.slice(0, 8).map((h) =>
    `[${h.when ?? "?"}] ${h.action ?? "?"} by ${h.softwareAgent ?? "?"}`
  ).join("\n");

  const prompt = `You are a forensic document examiner with FBI-level PDF analysis training. No identity claim was provided for this document. Run in EXPLORATION MODE: your goal is to extract maximum intelligence from the metadata and content — describe everything the document reveals about itself.

═══ PDF INFO DICTIONARY ═══
Author: ${m.author ?? "None"}
Creator: ${m.creator ?? "None"}
Producer: ${m.producer ?? "None"}
Creation Date: ${m.creationDate ?? "Unknown"}
Modification Date: ${m.modificationDate ?? "Unknown"}
PDF Version: ${m.pdfVersion ?? "Unknown"}
Page Count: ${m.pageCount ?? "Unknown"}
File Size: ${m.fileSize ? `${(m.fileSize / 1024).toFixed(1)} KB` : "Unknown"}

═══ XMP METADATA ═══
XMP Creator Tool: ${m.xmpCreatorTool ?? "None"}
XMP Create Date: ${m.xmpCreateDate ?? "None"}
XMP Modify Date: ${m.xmpModifyDate ?? "None"}
Title: ${m.title ?? "None"}
Subject: ${m.subject ?? "None"}
Keywords: ${m.keywords ?? "None"}
Language: ${m.language ?? "None"}
Document GUID: ${m.documentId ?? "None"}
Instance ID: ${m.instanceId ?? "None"}

═══ FONT ANALYSIS ═══
Total fonts: ${m.fontCount}  |  Embedded: ${m.embeddedFontCount}
Font list: ${fontList || "None"}

═══ XMP EDIT HISTORY ═══
${historyList || "(No XMP history)"}

═══ STRUCTURE ═══
Incremental saves: ${m.incrementalSaveCount}
JavaScript: ${m.hasJavaScript}  |  Signatures: ${m.signatureCount}  |  Linearized: ${m.linearized}
Encrypted: ${m.encrypted}  |  Embedded files: ${m.hasEmbeddedFiles}
Page size: ${m.pageSize ?? "Unknown"}  |  Page layout: ${m.pageLayout ?? "Unknown"}

═══ ALREADY DETECTED (rule-based) ═══
${hSum}

═══ DOCUMENT TEXT (first 3000 chars) ═══
${rawText.slice(0, 3000) || "(No extractable text)"}

EXPLORATION INSTRUCTIONS:
1. Describe what this document appears to be based on all available evidence. What type of document is it? What is its probable purpose?
2. Identify every creator, author, and tool that touched this document and what role they appear to have played.
3. Reconstruct the document's probable timeline: when was it created, who edited it, in what sequence?
4. Note any structural anomalies, inconsistencies, or unusual characteristics — even if their significance is uncertain without a claim.
5. If there are multiple pages, note any evidence of different authorship per page (different fonts, tools, or XMP sessions).
6. Do NOT assign a forgery verdict. The verdict must be "inconclusive". The summary should be an intelligence report, not a judgment.
7. Do NOT repeat findings from the rule-based section unless you have significant additional detail to add.

Return ONLY valid JSON (no markdown fences):
{
  "verdict": "inconclusive",
  "confidence": 0,
  "summary": "<three to five sentences — an intelligence briefing about what this document is, who created it, and any notable characteristics. Written for a forensic analyst, not a jury.>",
  "additionalFindings": [
    {
      "category": "metadata|software|timestamp|content|language|structure|signature",
      "severity": "info|low|medium|high|critical",
      "title": "<concise title>",
      "description": "<specific observation citing exact field names and values>"
    }
  ]
}`;

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
    logger.warn({ raw }, "Failed to parse exploration AI response JSON");
  }

  return {
    verdict: "inconclusive",
    confidence: 0,
    summary: parsed.summary ?? "Exploration complete. See findings for detailed observations.",
    aiFindings: Array.isArray(parsed.additionalFindings) ? parsed.additionalFindings : [],
  };
}

// ─── Document Q&A ─────────────────────────────────────────────────────────────

export async function chatWithDocument(
  filePath: string,
  metadata: DocumentMetadata,
  claimedIdentity: string,
  question: string,
  history: { role: "user" | "assistant"; content: string }[]
): Promise<string> {
  // Re-extract text from file (file is kept permanently)
  let rawText = (metadata as DocumentMetadata & { rawText?: string }).rawText ?? "";
  if (!rawText && filePath && fs.existsSync(filePath)) {
    try {
      const buf = fs.readFileSync(filePath);
      const parsed = await pdfParse(buf).catch(() => null);
      rawText = parsed?.text ?? "";
    } catch { /* ignore */ }
  }

  const metaSummary = JSON.stringify({
    author: metadata.author,
    creator: metadata.creator,
    producer: metadata.producer,
    xmpCreatorTool: metadata.xmpCreatorTool,
    creationDate: metadata.creationDate,
    modificationDate: metadata.modificationDate,
    xmpCreateDate: metadata.xmpCreateDate,
    xmpModifyDate: metadata.xmpModifyDate,
    pageCount: metadata.pageCount,
    pdfVersion: metadata.pdfVersion,
    title: metadata.title,
    subject: metadata.subject,
    keywords: metadata.keywords,
    author2: metadata.author,
    fontCount: metadata.fontCount,
    embeddedFontCount: metadata.embeddedFontCount,
    fonts: metadata.fonts?.slice(0, 15).map(f => f.name),
    incrementalSaveCount: metadata.incrementalSaveCount,
    hasDigitalSignature: metadata.hasDigitalSignature,
    signatureCount: metadata.signatureCount,
    hasJavaScript: metadata.hasJavaScript,
    encrypted: metadata.encrypted,
    isMergedDocument: metadata.isMergedDocument,
    mergedComponents: metadata.mergedComponents,
    xmpHistory: metadata.xmpHistory?.slice(0, 8),
    sha256: metadata.sha256,
    documentId: metadata.documentId,
    instanceId: metadata.instanceId,
    embeddedUrls: metadata.embeddedUrls?.slice(0, 10),
    originType: metadata.originType,
    originApp: metadata.originApp,
    softwareChain: metadata.softwareChain,
  }, null, 2);

  const systemPrompt = `You are a forensic document analyst with deep expertise in PDF forensics, metadata analysis, and document authentication. You have full access to the forensic data extracted from a PDF document.

DOCUMENT FILE NAME: ${metadata.fileSize ? `(${(metadata.fileSize / 1024).toFixed(1)} KB)` : ""}
CLAIMED IDENTITY: ${claimedIdentity || "(none — exploration mode)"}

EXTRACTED METADATA:
${metaSummary}

DOCUMENT TEXT (first 6000 chars):
${rawText.slice(0, 6000) || "(No extractable text)"}

Answer the user's questions about this document based ONLY on the data above. Be specific and cite exact field names and values. If asked about a specific page, use the document text to identify page content where possible. If you cannot determine something from the available data, say so clearly rather than guessing.`;

  const messages: { role: "user" | "assistant" | "system"; content: string }[] = [
    { role: "system", content: systemPrompt },
    ...history.slice(-10).map(h => ({ role: h.role as "user" | "assistant", content: h.content })),
    { role: "user", content: question },
  ];

  const response = await openai.chat.completions.create({
    model: "gpt-5.6-terra",
    max_completion_tokens: 1500,
    messages,
  });

  return response.choices[0]?.message?.content ?? "I was unable to generate a response. Please try again.";
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

  // Store rawText in metadata for future chat queries (capped at 50k chars)
  (metadata as DocumentMetadata & { rawText: string }).rawText = rawText.slice(0, 50000);

  const heuristicFindings = buildHeuristicFindings(metadata, claimedIdentity, rawText);

  const hasClaim = claimedIdentity.trim().length > 0;
  const { verdict, confidence, summary, aiFindings } = hasClaim
    ? await runAiAnalysis(metadata, claimedIdentity, rawText, heuristicFindings)
    : await runExplorationAnalysis(metadata, rawText, heuristicFindings);

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
