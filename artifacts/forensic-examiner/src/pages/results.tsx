import React from 'react';
import { useParams, useLocation } from 'wouter';
import { useGetDocument, getGetDocumentQueryKey, useReanalyzeDocument, useDeleteDocument, type DocumentAnalysis } from '@workspace/api-client-react';
import { VerdictBadge } from '@/components/VerdictBadge';
import { FindingsList } from '@/components/FindingsList';
import {
  Loader2, RefreshCcw, Trash2, ArrowLeft, FileText, FileKey, Fingerprint,
  AlertTriangle, Download, ChevronDown, ChevronRight, Shield, Code2,
  Type, Link2, Clock, Database, AlertOctagon, CheckCircle, XCircle, Minus,
  Globe, Printer, Monitor, Cloud, Layers, GitMerge, Network, History,
  ScanLine, ExternalLink, MessageSquare, Send, Bot, User as UserIcon
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { format } from 'date-fns';
import { useToast } from '@/hooks/use-toast';
import { Link } from 'wouter';

type DocData = DocumentAnalysis;

async function downloadForensicReport(doc: DocData) {
  const { jsPDF } = await import('jspdf');
  const pdf = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });

  const PAGE_W = 210;
  const PAGE_H = 297;
  const MARGIN = 20;
  const CONTENT_W = PAGE_W - MARGIN * 2;
  let y = 0;

  const COLORS = {
    bg:         [10,  12,  18]  as [number,number,number],
    card:       [16,  20,  30]  as [number,number,number],
    accent:     [0,   180, 216] as [number,number,number],
    authentic:  [34,  197, 94]  as [number,number,number],
    suspicious: [234, 179, 8]   as [number,number,number],
    forged:     [239, 68,  68]  as [number,number,number],
    inconc:     [148, 163, 184] as [number,number,number],
    white:      [255, 255, 255] as [number,number,number],
    muted:      [100, 116, 139] as [number,number,number],
    border:     [30,  41,  59]  as [number,number,number],
  };

  const verdictColor = (v: string | null | undefined): [number,number,number] => {
    if (v === 'authentic')    return COLORS.authentic;
    if (v === 'suspicious')   return COLORS.suspicious;
    if (v === 'likely_forged') return COLORS.forged;
    return COLORS.inconc;
  };

  const severityColor = (s: string): [number,number,number] => {
    if (s === 'critical') return COLORS.forged;
    if (s === 'high')     return [249, 115, 22];
    if (s === 'medium')   return COLORS.suspicious;
    if (s === 'low')      return COLORS.accent;
    return COLORS.muted;
  };

  const checkPage = (needed: number) => {
    if (y + needed > PAGE_H - 15) {
      pdf.addPage();
      pdf.setFillColor(...COLORS.bg);
      pdf.rect(0, 0, PAGE_W, PAGE_H, 'F');
      y = MARGIN;
    }
  };

  const wrapText = (text: string, maxWidth: number, fontSize: number): string[] => {
    pdf.setFontSize(fontSize);
    return pdf.splitTextToSize(text, maxWidth) as string[];
  };

  // ── Cover / header ──────────────────────────────────────────────────────────
  pdf.setFillColor(...COLORS.bg);
  pdf.rect(0, 0, PAGE_W, PAGE_H, 'F');

  // Top accent bar
  pdf.setFillColor(...COLORS.accent);
  pdf.rect(0, 0, PAGE_W, 2, 'F');

  // Title block
  y = 18;
  pdf.setTextColor(...COLORS.accent);
  pdf.setFontSize(7);
  pdf.setFont('helvetica', 'bold');
  pdf.text('FORENSIC DOCUMENT EXAMINER  ·  OFFICIAL ANALYSIS REPORT', MARGIN, y);

  y += 10;
  pdf.setTextColor(...COLORS.white);
  pdf.setFontSize(22);
  pdf.setFont('helvetica', 'bold');
  pdf.text('Forensic Analysis Report', MARGIN, y);

  y += 7;
  pdf.setTextColor(...COLORS.muted);
  pdf.setFontSize(9);
  pdf.setFont('helvetica', 'normal');
  const genDate = format(new Date(), 'MMMM d, yyyy · HH:mm');
  pdf.text(`Generated: ${genDate}`, MARGIN, y);

  // Divider
  y += 7;
  pdf.setDrawColor(...COLORS.border);
  pdf.setLineWidth(0.3);
  pdf.line(MARGIN, y, PAGE_W - MARGIN, y);

  // ── Verdict banner ──────────────────────────────────────────────────────────
  y += 10;
  const bannerH = 38;
  pdf.setFillColor(...COLORS.card);
  pdf.roundedRect(MARGIN, y, CONTENT_W, bannerH, 3, 3, 'F');
  pdf.setDrawColor(...verdictColor(doc.verdict));
  pdf.setLineWidth(0.6);
  pdf.roundedRect(MARGIN, y, CONTENT_W, bannerH, 3, 3, 'S');

  const verdictLabel = (doc.verdict ?? 'INCONCLUSIVE').replace(/_/g, ' ').toUpperCase();
  pdf.setFontSize(6);
  pdf.setFont('helvetica', 'bold');
  pdf.setTextColor(...COLORS.muted);
  pdf.text('OFFICIAL VERDICT', MARGIN + CONTENT_W / 2, y + 8, { align: 'center' });

  pdf.setFontSize(20);
  pdf.setFont('helvetica', 'bold');
  pdf.setTextColor(...verdictColor(doc.verdict));
  pdf.text(verdictLabel, MARGIN + CONTENT_W / 2, y + 20, { align: 'center' });

  pdf.setFontSize(8);
  pdf.setFont('helvetica', 'normal');
  pdf.setTextColor(...COLORS.muted);
  pdf.text(`Confidence Score: ${doc.confidenceScore ?? 0}%`, MARGIN + CONTENT_W / 2, y + 30, { align: 'center' });

  y += bannerH + 10;

  // ── Evidence record ─────────────────────────────────────────────────────────
  pdf.setFontSize(7);
  pdf.setFont('helvetica', 'bold');
  pdf.setTextColor(...COLORS.accent);
  pdf.text('EVIDENCE RECORD', MARGIN, y);
  y += 5;

  const reportSha256 = String((doc.metadata as Record<string, unknown> | null | undefined)?.['sha256'] ?? '');
  const metaRows: [string, string][] = [
    ['Claimed Identity', doc.claimedIdentity?.trim() ? doc.claimedIdentity : 'Exploration Mode (no claim)'],
    ['Filename', doc.fileName ?? '—'],
    ['File Size', doc.fileSize ? `${(doc.fileSize / 1024).toFixed(1)} KB` : '—'],
    ['Analysis Date', doc.createdAt ? format(new Date(doc.createdAt), 'MMMM d, yyyy') : '—'],
  ];

  for (const [label, value] of metaRows) {
    checkPage(8);
    pdf.setFontSize(7);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(...COLORS.muted);
    pdf.text(label.toUpperCase(), MARGIN, y);
    const lines = wrapText(value, CONTENT_W - 45, 8);
    pdf.setFont('helvetica', 'normal');
    pdf.setTextColor(...COLORS.white);
    pdf.setFontSize(8);
    pdf.text(lines, MARGIN + 44, y);
    y += lines.length * 5 + 2;
  }

  // SHA-256 in Evidence Record — prominent highlighted box
  if (reportSha256) {
    checkPage(18);
    y += 2;
    pdf.setFontSize(7);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(...COLORS.muted);
    pdf.text('SHA-256 DOCUMENT HASH', MARGIN, y);
    y += 5;
    pdf.setFillColor(...COLORS.card);
    pdf.roundedRect(MARGIN, y, CONTENT_W, 10, 1.5, 1.5, 'F');
    pdf.setDrawColor(...COLORS.accent);
    pdf.setLineWidth(0.4);
    pdf.roundedRect(MARGIN, y, CONTENT_W, 10, 1.5, 1.5, 'S');
    pdf.setFontSize(6.5);
    pdf.setFont('helvetica', 'normal');
    pdf.setTextColor(...COLORS.accent);
    // Split hash into two halves so it never overflows
    const half = Math.ceil(reportSha256.length / 2);
    const line1 = reportSha256.slice(0, half);
    const line2 = reportSha256.slice(half);
    pdf.text(line1 + (line2 ? '…' : ''), MARGIN + 3, y + 4.5);
    if (line2) {
      pdf.text('…' + line2, MARGIN + 3, y + 8.5);
    }
    y += line2 ? 18 : 14;
  }

  // ── Summary ─────────────────────────────────────────────────────────────────
  if (doc.summary) {
    y += 4;
    pdf.setDrawColor(...COLORS.border);
    pdf.line(MARGIN, y, PAGE_W - MARGIN, y);
    y += 8;

    pdf.setFontSize(7);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(...COLORS.accent);
    pdf.text('EXAMINER\'S SUMMARY', MARGIN, y);
    y += 6;

    // Left accent bar
    pdf.setFillColor(...COLORS.accent);
    pdf.rect(MARGIN, y, 1.5, 1, 'F'); // will extend with text

    const summaryLines = wrapText(`"${doc.summary}"`, CONTENT_W - 6, 9);
    const summaryBlockH = summaryLines.length * 5.5 + 6;
    checkPage(summaryBlockH + 4);

    pdf.setFillColor(...COLORS.card);
    pdf.roundedRect(MARGIN, y, CONTENT_W, summaryBlockH, 2, 2, 'F');
    pdf.setFillColor(...COLORS.accent);
    pdf.rect(MARGIN, y, 2, summaryBlockH, 'F');

    pdf.setFontSize(9);
    pdf.setFont('helvetica', 'italic');
    pdf.setTextColor(...COLORS.white);
    pdf.text(summaryLines, MARGIN + 6, y + 5.5);
    y += summaryBlockH + 10;
  }

  // ── Forensic Findings ───────────────────────────────────────────────────────
  const findings = (doc.findings ?? []) as Array<{ category: string; severity: string; title: string; description: string }>;
  if (findings.length > 0) {
    pdf.setDrawColor(...COLORS.border);
    pdf.line(MARGIN, y, PAGE_W - MARGIN, y);
    y += 8;

    pdf.setFontSize(7);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(...COLORS.accent);
    pdf.text(`FORENSIC FINDINGS  (${findings.length})`, MARGIN, y);
    y += 7;

    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      const descLines = wrapText(f.description, CONTENT_W - 8, 8);
      const blockH = 7 + descLines.length * 4.5 + 8;
      checkPage(blockH + 4);

      const col = severityColor(f.severity);
      pdf.setFillColor(...COLORS.card);
      pdf.roundedRect(MARGIN, y, CONTENT_W, blockH, 2, 2, 'F');
      pdf.setFillColor(...col);
      pdf.rect(MARGIN, y, 2, blockH, 'F');

      // Severity pill
      const pillW = 18;
      pdf.setFillColor(col[0] * 0.25, col[1] * 0.25, col[2] * 0.25);
      pdf.roundedRect(MARGIN + 5, y + 4, pillW, 5, 1, 1, 'F');
      pdf.setFontSize(5.5);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(...col);
      pdf.text(f.severity.toUpperCase(), MARGIN + 5 + pillW / 2, y + 7.5, { align: 'center' });

      // Category
      pdf.setFontSize(5.5);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor(...COLORS.muted);
      pdf.text(f.category.toUpperCase(), MARGIN + 5 + pillW + 4, y + 7.5);

      // Title
      pdf.setFontSize(9);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(...COLORS.white);
      pdf.text(f.title, MARGIN + 5, y + 15);

      // Description
      pdf.setFontSize(8);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor(...COLORS.muted);
      pdf.text(descLines, MARGIN + 5, y + 21);

      y += blockH + 4;
    }
  }

  // ── PDF Metadata ─────────────────────────────────────────────────────────────
  const meta = doc.metadata as Record<string, unknown> | null | undefined;
  if (meta) {
    checkPage(60);
    y += 4;
    pdf.setDrawColor(...COLORS.border);
    pdf.line(MARGIN, y, PAGE_W - MARGIN, y);
    y += 8;

    pdf.setFontSize(7);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(...COLORS.accent);
    pdf.text('EXTRACTED PDF METADATA', MARGIN, y);
    y += 6;

    // SHA-256 is already displayed in the Evidence Record at the top; skip duplicate here

    const metaFields: [string, string][] = [
      ['Author',        String(meta['author']           ?? 'N/A')],
      ['Creator',       String(meta['creator']          ?? 'N/A')],
      ['Producer',      String(meta['producer']         ?? 'N/A')],
      ['Creation Date', String(meta['creationDate']     ?? 'N/A')],
      ['Modified Date', String(meta['modificationDate'] ?? 'N/A')],
      ['Page Count',    String(meta['pageCount']        ?? 'N/A')],
      ['PDF Version',   String(meta['pdfVersion']       ?? 'N/A')],
    ];

    const colW = CONTENT_W / 2 - 2;
    for (let i = 0; i < metaFields.length; i += 2) {
      checkPage(10);
      const left  = metaFields[i];
      const right = metaFields[i + 1];
      const rowY  = y;

      for (const [idx, [label, value]] of [[0, left], [1, right]].filter(([, v]) => v) as [number, [string, string]][]) {
        const x = MARGIN + idx * (colW + 4);
        pdf.setFillColor(...COLORS.card);
        pdf.roundedRect(x, rowY, colW, 8, 1, 1, 'F');
        pdf.setFontSize(6);
        pdf.setFont('helvetica', 'bold');
        pdf.setTextColor(...COLORS.muted);
        pdf.text(label.toUpperCase(), x + 3, rowY + 3.5);
        pdf.setFontSize(7.5);
        pdf.setFont('helvetica', 'normal');
        pdf.setTextColor(...COLORS.white);
        const truncated = value.length > 30 ? value.slice(0, 28) + '…' : value;
        pdf.text(truncated, x + 3, rowY + 7);
      }
      y += 12;
    }
  }

  // ── Document History ─────────────────────────────────────────────────────────
  const dm = meta as Record<string, unknown> | null | undefined;
  if (dm && (dm['originType'] || (dm['provenanceTimeline'] as unknown[] | undefined)?.length || dm['isMergedDocument'])) {
    checkPage(30);
    y += 4;
    pdf.setDrawColor(...COLORS.border);
    pdf.line(MARGIN, y, PAGE_W - MARGIN, y);
    y += 8;

    pdf.setFontSize(7);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(...COLORS.accent);
    pdf.text('DOCUMENT HISTORY', MARGIN, y);
    y += 6;

    // Origin
    if (dm['originApp'] || dm['originType']) {
      checkPage(14);
      pdf.setFillColor(...COLORS.card);
      pdf.roundedRect(MARGIN, y, CONTENT_W, 12, 2, 2, 'F');
      pdf.setFontSize(6);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(...COLORS.muted);
      pdf.text('ORIGIN', MARGIN + 3, y + 4.5);
      pdf.setFontSize(8);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor(...COLORS.white);
      pdf.text(String(dm['originApp'] ?? 'Unknown'), MARGIN + 3, y + 10);
      if (dm['originType']) {
        pdf.setFontSize(7);
        pdf.setTextColor(...COLORS.accent);
        pdf.text(`[${String(dm['originType']).replace(/-/g,' ').toUpperCase()}]`, MARGIN + 50, y + 10);
      }
      y += 16;
    }

    // Source URL
    if (dm['sourceUrl']) {
      checkPage(12);
      pdf.setFontSize(6);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(...COLORS.muted);
      pdf.text('SOURCE URL', MARGIN, y);
      y += 4;
      pdf.setFontSize(7);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor(...COLORS.accent);
      const urlLines = wrapText(String(dm['sourceUrl']), CONTENT_W, 7);
      pdf.text(urlLines, MARGIN, y);
      y += urlLines.length * 4 + 4;
    }

    // Software chain
    const swChain = dm['softwareChain'] as string[] | undefined;
    if (swChain && swChain.length > 0) {
      checkPage(10 + swChain.length * 6);
      pdf.setFontSize(6);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(...COLORS.muted);
      pdf.text('SOFTWARE CHAIN', MARGIN, y);
      y += 4;
      swChain.forEach((sw, i) => {
        checkPage(7);
        pdf.setFillColor(...COLORS.card);
        pdf.roundedRect(MARGIN, y, CONTENT_W, 6, 1, 1, 'F');
        pdf.setFontSize(6.5);
        pdf.setFont('helvetica', 'normal');
        pdf.setTextColor(...COLORS.muted);
        pdf.text(`${i + 1}`, MARGIN + 2, y + 4.5);
        pdf.setTextColor(...COLORS.white);
        const swTrunc = sw.length > 60 ? sw.slice(0, 58) + '…' : sw;
        pdf.text(swTrunc, MARGIN + 8, y + 4.5);
        y += 8;
      });
      y += 2;
    }

    // Merged components
    const isMerged = dm['isMergedDocument'] as boolean | undefined;
    const components = dm['mergedComponents'] as Array<Record<string,unknown>> | undefined;
    if (isMerged && components && components.length > 0) {
      checkPage(20);
      pdf.setFontSize(6);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(234, 179, 8);
      pdf.text(`ASSEMBLED FROM ${components.length} SOURCE PDFs`, MARGIN, y);
      y += 5;
      components.forEach((comp, i) => {
        const fields = ([
          ['Title',    comp['title']],
          ['Author',   comp['author']],
          ['Creator',  comp['creator']],
          ['Created',  comp['creationDate']],
          ['Doc ID',   comp['documentId']],
        ] as [string, unknown][]).filter(([,v]) => v);
        const blockH = 8 + fields.length * 5;
        checkPage(blockH + 4);
        pdf.setFillColor(16, 20, 30);
        pdf.roundedRect(MARGIN, y, CONTENT_W, blockH, 2, 2, 'F');
        pdf.setDrawColor(234, 179, 8);
        pdf.setLineWidth(0.4);
        pdf.roundedRect(MARGIN, y, CONTENT_W, blockH, 2, 2, 'S');
        pdf.setFontSize(6);
        pdf.setFont('helvetica', 'bold');
        pdf.setTextColor(234, 179, 8);
        pdf.text(`SOURCE #${comp['index'] ?? i + 1}  ·  ${String(comp['detectionMethod'] ?? '')}`, MARGIN + 3, y + 5);
        let fy = y + 9;
        fields.forEach(([label, value]) => {
          pdf.setFont('helvetica', 'bold');
          pdf.setTextColor(...COLORS.muted);
          pdf.text(String(label).toUpperCase(), MARGIN + 3, fy);
          pdf.setFont('helvetica', 'normal');
          pdf.setTextColor(...COLORS.white);
          const vTrunc = String(value).length > 55 ? String(value).slice(0, 53) + '…' : String(value);
          pdf.text(vTrunc, MARGIN + 22, fy);
          fy += 5;
        });
        y += blockH + 4;
      });
    }
  }

  // ── Footer on every page ────────────────────────────────────────────────────
  const totalPages = (pdf as unknown as { internal: { getNumberOfPages(): number } }).internal.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    pdf.setPage(p);
    pdf.setFillColor(...COLORS.accent);
    pdf.rect(0, PAGE_H - 2, PAGE_W, 2, 'F');
    pdf.setFontSize(6);
    pdf.setFont('helvetica', 'normal');
    pdf.setTextColor(...COLORS.muted);
    pdf.text('FORENSIC DOCUMENT EXAMINER  ·  CONFIDENTIAL', MARGIN, PAGE_H - 6);
    pdf.text(`Page ${p} of ${totalPages}`, PAGE_W - MARGIN, PAGE_H - 6, { align: 'right' });
  }

  const safeName = (doc.fileName ?? 'document').replace(/\.pdf$/i, '').replace(/[^a-z0-9]/gi, '_');
  pdf.save(`forensic_report_${safeName}.pdf`);
}

// ── Deep metadata types (mirror server DocumentMetadata) ──────────────────

interface FontInfo { name: string; type: string | null; encoding: string | null; embedded: boolean; subset: boolean; }
interface XmpHistoryEntry { action: string | null; instanceId: string | null; when: string | null; softwareAgent: string | null; changed: string | null; }
interface EmbeddedUrl { url: string; context: string | null; }

interface ProvenanceEvent { timestamp: string | null; event: string; agent: string | null; detail: string | null; }
interface MergedComponent { index: number; title: string | null; author: string | null; creator: string | null; producer: string | null; creationDate: string | null; modificationDate: string | null; documentId: string | null; instanceId: string | null; detectionMethod: string; }

interface DeepMeta {
  sha256?: string | null;
  author?: string | null; creator?: string | null; producer?: string | null;
  creationDate?: string | null; modificationDate?: string | null; pageCount?: number | null;
  fileSize?: number; pdfVersion?: string | null;
  xmpToolkit?: string | null; xmpCreatorTool?: string | null;
  xmpCreateDate?: string | null; xmpModifyDate?: string | null; xmpMetadataDate?: string | null;
  documentId?: string | null; instanceId?: string | null; originalDocumentId?: string | null;
  title?: string | null; subject?: string | null; description?: string | null;
  keywords?: string | null; rights?: string | null; language?: string | null;
  linearized?: boolean | null; tagged?: boolean | null;
  pageLayout?: string | null; pageMode?: string | null; pageSize?: string | null; pdfSecurity?: string | null;
  encrypted?: boolean; encryptionMethod?: string | null; encryptionKeyLength?: number | null; userAccess?: string | null;
  hasDigitalSignature?: boolean; signatureCount?: number;
  incrementalSaveCount?: number; hasJavaScript?: boolean; hasEmbeddedFiles?: boolean;
  hasLaunchActions?: boolean; hasAcroForm?: boolean; hasObjectStreams?: boolean;
  hasXRefStreams?: boolean; hasExternalLinks?: boolean;
  embeddedUrls?: EmbeddedUrl[]; rawObjectCount?: number | null;
  fonts?: FontInfo[]; fontCount?: number; embeddedFontCount?: number; suspectFonts?: string[];
  xmpHistory?: XmpHistoryEntry[]; totalEditSessions?: number;
  exiftoolRaw?: Record<string, unknown> | null;
  // Document History / Provenance
  sourceUrl?: string | null;
  originType?: string | null;
  originApp?: string | null;
  softwareChain?: string[];
  provenanceTimeline?: ProvenanceEvent[];
  // Merged document analysis
  isMergedDocument?: boolean;
  mergedComponents?: MergedComponent[];
  derivedFromId?: string | null;
}

// ── Origin icon helper ─────────────────────────────────────────────────────

function OriginIcon({ type, className }: { type: string | null | undefined; className?: string }) {
  const icons: Record<string, React.ElementType> = {
    'web-download':  Globe,
    'print-to-pdf':  Printer,
    'native-app':    Monitor,
    'cloud-service': Cloud,
    'converted':     Layers,
    'scanned':       ScanLine,
    'unknown':       FileText,
  };
  const Icon = icons[type ?? 'unknown'] ?? FileText;
  return <Icon className={className} />;
}

// ── Document History section ───────────────────────────────────────────────

function DocumentHistorySection({ meta }: { meta: DeepMeta }) {
  const originLabels: Record<string, string> = {
    'web-download':  'Downloaded from the Web',
    'print-to-pdf':  'Printed to PDF',
    'native-app':    'Created in Desktop App',
    'cloud-service': 'Created in Cloud Service',
    'converted':     'Programmatically Converted',
    'scanned':       'Scanned / Imaged',
    'unknown':       'Unknown Origin',
  };

  const timeline    = meta.provenanceTimeline ?? [];
  const swChain     = meta.softwareChain ?? [];
  const isMerged    = meta.isMergedDocument ?? false;
  const components  = meta.mergedComponents ?? [];
  const hasAny      = !!meta.originType || timeline.length > 0 || swChain.length > 0 || isMerged;

  if (!hasAny) return null;

  return (
    <div className="space-y-5">
      {/* Section header */}
      <div className="flex items-center gap-3">
        <div className="h-px flex-1 bg-border" />
        <span className="font-mono text-xs text-muted-foreground uppercase tracking-widest px-3">Document History</span>
        <div className="h-px flex-1 bg-border" />
      </div>

      {/* Merged document alert */}
      {isMerged && (
        <div className="flex items-center gap-3 bg-amber-500/5 border border-amber-500/30 rounded-xl px-5 py-3">
          <GitMerge className="h-5 w-5 text-amber-500 shrink-0" />
          <div>
            <span className="text-sm font-serif text-amber-400">Assembled Document</span>
            <span className="ml-3 text-[11px] font-mono text-amber-500/70">
              {components.length > 1
                ? `${components.length} source PDFs identified inside this document`
                : 'XMP Ingredients marker detected — document was merged from other PDFs'}
            </span>
          </div>
        </div>
      )}

      {/* Three-column cards row */}
      <div className="grid md:grid-cols-3 gap-4">

        {/* Origin card */}
        {meta.originType && (
          <div className="bg-card border border-border rounded-xl p-5 space-y-4 flex flex-col">
            <div className="flex items-center gap-2">
              <OriginIcon type={meta.originType} className="h-4 w-4 text-primary" />
              <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">Origin</span>
            </div>
            <div className="flex-1">
              <div className="text-base font-serif text-foreground leading-tight">
                {meta.originApp ?? 'Unknown'}
              </div>
              <div className="mt-1.5 inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-primary/10 text-primary border border-primary/20">
                {originLabels[meta.originType] ?? meta.originType}
              </div>
            </div>
            {meta.sourceUrl && (
              <div className="pt-3 border-t border-border/50 space-y-1">
                <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">
                  Source URL
                </div>
                <a
                  href={meta.sourceUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-start gap-1.5 text-[11px] font-mono text-primary/80 break-all hover:text-primary transition-colors"
                >
                  <ExternalLink className="h-3 w-3 shrink-0 mt-0.5" />
                  {meta.sourceUrl}
                </a>
              </div>
            )}
            {meta.derivedFromId && (
              <div className="pt-2 border-t border-border/50 space-y-1">
                <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">
                  Derived From
                </div>
                <div className="text-[10px] font-mono text-foreground/60 break-all">
                  {meta.derivedFromId}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Provenance timeline */}
        {timeline.length > 0 && (
          <div className="bg-card border border-border rounded-xl p-5 space-y-3">
            <div className="flex items-center gap-2">
              <History className="h-4 w-4 text-primary" />
              <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">Event Timeline</span>
            </div>
            <div className="relative space-y-0">
              {timeline.map((ev, i) => (
                <div key={i} className="flex gap-3">
                  {/* Timeline rail */}
                  <div className="flex flex-col items-center w-3 shrink-0">
                    <div className={`w-2 h-2 rounded-full shrink-0 mt-1 ${
                      ev.event === 'created' ? 'bg-primary' :
                      ev.event === 'modified' || ev.event === 'saved' ? 'bg-amber-500/80' : 'bg-muted-foreground/40'
                    }`} />
                    {i < timeline.length - 1 && <div className="w-px flex-1 bg-border/50 min-h-[8px]" />}
                  </div>
                  <div className="pb-3 min-w-0">
                    <div className="text-[11px] font-mono text-primary/80 capitalize">{ev.event}</div>
                    {ev.timestamp && (
                      <div className="text-[10px] font-mono text-muted-foreground">{ev.timestamp}</div>
                    )}
                    {ev.agent && (
                      <div className="text-[10px] font-mono text-foreground/60 truncate" title={ev.agent}>
                        {ev.agent}
                      </div>
                    )}
                    {ev.detail && (
                      <div className="text-[10px] text-muted-foreground/50">{ev.detail}</div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Software chain */}
        {swChain.length > 0 && (
          <div className="bg-card border border-border rounded-xl p-5 space-y-3">
            <div className="flex items-center gap-2">
              <Network className="h-4 w-4 text-primary" />
              <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">Software Chain</span>
            </div>
            <div className="space-y-2">
              {swChain.map((sw, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-muted-foreground/50 w-4 shrink-0 text-right">{i + 1}</span>
                  <div
                    className="flex-1 bg-secondary/20 rounded px-3 py-1.5 text-[11px] font-mono text-foreground/80 truncate border border-border/30"
                    title={sw}
                  >
                    {sw}
                  </div>
                </div>
              ))}
            </div>
            <div className="pt-1 text-[10px] font-mono text-muted-foreground/40">
              Listed in chronological order of contact
            </div>
          </div>
        )}
      </div>

      {/* Merged component details */}
      {isMerged && components.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Layers className="h-4 w-4 text-amber-500" />
            <span className="text-sm font-serif text-foreground">Source PDF Components</span>
            <span className="px-2 py-0.5 text-[10px] font-mono bg-amber-500/10 text-amber-500 border border-amber-500/30 rounded ml-1">
              {components.length} detected
            </span>
          </div>
          <div className="grid sm:grid-cols-2 gap-4">
            {components.map((comp, i) => (
              <div key={i} className="bg-card border border-amber-500/20 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono text-amber-400 uppercase tracking-widest">
                    Source #{comp.index}
                  </span>
                  <span className="text-[9px] font-mono text-muted-foreground/50 bg-secondary/20 px-2 py-0.5 rounded">
                    via {comp.detectionMethod === 'xmpIngredients' ? 'XMP Ingredients' : 'Binary Scan'}
                  </span>
                </div>
                <div className="space-y-1.5">
                  {([
                    ['Title',    comp.title],
                    ['Author',   comp.author],
                    ['Creator',  comp.creator],
                    ['Producer', comp.producer],
                    ['Created',  comp.creationDate],
                    ['Modified', comp.modificationDate],
                    ['Doc ID',   comp.documentId],
                  ] as [string, string | null][]).filter(([, v]) => v).map(([label, value]) => (
                    <div key={label} className="flex gap-2 text-[11px] font-mono">
                      <span className="text-muted-foreground w-16 shrink-0">{label}</span>
                      <span className="text-foreground/80 break-all">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Helper sub-components ──────────────────────────────────────────────────

function MetaRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <tr className="hover:bg-secondary/10 border-b border-border/40 last:border-0">
      <td className="py-2 px-4 text-[11px] font-mono text-muted-foreground align-top w-[38%]">{label}</td>
      <td className="py-2 px-4 text-[11px] font-mono text-foreground break-all">{value ?? <span className="text-muted-foreground/40 italic">—</span>}</td>
    </tr>
  );
}

function BoolBadge({ val, label }: { val: boolean | null | undefined; label: string }) {
  if (val == null) return (
    <div className="flex items-center gap-2 px-3 py-2 rounded-md bg-card border border-border/40">
      <Minus className="h-3.5 w-3.5 text-muted-foreground/50 shrink-0" />
      <span className="text-[11px] font-mono text-muted-foreground">{label}</span>
    </div>
  );
  const isAlert = val && ['JavaScript','Launch Action','Embedded File'].some(w => label.includes(w));
  return (
    <div className={`flex items-center gap-2 px-3 py-2 rounded-md border ${
      val
        ? isAlert ? 'bg-destructive/10 border-destructive/30' : 'bg-primary/5 border-primary/20'
        : 'bg-card border-border/40'
    }`}>
      {val
        ? isAlert
          ? <AlertOctagon className="h-3.5 w-3.5 text-destructive shrink-0" />
          : <CheckCircle className="h-3.5 w-3.5 text-primary shrink-0" />
        : <XCircle className="h-3.5 w-3.5 text-muted-foreground/40 shrink-0" />}
      <span className={`text-[11px] font-mono ${val ? isAlert ? 'text-destructive' : 'text-primary' : 'text-muted-foreground/60'}`}>{label}</span>
    </div>
  );
}

function SectionHeader({ icon: Icon, title, count }: { icon: React.ElementType; title: string; count?: number }) {
  return (
    <div className="flex items-center gap-3 border-b border-border pb-3 mb-5">
      <Icon className="h-4 w-4 text-primary" />
      <h3 className="text-base font-serif text-foreground">{title}</h3>
      {count != null && <span className="ml-auto font-mono text-xs text-muted-foreground bg-secondary/30 px-2 py-0.5 rounded">{count}</span>}
    </div>
  );
}

function CollapsibleSection({ title, icon: Icon, defaultOpen = false, children }: {
  title: string; icon: React.ElementType; defaultOpen?: boolean; children: React.ReactNode;
}) {
  const [open, setOpen] = React.useState(defaultOpen);
  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden">
      <button onClick={() => setOpen(v => !v)} className="w-full flex items-center gap-3 px-6 py-4 text-left hover:bg-secondary/10 transition-colors">
        <Icon className="h-4 w-4 text-primary shrink-0" />
        <span className="font-serif text-foreground">{title}</span>
        {open ? <ChevronDown className="h-4 w-4 text-muted-foreground ml-auto" /> : <ChevronRight className="h-4 w-4 text-muted-foreground ml-auto" />}
      </button>
      {open && <div className="px-6 pb-6">{children}</div>}
    </div>
  );
}

function DeepMetadata({ meta }: { meta: DeepMeta }) {
  const [rawOpen, setRawOpen] = React.useState(false);

  const xmpRows: [string, React.ReactNode][] = [
    ['XMP Creator Tool',     meta.xmpCreatorTool],
    ['XMP Toolkit',          meta.xmpToolkit],
    ['XMP Create Date',      meta.xmpCreateDate],
    ['XMP Modify Date',      meta.xmpModifyDate],
    ['XMP Metadata Date',    meta.xmpMetadataDate],
    ['Document GUID',        meta.documentId ? <span className="text-primary/80">{meta.documentId}</span> : null],
    ['Instance ID',          meta.instanceId ? <span className="text-primary/80">{meta.instanceId}</span> : null],
    ['Original Document ID', meta.originalDocumentId],
    ['Title',                meta.title],
    ['Subject',              meta.subject],
    ['Description',          meta.description],
    ['Keywords',             meta.keywords],
    ['Language',             meta.language],
    ['Rights',               meta.rights],
    ['Page Layout',          meta.pageLayout],
    ['Page Mode',            meta.pageMode],
    ['Page Size',            meta.pageSize],
    ['PDF Security',         meta.pdfSecurity],
    ['Linearized',           meta.linearized != null ? String(meta.linearized) : null],
    ['Tagged PDF',           meta.tagged != null ? String(meta.tagged) : null],
    ['Encryption Method',    meta.encryptionMethod],
    ['User Access',          meta.userAccess],
    ['Approx. Object Count', meta.rawObjectCount],
  ].filter(([, v]) => v != null) as [string, React.ReactNode][];

  return (
    <div className="space-y-4 pt-4">
      <div className="flex items-center gap-3 pt-4 mb-2">
        <div className="h-px flex-1 bg-border" />
        <span className="font-mono text-xs text-muted-foreground uppercase tracking-widest px-3">Deep Forensic Analysis</span>
        <div className="h-px flex-1 bg-border" />
      </div>

      {/* ── XMP + Extended Metadata ─────────────────────────────── */}
      {xmpRows.length > 0 && (
        <CollapsibleSection title="XMP & Extended Metadata" icon={Database} defaultOpen>
          <table className="w-full">
            <tbody>{xmpRows.map(([k, v]) => <MetaRow key={k} label={k} value={v} />)}</tbody>
          </table>
        </CollapsibleSection>
      )}

      {/* ── Structural Analysis ─────────────────────────────────── */}
      <CollapsibleSection title="Structural Analysis" icon={Shield} defaultOpen>
        <div className="space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            <BoolBadge val={meta.hasJavaScript} label="JavaScript (/JS)" />
            <BoolBadge val={meta.hasLaunchActions} label="Launch Action" />
            <BoolBadge val={meta.hasEmbeddedFiles} label="Embedded File" />
            <BoolBadge val={meta.hasAcroForm} label="AcroForm Fields" />
            <BoolBadge val={meta.hasObjectStreams} label="Object Streams" />
            <BoolBadge val={meta.hasXRefStreams} label="XRef Streams" />
            <BoolBadge val={meta.hasDigitalSignature} label="Digital Signature" />
            <BoolBadge val={meta.linearized} label="Linearized (web)" />
            <BoolBadge val={meta.encrypted} label="Encrypted" />
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 pt-2">
            {[
              ['Incremental Saves', meta.incrementalSaveCount != null ? `${meta.incrementalSaveCount} additional save${meta.incrementalSaveCount !== 1 ? 's' : ''}` : null],
              ['Signatures', meta.signatureCount != null ? `${meta.signatureCount} found` : null],
              ['Objects', meta.rawObjectCount != null ? `~${meta.rawObjectCount} objects` : null],
              ['Total Edit Sessions', meta.totalEditSessions != null ? `${meta.totalEditSessions} recorded` : null],
              ['Embedded URLs', meta.embeddedUrls?.length != null ? `${meta.embeddedUrls.length} found` : null],
            ].filter(([, v]) => v != null).map(([label, value]) => (
              <div key={label as string} className="bg-secondary/10 rounded-lg p-3 border border-border/40">
                <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-1">{label}</div>
                <div className="text-sm font-mono text-foreground">{value as string}</div>
              </div>
            ))}
          </div>
        </div>
      </CollapsibleSection>

      {/* ── Font Analysis ─────────────────────────────────────────── */}
      {(meta.fonts?.length ?? 0) > 0 && (
        <CollapsibleSection title={`Font Analysis (${meta.fontCount} fonts, ${meta.embeddedFontCount} embedded)`} icon={Type} defaultOpen>
          <div className="overflow-x-auto">
            <table className="w-full text-[11px] font-mono">
              <thead>
                <tr className="border-b border-border text-muted-foreground">
                  <th className="text-left py-2 px-3 font-normal">Font Name</th>
                  <th className="text-left py-2 px-3 font-normal">Type</th>
                  <th className="text-left py-2 px-3 font-normal">Encoding</th>
                  <th className="text-left py-2 px-3 font-normal">Embedded</th>
                  <th className="text-left py-2 px-3 font-normal">Subset</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/30">
                {meta.fonts?.map((f, i) => (
                  <tr key={i} className={`hover:bg-secondary/10 ${meta.suspectFonts?.includes(f.name) ? 'bg-destructive/5' : ''}`}>
                    <td className="py-2 px-3 text-foreground">
                      {meta.suspectFonts?.includes(f.name) && <AlertOctagon className="h-3 w-3 text-destructive inline mr-1.5" />}
                      {f.name}
                    </td>
                    <td className="py-2 px-3 text-muted-foreground">{f.type ?? '—'}</td>
                    <td className="py-2 px-3 text-muted-foreground">{f.encoding ?? '—'}</td>
                    <td className="py-2 px-3">
                      {f.embedded ? <CheckCircle className="h-3.5 w-3.5 text-primary" /> : <XCircle className="h-3.5 w-3.5 text-muted-foreground/40" />}
                    </td>
                    <td className="py-2 px-3">
                      {f.subset ? <CheckCircle className="h-3.5 w-3.5 text-primary" /> : <XCircle className="h-3.5 w-3.5 text-muted-foreground/40" />}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CollapsibleSection>
      )}

      {/* ── XMP Edit History ──────────────────────────────────────── */}
      {(meta.xmpHistory?.length ?? 0) > 0 && (
        <CollapsibleSection title={`XMP Edit History (${meta.xmpHistory?.length} sessions)`} icon={Clock} defaultOpen>
          <div className="space-y-2">
            {meta.xmpHistory?.map((h, i) => (
              <div key={i} className="bg-secondary/10 border border-border/40 rounded-lg p-3 text-[11px] font-mono grid grid-cols-2 gap-x-4 gap-y-1">
                {h.when        && <><span className="text-muted-foreground">When</span><span className="text-foreground">{h.when}</span></>}
                {h.action      && <><span className="text-muted-foreground">Action</span><span className="text-primary/80">{h.action}</span></>}
                {h.softwareAgent && <><span className="text-muted-foreground">Software</span><span className="text-foreground col-span-1 truncate" title={h.softwareAgent}>{h.softwareAgent}</span></>}
                {h.instanceId  && <><span className="text-muted-foreground">Instance ID</span><span className="text-foreground/60 truncate text-[10px]">{h.instanceId}</span></>}
                {h.changed     && <><span className="text-muted-foreground">Changed</span><span className="text-foreground">{h.changed}</span></>}
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* ── Embedded URLs ─────────────────────────────────────────── */}
      {(meta.embeddedUrls?.length ?? 0) > 0 && (
        <CollapsibleSection title={`Embedded URLs (${meta.embeddedUrls?.length})`} icon={Link2}>
          <div className="space-y-1.5">
            {meta.embeddedUrls?.map((u, i) => (
              <div key={i} className="flex items-center gap-2 bg-secondary/10 border border-border/40 rounded px-3 py-2">
                <Link2 className="h-3 w-3 text-primary shrink-0" />
                <span className="text-[11px] font-mono text-foreground/80 break-all">{u.url}</span>
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* ── Raw ExifTool Dump ─────────────────────────────────────── */}
      {meta.exiftoolRaw && Object.keys(meta.exiftoolRaw).length > 0 && (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <button onClick={() => setRawOpen(v => !v)} className="w-full flex items-center gap-3 px-6 py-4 text-left hover:bg-secondary/10 transition-colors">
            <Code2 className="h-4 w-4 text-muted-foreground shrink-0" />
            <span className="font-serif text-muted-foreground">Raw ExifTool Output</span>
            <span className="ml-2 font-mono text-xs text-muted-foreground/60">({Object.keys(meta.exiftoolRaw).length} fields)</span>
            {rawOpen ? <ChevronDown className="h-4 w-4 text-muted-foreground ml-auto" /> : <ChevronRight className="h-4 w-4 text-muted-foreground ml-auto" />}
          </button>
          {rawOpen && (
            <div className="px-6 pb-6 max-h-96 overflow-y-auto">
              <table className="w-full">
                <tbody className="divide-y divide-border/20">
                  {Object.entries(meta.exiftoolRaw).map(([k, v]) => {
                    const display = typeof v === 'object' && v !== null && 'val' in v
                      ? String((v as { val: unknown }).val)
                      : String(v ?? '');
                    return display ? (
                      <tr key={k} className="hover:bg-secondary/5">
                        <td className="py-1.5 px-3 text-[10px] font-mono text-muted-foreground/70 w-[40%] align-top">{k}</td>
                        <td className="py-1.5 px-3 text-[10px] font-mono text-foreground/70 break-all">{display}</td>
                      </tr>
                    ) : null;
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ResultsPage() {
  const { id } = useParams();
  const docId = id ? parseInt(id, 10) : null;
  const [, setLocation] = useLocation();
  const { toast } = useToast();

  const { data: doc, isLoading, isError } = useGetDocument(docId as number, {
    query: {
      enabled: docId !== null,
      queryKey: getGetDocumentQueryKey(docId as number),
      refetchInterval: (query) => {
        // According to instructions: poll if status is pending or analyzing
        const status = query.state?.data?.status;
        if (status === 'pending' || status === 'analyzing') {
          return 2000;
        }
        return false;
      }
    }
  });

  const reanalyzeMutation = useReanalyzeDocument();
  const deleteMutation = useDeleteDocument();
  const [isDownloading, setIsDownloading] = React.useState(false);
  const [hashCopied, setHashCopied] = React.useState(false);

  // ── Chat state ────────────────────────────────────────────────────────────
  type ChatMsg = { role: 'user' | 'assistant'; content: string };
  const [chatMessages, setChatMessages] = React.useState<ChatMsg[]>([]);
  const [chatInput, setChatInput] = React.useState('');
  const [chatLoading, setChatLoading] = React.useState(false);
  const chatBottomRef = React.useRef<HTMLDivElement>(null);
  const chatInputRef = React.useRef<HTMLTextAreaElement>(null);

  const sendChat = async () => {
    if (!chatInput.trim() || chatLoading || !docId) return;
    const question = chatInput.trim();
    setChatInput('');
    const newHistory: ChatMsg[] = [...chatMessages, { role: 'user', content: question }];
    setChatMessages(newHistory);
    setChatLoading(true);
    try {
      const resp = await fetch(`/api/documents/${docId}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question, history: chatMessages }),
      });
      const data = await resp.json();
      setChatMessages([...newHistory, { role: 'assistant', content: data.answer ?? 'No response received.' }]);
    } catch {
      setChatMessages([...newHistory, { role: 'assistant', content: 'Failed to get a response. Please try again.' }]);
    } finally {
      setChatLoading(false);
      setTimeout(() => chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
    }
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash).then(() => {
      setHashCopied(true);
      setTimeout(() => setHashCopied(false), 2000);
    });
  };

  const handleDownload = async () => {
    if (!doc) return;
    setIsDownloading(true);
    try {
      await downloadForensicReport(doc);
    } finally {
      setIsDownloading(false);
    }
  };

  const handleReanalyze = () => {
    if (!docId) return;
    reanalyzeMutation.mutate({ id: docId }, {
      onSuccess: () => {
        toast({
          title: 'Re-analysis initiated',
          description: 'The document has been queued for a fresh analysis cycle.',
        });
      }
    });
  };

  const handleDelete = () => {
    if (!docId) return;
    deleteMutation.mutate({ id: docId }, {
      onSuccess: () => {
        toast({
          title: 'Record deleted',
          description: 'The analysis record has been removed.',
        });
        setLocation('/history');
      }
    });
  };

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
        <Loader2 className="h-10 w-10 text-primary animate-spin" />
        <p className="font-mono text-muted-foreground uppercase tracking-widest text-sm">Retrieving case file...</p>
      </div>
    );
  }

  if (isError || !doc) {
    return (
      <div className="max-w-4xl mx-auto py-12 px-6 text-center">
        <div className="bg-destructive/10 border border-destructive/20 text-destructive p-8 rounded-lg space-y-4">
          <AlertTriangle className="h-10 w-10 mx-auto opacity-80" />
          <h2 className="text-xl font-semibold">Case File Not Found</h2>
          <p className="text-sm">The requested analysis record could not be retrieved or has been deleted.</p>
          <Button variant="outline" className="mt-4 border-destructive text-destructive hover:bg-destructive hover:text-white" onClick={() => setLocation('/history')}>
            Return to History
          </Button>
        </div>
      </div>
    );
  }

  const isProcessing = doc.status === 'pending' || doc.status === 'analyzing';
  const isExplorationMode = !doc.claimedIdentity?.trim();
  const sha256 = (doc.metadata as DeepMeta | null)?.sha256 ?? null;

  return (
    <div className="max-w-5xl mx-auto py-8 px-6 space-y-12 pb-24">

      {/* ── SHA-256 Hash — very top ──────────────────────────────────────── */}
      {doc.status === 'complete' && (
        <div className={`flex items-center gap-4 rounded-xl px-5 py-3 border ${
          sha256
            ? 'bg-card border-primary/25'
            : 'bg-card border-border/50'
        }`}>
          <div className="flex items-center gap-2 shrink-0">
            <Fingerprint className="h-4 w-4 text-primary" />
            <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">SHA-256</span>
          </div>
          {sha256 ? (
            <>
              <span className="flex-1 font-mono text-[12px] text-primary/90 select-all break-all leading-relaxed">
                {sha256}
              </span>
              <button
                onClick={() => handleCopyHash(sha256)}
                className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-mono uppercase tracking-wider border transition-all duration-150 border-primary/30 text-primary hover:bg-primary/10 active:scale-95"
              >
                {hashCopied
                  ? <><CheckCircle className="h-3 w-3 mr-1" />Copied</>
                  : <><Database className="h-3 w-3 mr-1" />Copy</>}
              </button>
            </>
          ) : (
            <span className="flex-1 font-mono text-[12px] text-muted-foreground/50 italic">
              Hash not computed — hit Re-run to generate
            </span>
          )}
        </div>
      )}

      {/* Header / Actions */}
      <div className="flex items-center justify-between">
        <Link href="/history" className="text-muted-foreground hover:text-foreground inline-flex items-center gap-2 text-sm font-medium transition-colors">
          <ArrowLeft className="h-4 w-4" />
          Back to History
        </Link>
        <div className="flex items-center gap-3">
          {!isProcessing && doc?.status === 'complete' && (
            <Button
              variant="outline"
              size="sm"
              onClick={handleDownload}
              disabled={isDownloading}
              className="font-mono text-xs uppercase tracking-wider h-8 border-primary/40 text-primary hover:bg-primary/10"
            >
              {isDownloading
                ? <Loader2 className="h-3.5 w-3.5 mr-2 animate-spin" />
                : <Download className="h-3.5 w-3.5 mr-2" />}
              Download Report
            </Button>
          )}
          <Button 
            variant="outline" 
            size="sm" 
            onClick={handleReanalyze} 
            disabled={isProcessing || reanalyzeMutation.isPending}
            className="font-mono text-xs uppercase tracking-wider h-8"
          >
            <RefreshCcw className={`h-3.5 w-3.5 mr-2 ${reanalyzeMutation.isPending ? 'animate-spin' : ''}`} />
            Re-run
          </Button>
          <Button 
            variant="destructive" 
            size="sm" 
            onClick={handleDelete}
            disabled={deleteMutation.isPending}
            className="font-mono text-xs uppercase tracking-wider h-8 bg-destructive/20 text-destructive hover:bg-destructive hover:text-white border-none"
          >
            <Trash2 className="h-3.5 w-3.5 mr-2" />
            Delete
          </Button>
        </div>
      </div>

      {isProcessing ? (
        <div className="bg-card border border-border rounded-xl p-16 flex flex-col items-center justify-center space-y-6">
          <div className="relative">
            <div className="absolute inset-0 bg-primary/20 blur-xl rounded-full" />
            <Loader2 className="h-16 w-16 text-primary animate-spin relative z-10" />
          </div>
          <div className="text-center space-y-2">
            <h2 className="text-2xl font-serif text-foreground">Analysis in Progress</h2>
            <p className="text-muted-foreground font-mono text-sm max-w-md mx-auto">
              Extracting metadata, examining file structure, and executing forensic heuristics. This may take a moment.
            </p>
          </div>
        </div>
      ) : doc.status === 'error' ? (
        <div className="bg-destructive/5 border border-destructive/20 rounded-xl p-10 flex flex-col items-center text-center space-y-4">
          <div className="bg-destructive/10 p-4 rounded-full">
            <AlertTriangle className="h-8 w-8 text-destructive" />
          </div>
          <h2 className="text-2xl font-serif text-foreground">Analysis Failed</h2>
          <p className="text-muted-foreground max-w-md">{doc.errorMessage || 'An unknown error occurred during the analysis process.'}</p>
        </div>
      ) : (
        <div className="space-y-12">
          {/* Verdict / Exploration Block */}
          <div className="relative overflow-hidden rounded-xl border border-border bg-card p-1">
            <div className={`absolute inset-0 opacity-[0.03] ${
              isExplorationMode ? 'bg-primary' :
              doc.verdict === 'authentic' ? 'bg-authentic' :
              doc.verdict === 'likely_forged' ? 'bg-forged' :
              doc.verdict === 'suspicious' ? 'bg-suspicious' : 'bg-foreground'
            }`} />
            
            <div className="relative p-10 text-center flex flex-col items-center">
              {isExplorationMode ? (
                <>
                  <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground mb-4">Analysis Mode</span>
                  <div className="mb-6 flex items-center gap-2 px-6 py-2 rounded-lg border border-primary/40 bg-primary/10">
                    <ScanLine className="h-5 w-5 text-primary" />
                    <span className="text-xl font-bold font-serif tracking-widest text-primary uppercase">Exploration Mode</span>
                  </div>
                  <p className="text-sm text-muted-foreground font-mono max-w-lg">
                    No identity claim provided. The engine has cataloged all metadata, software, and structural signals without judging against a specific claim.
                  </p>
                </>
              ) : (
                <>
                  <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground mb-4">Official Verdict</span>
                  <div className="mb-6">
                    <VerdictBadge verdict={doc.verdict} className="px-6 py-2 text-xl font-bold font-serif tracking-widest" />
                  </div>
                  <div className="flex items-center gap-12 mt-4 text-center">
                    <div className="flex flex-col items-center">
                      <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-1">Confidence Score</span>
                      <div className="text-4xl font-light font-mono text-foreground flex items-baseline">
                        {doc.confidenceScore}<span className="text-lg text-muted-foreground ml-1">%</span>
                      </div>
                    </div>
                  </div>
                </>
              )}

              {doc.summary && (
                <div className="mt-10 max-w-2xl text-lg text-foreground font-serif leading-relaxed border-t border-border/50 pt-8">
                  &ldquo;{doc.summary}&rdquo;
                </div>
              )}
            </div>
          </div>

          {/* Details Grid */}
          <div className="grid md:grid-cols-3 gap-8">
            
            {/* Findings */}
            <div className="md:col-span-2 space-y-6">
              <div className="flex items-center gap-3 border-b border-border pb-4">
                <Fingerprint className="h-5 w-5 text-primary" />
                <h3 className="text-xl font-serif text-foreground">Forensic Findings</h3>
              </div>
              <FindingsList findings={doc.findings || []} />
            </div>

            {/* Evidence details & Metadata */}
            <div className="space-y-8">
              <div className="space-y-6">
                <div className="flex items-center gap-3 border-b border-border pb-4">
                  <FileText className="h-5 w-5 text-primary" />
                  <h3 className="text-xl font-serif text-foreground">Evidence Record</h3>
                </div>
                
                <div className="bg-card border border-border rounded-lg p-5 space-y-4">
                  <div>
                    <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest block mb-1">
                      {doc.claimedIdentity?.trim() ? 'Claimed Identity' : 'Analysis Mode'}
                    </span>
                    {doc.claimedIdentity?.trim()
                      ? <p className="text-sm text-foreground">{doc.claimedIdentity}</p>
                      : <p className="text-sm text-primary font-mono">Exploration Mode — no claim provided</p>
                    }
                  </div>
                  <div className="grid grid-cols-2 gap-4 pt-4 border-t border-border/50">
                    <div>
                      <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest block mb-1">Filename</span>
                      <p className="text-sm text-foreground truncate" title={doc.fileName}>{doc.fileName}</p>
                    </div>
                    <div>
                      <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest block mb-1">File Size</span>
                      <p className="text-sm font-mono text-foreground">{(doc.fileSize / 1024).toFixed(1)} KB</p>
                    </div>
                  </div>
                </div>
              </div>

              {doc.metadata && (
                <div className="space-y-6">
                  <div className="flex items-center gap-3 border-b border-border pb-4">
                    <FileKey className="h-5 w-5 text-primary" />
                    <h3 className="text-xl font-serif text-foreground">PDF Identity</h3>
                  </div>
                  <div className="bg-card border border-border rounded-lg overflow-hidden text-sm">
                    <table className="w-full text-left font-mono">
                      <tbody className="divide-y divide-border/50">
                        {((): [string, string | number | null | undefined][] => {
                          const m = doc.metadata as DeepMeta;
                          return [
                            ['Author',    m.author],
                            ['Creator',   m.creator],
                            ['Producer',  m.producer],
                            ['XMP Tool',  m.xmpCreatorTool],
                            ['Created',   m.creationDate],
                            ['Modified',  m.modificationDate],
                            ['Pages',     m.pageCount],
                            ['Version',   m.pdfVersion],
                            ['Size',      `${((m.fileSize ?? 0) / 1024).toFixed(1)} KB`],
                          ];
                        })().map(([key, value]) => (
                          <tr key={key} className="hover:bg-secondary/10">
                            <td className="py-2 px-4 text-muted-foreground w-[40%] text-[11px]">{key}</td>
                            <td className="py-2 px-4 text-foreground truncate max-w-[140px] text-[11px]" title={String(value ?? '—')}>
                              {value != null && value !== '' ? String(value) : <span className="text-muted-foreground/40 italic">—</span>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* ── Document History ──────────────────────────────────────────── */}
          {doc.metadata && <DocumentHistorySection meta={doc.metadata as DeepMeta} />}

          {/* ── Deep Forensic Layers ────────────────────────────────────── */}
          {doc.metadata && <DeepMetadata meta={doc.metadata as DeepMeta} />}

          {/* ── Document Q&A ─────────────────────────────────────────────── */}
          <div className="rounded-xl border border-border bg-card overflow-hidden">
            <div className="flex items-center gap-3 px-6 py-4 border-b border-border bg-card">
              <MessageSquare className="h-5 w-5 text-primary" />
              <h3 className="text-xl font-serif text-foreground">Query This Document</h3>
              <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest ml-auto">AI Deep Dive</span>
            </div>

            {/* Message history */}
            {chatMessages.length > 0 && (
              <div className="px-6 py-4 space-y-4 max-h-[520px] overflow-y-auto border-b border-border">
                {chatMessages.map((msg, i) => (
                  <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                    {msg.role === 'assistant' && (
                      <div className="shrink-0 h-7 w-7 rounded-full bg-primary/20 flex items-center justify-center mt-0.5">
                        <Bot className="h-3.5 w-3.5 text-primary" />
                      </div>
                    )}
                    <div className={`max-w-[80%] rounded-xl px-4 py-3 text-sm leading-relaxed whitespace-pre-wrap ${
                      msg.role === 'user'
                        ? 'bg-primary/15 text-foreground border border-primary/20'
                        : 'bg-secondary/30 text-foreground border border-border/50'
                    }`}>
                      {msg.content}
                    </div>
                    {msg.role === 'user' && (
                      <div className="shrink-0 h-7 w-7 rounded-full bg-secondary flex items-center justify-center mt-0.5">
                        <UserIcon className="h-3.5 w-3.5 text-muted-foreground" />
                      </div>
                    )}
                  </div>
                ))}
                {chatLoading && (
                  <div className="flex gap-3 justify-start">
                    <div className="shrink-0 h-7 w-7 rounded-full bg-primary/20 flex items-center justify-center">
                      <Bot className="h-3.5 w-3.5 text-primary" />
                    </div>
                    <div className="bg-secondary/30 border border-border/50 rounded-xl px-4 py-3 flex items-center gap-2">
                      <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />
                      <span className="text-sm text-muted-foreground font-mono">Analyzing…</span>
                    </div>
                  </div>
                )}
                <div ref={chatBottomRef} />
              </div>
            )}

            {/* Input */}
            <div className="px-6 py-4">
              {chatMessages.length === 0 && (
                <div className="mb-4 flex flex-wrap gap-2">
                  {[
                    'Who created this document and with what software?',
                    'What does page 1 contain?',
                    'Is there any evidence of tampering?',
                    'Summarize the document timeline',
                  ].map(suggestion => (
                    <button
                      key={suggestion}
                      onClick={() => { setChatInput(suggestion); chatInputRef.current?.focus(); }}
                      className="text-[11px] font-mono px-3 py-1.5 rounded-lg border border-border/60 text-muted-foreground hover:border-primary/40 hover:text-primary transition-colors"
                    >
                      {suggestion}
                    </button>
                  ))}
                </div>
              )}
              <div className="flex gap-3 items-end">
                <textarea
                  ref={chatInputRef}
                  value={chatInput}
                  onChange={e => setChatInput(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); } }}
                  placeholder="Ask anything about this document — specific pages, metadata, authorship, timeline…"
                  rows={2}
                  className="flex-1 resize-none rounded-lg bg-background border border-border px-4 py-3 text-sm font-mono text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/50 transition-colors"
                />
                <button
                  onClick={sendChat}
                  disabled={chatLoading || !chatInput.trim()}
                  className="shrink-0 h-10 w-10 rounded-lg bg-primary text-primary-foreground flex items-center justify-center hover:bg-primary/90 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                >
                  {chatLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                </button>
              </div>
              <p className="text-[10px] text-muted-foreground/50 font-mono mt-2">Enter to send · Shift+Enter for newline</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

