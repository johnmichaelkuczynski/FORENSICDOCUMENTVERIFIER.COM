import React from 'react';
import { useParams, useLocation } from 'wouter';
import { useGetDocument, getGetDocumentQueryKey, useReanalyzeDocument, useDeleteDocument, type DocumentAnalysis } from '@workspace/api-client-react';
import { VerdictBadge } from '@/components/VerdictBadge';
import { FindingsList } from '@/components/FindingsList';
import { Loader2, RefreshCcw, Trash2, ArrowLeft, FileText, Calendar, Hash, FileKey, Fingerprint, AlertTriangle, Download } from 'lucide-react';
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

  const metaRows: [string, string][] = [
    ['Claimed Identity', doc.claimedIdentity ?? '—'],
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
    if (confirm('Are you sure you want to permanently delete this analysis record?')) {
      deleteMutation.mutate({ id: docId }, {
        onSuccess: () => {
          toast({
            title: 'Record deleted',
            description: 'The analysis record has been removed.',
          });
          setLocation('/history');
        }
      });
    }
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

  return (
    <div className="max-w-5xl mx-auto py-8 px-6 space-y-12 pb-24">
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
          {/* Verdict Block */}
          <div className="relative overflow-hidden rounded-xl border border-border bg-card p-1">
            <div className={`absolute inset-0 opacity-[0.03] ${
              doc.verdict === 'authentic' ? 'bg-authentic' :
              doc.verdict === 'likely_forged' ? 'bg-forged' :
              doc.verdict === 'suspicious' ? 'bg-suspicious' : 'bg-foreground'
            }`} />
            
            <div className="relative p-10 text-center flex flex-col items-center">
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
                    <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest block mb-1">Claimed Identity</span>
                    <p className="text-sm text-foreground">{doc.claimedIdentity}</p>
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
                    <h3 className="text-xl font-serif text-foreground">Extracted Metadata</h3>
                  </div>
                  
                  <div className="bg-card border border-border rounded-lg overflow-hidden text-sm">
                    <table className="w-full text-left font-mono">
                      <tbody className="divide-y divide-border/50">
                        {Object.entries({
                          Author: doc.metadata.author,
                          Creator: doc.metadata.creator,
                          Producer: doc.metadata.producer,
                          Created: doc.metadata.creationDate,
                          Modified: doc.metadata.modificationDate,
                          Pages: doc.metadata.pageCount,
                          Version: doc.metadata.pdfVersion,
                        }).map(([key, value]) => (
                          <tr key={key} className="hover:bg-secondary/10">
                            <td className="py-2.5 px-4 text-muted-foreground w-1/3">{key}</td>
                            <td className="py-2.5 px-4 text-foreground truncate max-w-[150px]" title={String(value || 'N/A')}>
                              {value || <span className="text-muted-foreground/50 italic">Null</span>}
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
        </div>
      )}
    </div>
  );
}

