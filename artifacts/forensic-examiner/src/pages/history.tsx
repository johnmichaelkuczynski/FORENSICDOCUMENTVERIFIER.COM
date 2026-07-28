import React from 'react';
import { useListDocuments, useGetDocumentStats, useDeleteDocument, getListDocumentsQueryKey, getGetDocumentStatsQueryKey } from '@workspace/api-client-react';
import { VerdictBadge } from '@/components/VerdictBadge';
import { format } from 'date-fns';
import { Link } from 'wouter';
import { Trash2, FileText, Loader2, ArrowRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import { useQueryClient } from '@tanstack/react-query';

export default function HistoryPage() {
  const { data: documents, isLoading } = useListDocuments();
  const { data: stats } = useGetDocumentStats();
  const deleteMutation = useDeleteDocument();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const handleDelete = async (id: number, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    
    if (confirm('Are you sure you want to permanently delete this analysis record?')) {
      deleteMutation.mutate({ id }, {
        onSuccess: () => {
          queryClient.invalidateQueries({ queryKey: getListDocumentsQueryKey() });
          queryClient.invalidateQueries({ queryKey: getGetDocumentStatsQueryKey() });
          toast({
            title: 'Record Deleted',
            description: 'The analysis record has been removed.',
          });
        },
        onError: () => {
          toast({
            title: 'Error',
            description: 'Failed to delete the record.',
            variant: 'destructive',
          });
        }
      });
    }
  };

  return (
    <div className="max-w-6xl mx-auto py-12 px-6 space-y-12">
      <div>
        <h1 className="text-4xl font-serif tracking-tight text-foreground mb-4">
          Case History
        </h1>
        <p className="text-muted-foreground font-mono text-sm">
          Archive of past documentary evidence analyses.
        </p>
      </div>

      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="bg-card border border-border p-4 rounded-lg flex flex-col">
            <span className="text-xs font-mono text-muted-foreground uppercase tracking-wider mb-2">Total Analyses</span>
            <span className="text-3xl font-light font-serif">{stats.total}</span>
          </div>
          <div className="bg-card border border-border p-4 rounded-lg flex flex-col">
            <span className="text-xs font-mono text-muted-foreground uppercase tracking-wider mb-2 text-authentic">Strong Match</span>
            <span className="text-3xl font-light font-serif">{stats.byVerdict.strong_match || 0}</span>
          </div>
          <div className="bg-card border border-border p-4 rounded-lg flex flex-col">
            <span className="text-xs font-mono text-muted-foreground uppercase tracking-wider mb-2 text-primary">Partial Match</span>
            <span className="text-3xl font-light font-serif">{(stats.byVerdict.partial_match || 0) + (stats.byVerdict.weak_match || 0)}</span>
          </div>
          <div className="bg-card border border-border p-4 rounded-lg flex flex-col">
            <span className="text-xs font-mono text-muted-foreground uppercase tracking-wider mb-2 text-forged">Inconsistent</span>
            <span className="text-3xl font-light font-serif">{stats.byVerdict.inconsistent || 0}</span>
          </div>
          <div className="bg-card border border-border p-4 rounded-lg flex flex-col">
            <span className="text-xs font-mono text-muted-foreground uppercase tracking-wider mb-2">Inconclusive</span>
            <span className="text-3xl font-light font-serif">{stats.byVerdict.inconclusive || 0}</span>
          </div>
        </div>
      )}

      <div className="border border-border rounded-lg overflow-hidden bg-card">
        {isLoading ? (
          <div className="p-12 flex justify-center items-center">
            <Loader2 className="h-8 w-8 text-muted-foreground animate-spin" />
          </div>
        ) : documents?.length === 0 ? (
          <div className="p-16 text-center flex flex-col items-center">
            <FileText className="h-12 w-12 text-muted-foreground mb-4 opacity-50" />
            <h3 className="text-lg font-medium text-foreground mb-2">No records found</h3>
            <p className="text-sm text-muted-foreground max-w-sm">
              Your case history is empty. Upload a new document to begin your first forensic analysis.
            </p>
          </div>
        ) : (
          <table className="w-full text-sm text-left">
            <thead className="bg-secondary/30 text-xs uppercase font-mono text-muted-foreground border-b border-border">
              <tr>
                <th className="px-6 py-4 font-medium tracking-wider">Document</th>
                <th className="px-6 py-4 font-medium tracking-wider">Date</th>
                <th className="px-6 py-4 font-medium tracking-wider">Status / Verdict</th>
                <th className="px-6 py-4 font-medium tracking-wider text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {documents?.map((doc) => (
                <tr key={doc.id} className="hover:bg-secondary/10 transition-colors group">
                  <td className="px-6 py-4">
                    <Link href={`/results/${doc.id}`} className="block">
                      <div className="font-medium text-foreground mb-1 group-hover:text-primary transition-colors flex items-center gap-2">
                        {doc.fileName}
                      </div>
                      <div className="text-xs text-muted-foreground truncate max-w-md" title={doc.claimedIdentity}>
                        Claim: {doc.claimedIdentity}
                      </div>
                    </Link>
                  </td>
                  <td className="px-6 py-4 text-muted-foreground font-mono">
                    {format(new Date(doc.createdAt), 'yyyy-MM-dd HH:mm')}
                  </td>
                  <td className="px-6 py-4">
                    {doc.status === 'complete' ? (
                      <VerdictBadge verdict={doc.verdict} />
                    ) : (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-sm text-xs font-mono font-medium bg-secondary text-muted-foreground border border-border">
                        {doc.status === 'error' ? 'ERROR' : 'PROCESSING...'}
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <Button 
                        variant="ghost" 
                        size="icon" 
                        className="h-8 w-8 text-destructive hover:text-destructive hover:bg-destructive/10"
                        onClick={(e) => handleDelete(doc.id, e)}
                        data-testid={`button-delete-${doc.id}`}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                      <Link href={`/results/${doc.id}`}>
                        <Button 
                          variant="secondary" 
                          size="icon"
                          className="h-8 w-8"
                          data-testid={`link-results-${doc.id}`}
                        >
                          <ArrowRight className="h-4 w-4" />
                        </Button>
                      </Link>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
