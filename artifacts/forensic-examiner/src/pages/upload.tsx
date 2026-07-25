import React, { useRef, useState, useCallback } from 'react';
import { useLocation } from 'wouter';
import { Upload, FileText, AlertCircle, Loader2 } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

export default function UploadPage() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [file, setFile] = useState<File | null>(null);
  const [claimedIdentity, setClaimedIdentity] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const droppedFile = e.dataTransfer.files[0];
      if (droppedFile.type === 'application/pdf') {
        setFile(droppedFile);
      } else {
        toast({
          title: 'Invalid file type',
          description: 'Only PDF documents are supported for forensic analysis.',
          variant: 'destructive',
        });
      }
    }
  }, [toast]);

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      toast({
        title: 'Missing evidence',
        description: 'Please upload a document to analyze.',
        variant: 'destructive',
      });
      return;
    }
    if (!claimedIdentity.trim()) {
      toast({
        title: 'Missing identity claim',
        description: 'Please describe what this document claims to be.',
        variant: 'destructive',
      });
      return;
    }

    setIsUploading(true);
    try {
      const fd = new FormData();
      fd.append('file', file);
      fd.append('claimedIdentity', claimedIdentity);
      
      const response = await fetch('/api/documents/analyze', {
        method: 'POST',
        body: fd,
      });
      
      if (!response.ok) {
        throw new Error('Analysis submission failed');
      }
      
      const result = await response.json();
      setLocation(`/results/${result.id}`);
    } catch (error) {
      toast({
        title: 'Submission Error',
        description: 'Failed to submit document to the analysis engine.',
        variant: 'destructive',
      });
      setIsUploading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-12 px-6">
      <div className="mb-10">
        <h1 className="text-4xl font-serif tracking-tight text-foreground mb-4">
          Initiate Forensic Analysis
        </h1>
        <p className="text-muted-foreground text-lg max-w-2xl font-mono text-sm leading-relaxed">
          Upload documentary evidence to verify authenticity, detect metadata manipulation, 
          and identify potential forgery signatures. 
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-10">
        <div className="space-y-4">
          <Label htmlFor="claimedIdentity" className="text-sm font-mono text-muted-foreground uppercase tracking-wider">
            Document Identity Claim
          </Label>
          <Input 
            id="claimedIdentity"
            placeholder="e.g. A letter from First National Bank dated March 2022 certifying a $500k account balance"
            value={claimedIdentity}
            onChange={(e) => setClaimedIdentity(e.target.value)}
            className="font-mono bg-card text-foreground border-border h-14 text-base focus-visible:ring-primary"
            data-testid="input-claimed-identity"
          />
          <p className="text-xs text-muted-foreground">
            Describe the stated purpose and origin of the document. The analysis engine will compare the document's structure and metadata against this claim.
          </p>
        </div>

        <div className="space-y-4">
          <Label className="text-sm font-mono text-muted-foreground uppercase tracking-wider">
            Evidence File (PDF)
          </Label>
          <div 
            className={`relative border-2 border-dashed rounded-lg transition-colors duration-200 ease-in-out ${
              isDragging ? 'border-primary bg-primary/5' : 'border-border bg-card'
            } ${file ? 'border-primary/50 bg-primary/5' : ''}`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            data-testid="dropzone-upload"
          >
            <div className="flex flex-col items-center justify-center py-16 px-6 text-center cursor-pointer">
              <input 
                type="file" 
                ref={fileInputRef} 
                onChange={handleFileChange} 
                accept="application/pdf" 
                className="hidden" 
                data-testid="input-file"
              />
              
              {file ? (
                <div className="flex flex-col items-center space-y-4">
                  <div className="h-16 w-16 rounded-full bg-primary/20 flex items-center justify-center">
                    <FileText className="h-8 w-8 text-primary" />
                  </div>
                  <div className="space-y-1">
                    <p className="text-lg font-medium text-foreground">{file.name}</p>
                    <p className="text-sm text-muted-foreground font-mono">
                      {(file.size / 1024 / 1024).toFixed(2)} MB
                    </p>
                  </div>
                  <Button type="button" variant="outline" size="sm" onClick={(e) => { e.stopPropagation(); setFile(null); }} className="mt-4">
                    Remove Evidence
                  </Button>
                </div>
              ) : (
                <div className="flex flex-col items-center space-y-4">
                  <div className="h-16 w-16 rounded-full bg-muted flex items-center justify-center">
                    <Upload className="h-8 w-8 text-muted-foreground" />
                  </div>
                  <div className="space-y-1">
                    <p className="text-lg font-medium text-foreground">Drag and drop PDF document here</p>
                    <p className="text-sm text-muted-foreground">or click to browse local files</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="flex justify-end pt-4 border-t border-border">
          <Button 
            type="submit" 
            size="lg" 
            disabled={isUploading} 
            className="w-full sm:w-auto h-14 px-8 text-base font-medium tracking-wide"
            data-testid="button-submit-analysis"
          >
            {isUploading ? (
              <>
                <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                INITIATING ANALYSIS
              </>
            ) : (
              'BEGIN ANALYSIS'
            )}
          </Button>
        </div>
      </form>
    </div>
  );
}
