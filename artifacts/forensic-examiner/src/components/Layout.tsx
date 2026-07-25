import React from 'react';
import { Link, useLocation } from 'wouter';
import { Fingerprint, History, Upload, Activity } from 'lucide-react';
import { useHealthCheck } from '@workspace/api-client-react';

interface LayoutProps {
  children: React.ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  const [location] = useLocation();
  const { data: health } = useHealthCheck();

  return (
    <div className="min-h-[100dvh] flex flex-col">
      <header className="sticky top-0 z-50 w-full border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="flex h-16 items-center px-6">
          <Link href="/" className="flex items-center gap-3 mr-8" data-testid="link-home">
            <div className="bg-primary/10 p-1.5 rounded-md">
              <Fingerprint className="h-5 w-5 text-primary" />
            </div>
            <span className="font-serif font-bold text-lg tracking-tight">Forensic Document Examiner</span>
          </Link>

          <nav className="flex items-center space-x-1">
            <Link 
              href="/" 
              className={`flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                location === '/' ? 'bg-secondary text-secondary-foreground' : 'text-muted-foreground hover:bg-secondary/50 hover:text-foreground'
              }`}
              data-testid="link-nav-upload"
            >
              <Upload className="h-4 w-4" />
              New Analysis
            </Link>
            <Link 
              href="/history" 
              className={`flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                location === '/history' ? 'bg-secondary text-secondary-foreground' : 'text-muted-foreground hover:bg-secondary/50 hover:text-foreground'
              }`}
              data-testid="link-nav-history"
            >
              <History className="h-4 w-4" />
              Case History
            </Link>
          </nav>

          <div className="ml-auto flex items-center space-x-4">
            <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground bg-secondary/30 px-3 py-1.5 rounded-full">
              <div className={`h-2 w-2 rounded-full ${health?.status === 'ok' ? 'bg-authentic' : 'bg-muted'}`} />
              <span className="uppercase tracking-wider">Engine Status</span>
            </div>
          </div>
        </div>
      </header>

      <main className="flex-1">
        {children}
      </main>
    </div>
  );
}
