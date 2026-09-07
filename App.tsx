import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { DashboardView } from './components/DashboardView';
import { AnalyzeEmailView } from './components/AnalyzeEmailView';
import { ResultDashboardView } from './components/ResultDashboardView';
import { InvestigationsHistoryView } from './components/InvestigationsHistoryView';
import { ModelPerformanceView } from './components/ModelPerformanceView';
import { ArchitectureView } from './components/ArchitectureView';
import { VivaGuideView } from './components/VivaGuideView';
import { LoadingInvestigation } from './components/LoadingInvestigation';
import { SupabaseModal } from './components/SupabaseModal';
import { AnalysisResult, InvestigationSummary } from './types';
import { DEMO_SAMPLES } from './lib/demo-samples';
import { executeThreatAnalysis } from './lib/cyber-engine';
import { AlertCircle, X, ShieldAlert, CheckCircle2 } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<
    'dashboard' | 'analyze' | 'result' | 'investigations' | 'metrics' | 'architecture' | 'about'
  >('dashboard');

  const [currentAnalysis, setCurrentAnalysis] = useState<AnalysisResult | null>(null);
  const [isAnalystMode, setIsAnalystMode] = useState<boolean>(false);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isSupabaseModalOpen, setIsSupabaseModalOpen] = useState<boolean>(false);
  const [isSupabaseConnected, setIsSupabaseConnected] = useState<boolean>(false);

  // In-memory cases map & summaries
  const [casesMap, setCasesMap] = useState<Record<string, AnalysisResult>>({});
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);

  // Function to refresh investigations list from server
  const refreshInvestigations = useCallback(async () => {
    try {
      const resp = await fetch('/api/investigations');
      if (resp.ok) {
        const data = await resp.json();
        if (data.cases) {
          setInvestigations(data.cases);
        }
      }
    } catch (err) {
      console.warn('Failed to refresh investigations from server:', err);
    }
  }, []);

  // Check Supabase connection state
  const checkSupabaseStatus = useCallback(async () => {
    try {
      const res = await fetch('/api/supabase/status');
      if (res.ok) {
        const data = await res.json();
        setIsSupabaseConnected(Boolean(data.isConnected && data.tableExists));
      }
    } catch {
      setIsSupabaseConnected(false);
    }
  }, []);

  // Seed initial demo cases on application start
  useEffect(() => {
    async function initPlatform() {
      await checkSupabaseStatus();

      try {
        // Attempt to fetch existing cases from backend server
        const resp = await fetch('/api/investigations');
        if (resp.ok) {
          const data = await resp.json();
          if (data.cases && data.cases.length > 0) {
            setInvestigations(data.cases);
          }
        }
      } catch (err) {
        console.warn('Backend server poll failed, seeding client-side demo repository...', err);
      }

      // Generate local instances of the 3 demo cases to guarantee instant presentation readiness
      try {
        const phish = await executeThreatAnalysis(
          {
            rawEmail: DEMO_SAMPLES.phishing.rawEmail,
            from: DEMO_SAMPLES.phishing.from,
            to: DEMO_SAMPLES.phishing.to,
            subject: DEMO_SAMPLES.phishing.subject,
            body: DEMO_SAMPLES.phishing.body,
            headers: DEMO_SAMPLES.phishing.rawHeaders,
          },
          true
        );
        phish.case_id = 'CASE-DEMO-001';

        const susp = await executeThreatAnalysis(
          {
            rawEmail: DEMO_SAMPLES.suspicious.rawEmail,
            from: DEMO_SAMPLES.suspicious.from,
            to: DEMO_SAMPLES.suspicious.to,
            subject: DEMO_SAMPLES.suspicious.subject,
            body: DEMO_SAMPLES.suspicious.body,
            headers: DEMO_SAMPLES.suspicious.rawHeaders,
          },
          true
        );
        susp.case_id = 'CASE-DEMO-002';

        const safe = await executeThreatAnalysis(
          {
            rawEmail: DEMO_SAMPLES.safe.rawEmail,
            from: DEMO_SAMPLES.safe.from,
            to: DEMO_SAMPLES.safe.to,
            subject: DEMO_SAMPLES.safe.subject,
            body: DEMO_SAMPLES.safe.body,
            headers: DEMO_SAMPLES.safe.rawHeaders,
          },
          true
        );
        safe.case_id = 'CASE-DEMO-003';

        const initialMap: Record<string, AnalysisResult> = {
          [phish.case_id]: phish,
          [susp.case_id]: susp,
          [safe.case_id]: safe,
        };

        const initialSummaries: InvestigationSummary[] = [
          {
            id: phish.case_id,
            date: phish.created_at,
            sender: phish.metadata.from,
            subject: phish.metadata.subject,
            verdict: phish.classification,
            risk_score: phish.threat_risk_score,
            model_confidence: phish.model_confidence,
            status: 'Investigated',
            is_demo: true,
          },
          {
            id: susp.case_id,
            date: susp.created_at,
            sender: susp.metadata.from,
            subject: susp.metadata.subject,
            verdict: susp.classification,
            risk_score: susp.threat_risk_score,
            model_confidence: susp.model_confidence,
            status: 'Under Review',
            is_demo: true,
          },
          {
            id: safe.case_id,
            date: safe.created_at,
            sender: safe.metadata.from,
            subject: safe.metadata.subject,
            verdict: safe.classification,
            risk_score: safe.threat_risk_score,
            model_confidence: safe.model_confidence,
            status: 'Closed',
            is_demo: true,
          },
        ];

        setCasesMap((prev) => ({ ...initialMap, ...prev }));
        setInvestigations((prev) => (prev.length > 0 ? prev : initialSummaries));
      } catch (e) {
        console.error('Failed to pre-seed demonstration sample cache:', e);
      }
    }

    initPlatform();
  }, []);

  // Handle selecting an existing case by ID
  const handleSelectCase = async (caseId: string) => {
    // Check in-memory map first
    if (casesMap[caseId]) {
      setCurrentAnalysis(casesMap[caseId]);
      setActiveTab('result');
      return;
    }

    // Otherwise fetch from server
    try {
      const resp = await fetch(`/api/investigations/${caseId}`);
      if (resp.ok) {
        const item: AnalysisResult = await resp.json();
        setCasesMap((prev) => ({ ...prev, [caseId]: item }));
        setCurrentAnalysis(item);
        setActiveTab('result');
        return;
      }
    } catch (err) {
      console.warn('Could not fetch remote case details:', err);
    }

    setErrorMessage(`Unable to load investigation dossier for ${caseId}`);
  };

  // Handle new analysis lifecycle
  const handleAnalysisStart = () => {
    setIsAnalyzing(true);
    setErrorMessage(null);
  };

  const handleAnalysisSuccess = (result: AnalysisResult) => {
    setIsAnalyzing(false);
    setCurrentAnalysis(result);
    setCasesMap((prev) => ({ ...prev, [result.case_id]: result }));

    // Prepend to summaries
    const summary: InvestigationSummary = {
      id: result.case_id,
      date: result.created_at,
      sender: result.metadata.from,
      subject: result.metadata.subject,
      verdict: result.classification,
      risk_score: result.threat_risk_score,
      model_confidence: result.model_confidence,
      status: result.classification === 'PHISHING' ? 'Investigated' : result.classification === 'SUSPICIOUS' ? 'Under Review' : 'Closed',
      is_demo: Boolean(result.is_demo_sample),
    };

    setInvestigations((prev) => [summary, ...prev.filter((i) => i.id !== summary.id)]);
    setActiveTab('result');
  };

  const handleAnalysisError = (err: string) => {
    setIsAnalyzing(false);
    setErrorMessage(err);
  };

  // Quick 1-click launch phishing demo from dashboard
  const handleLoadPhishingDemo = async () => {
    if (casesMap['CASE-DEMO-001']) {
      setCurrentAnalysis(casesMap['CASE-DEMO-001']);
      setActiveTab('result');
    } else {
      setActiveTab('analyze');
    }
  };

  // Handle case deletion
  const handleDeleteCase = async (caseId: string) => {
    setInvestigations((prev) => prev.filter((c) => c.id !== caseId));
    setCasesMap((prev) => {
      const next = { ...prev };
      delete next[caseId];
      return next;
    });

    if (currentAnalysis?.case_id === caseId) {
      setCurrentAnalysis(null);
      setActiveTab('investigations');
    }

    try {
      await fetch(`/api/investigations/${caseId}`, { method: 'DELETE' });
    } catch (e) {
      // Ignored
    }
  };

  return (
    <div className="min-h-screen bg-[#020617] bg-cyber-grid text-slate-200 flex flex-col font-sans selection:bg-blue-600 selection:text-white relative">
      {/* Ambient background dot grid overlay */}
      <div
        className="absolute inset-0 opacity-10 pointer-events-none"
        style={{
          backgroundImage: 'radial-gradient(#1e293b 1px, transparent 1px)',
          backgroundSize: '20px 20px',
        }}
      ></div>

      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab === 'result' ? 'analyze' : activeTab}
        setActiveTab={(tab) => {
          setErrorMessage(null);
          setActiveTab(tab);
        }}
        isAnalystMode={isAnalystMode}
        setIsAnalystMode={setIsAnalystMode}
        investigationCount={investigations.length}
        isSupabaseConnected={isSupabaseConnected}
        onOpenSupabaseModal={() => setIsSupabaseModalOpen(true)}
      />

      {/* Supabase Cloud Database Modal */}
      <SupabaseModal
        isOpen={isSupabaseModalOpen}
        onClose={() => {
          setIsSupabaseModalOpen(false);
          checkSupabaseStatus();
        }}
        onRefreshInvestigations={refreshInvestigations}
      />

      {/* Global Error Banner */}
      {errorMessage && (
        <div className="max-w-4xl mx-auto px-4 mt-4 w-full">
          <div className="p-3.5 rounded-xl bg-rose-950/80 border border-rose-800 text-rose-200 text-xs flex items-center justify-between shadow-xl">
            <div className="flex items-center space-x-2.5">
              <AlertCircle className="w-4 h-4 text-rose-400 flex-shrink-0" />
              <span>{errorMessage}</span>
            </div>
            <button
              type="button"
              onClick={() => setErrorMessage(null)}
              className="p-1 rounded text-rose-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Main Body Stage */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {isAnalyzing ? (
          <LoadingInvestigation />
        ) : (
          <>
            {activeTab === 'dashboard' && (
              <DashboardView
                cases={investigations}
                onSelectCase={handleSelectCase}
                onNavigateAnalyze={() => setActiveTab('analyze')}
                onNavigateMetrics={() => setActiveTab('metrics')}
                onLoadPhishingDemo={handleLoadPhishingDemo}
              />
            )}

            {activeTab === 'analyze' && (
              <AnalyzeEmailView
                onAnalysisStart={handleAnalysisStart}
                onAnalysisSuccess={handleAnalysisSuccess}
                onAnalysisError={handleAnalysisError}
              />
            )}

            {activeTab === 'result' && currentAnalysis && (
              <ResultDashboardView
                result={currentAnalysis}
                isAnalystMode={isAnalystMode}
                setIsAnalystMode={setIsAnalystMode}
                onNewAnalysis={() => setActiveTab('analyze')}
              />
            )}

            {activeTab === 'investigations' && (
              <InvestigationsHistoryView
                cases={investigations}
                onSelectCase={handleSelectCase}
                onDeleteCase={handleDeleteCase}
                onNavigateAnalyze={() => setActiveTab('analyze')}
                onOpenSupabaseModal={() => setIsSupabaseModalOpen(true)}
                isSupabaseConnected={isSupabaseConnected}
              />
            )}

            {activeTab === 'metrics' && <ModelPerformanceView />}

            {activeTab === 'architecture' && <ArchitectureView />}

            {activeTab === 'about' && <VivaGuideView />}
          </>
        )}
      </main>

      {/* Cyber SOC Frosted Footer */}
      <footer className="relative z-10 border-t border-slate-800/80 bg-slate-900/50 backdrop-blur-xl py-4 text-xs text-slate-500 font-mono shadow-2xl">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-4 text-slate-400 text-[10px]">
            <span className="flex items-center gap-1.5 text-green-400">
              <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></span>
              SYSTEM: HYBRID_SOC v2.6.1
            </span>
            <span>MODEL: TFIDF_LOGISTIC_REG</span>
            <span>ENV: SIH_PRODUCTION_2026</span>
          </div>

          <div className="text-[10px] text-slate-400">
            &copy; 2026 Smart India Hackathon • PS26106 Cybersecurity Investigation Platform
          </div>
        </div>
      </footer>
    </div>
  );
}
