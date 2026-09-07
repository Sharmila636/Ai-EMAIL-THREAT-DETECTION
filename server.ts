import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { executeThreatAnalysis, resolveIpGeolocation } from './src/lib/cyber-engine';
import { HELD_OUT_MODEL_METRICS } from './src/lib/ml-engine';
import { DEMO_SAMPLES } from './src/lib/demo-samples';
import { AnalysisResult, InvestigationSummary } from './src/types';
import {
  saveInvestigationToSupabase,
  fetchInvestigationsFromSupabase,
  deleteInvestigationFromSupabase,
  testSupabaseConnection,
  SUPABASE_SQL_SCHEMA,
} from './src/lib/supabase-server';

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '10mb' }));

// In-memory persistent investigation repository (mirrored with Supabase when connected)
const investigationsStore: Map<string, AnalysisResult> = new Map();

// Seed initial demonstration cases (clearly tagged as Demo Data)
async function seedDemoCases() {
  try {
    const phishResult = await executeThreatAnalysis(
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
    phishResult.case_id = 'CASE-DEMO-001';
    investigationsStore.set(phishResult.case_id, phishResult);

    const suspResult = await executeThreatAnalysis(
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
    suspResult.case_id = 'CASE-DEMO-002';
    investigationsStore.set(suspResult.case_id, suspResult);

    const safeResult = await executeThreatAnalysis(
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
    safeResult.case_id = 'CASE-DEMO-003';
    investigationsStore.set(safeResult.case_id, safeResult);
    console.log('[ThreatTrace SOC] Pre-seeded 3 demo cases successfully.');

    // Hydrate with remote cases from Supabase if connected
    const supabaseCases = await fetchInvestigationsFromSupabase();
    if (supabaseCases && supabaseCases.length > 0) {
      for (const item of supabaseCases) {
        investigationsStore.set(item.case_id, item);
      }
      console.log(`[ThreatTrace SOC] Hydrated ${supabaseCases.length} persistent investigations from Supabase.`);
    }
  } catch (err) {
    console.error('[ThreatTrace SOC] Error seeding initial demo cases:', err);
  }
}

// ----------------------------------------------------
// REST API ENDPOINTS
// ----------------------------------------------------

// 1. Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'online', engine: 'ThreatTrace Hybrid Threat Engine v2.6.1' });
});

// 2. Supabase Connection & Configuration Status
app.get('/api/supabase/status', async (req, res) => {
  try {
    const status = await testSupabaseConnection();
    res.json(status);
  } catch (err: any) {
    res.status(500).json({
      isConfigured: false,
      isConnected: false,
      url: null,
      tableExists: false,
      message: err?.message || 'Error checking Supabase status',
      sqlSchema: SUPABASE_SQL_SCHEMA,
    });
  }
});

// Sync in-memory cases to Supabase
app.post('/api/supabase/sync', async (req, res) => {
  try {
    const status = await testSupabaseConnection();
    if (!status.isConfigured || !status.isConnected) {
      return res.status(400).json({
        success: false,
        message: status.message,
      });
    }

    let synced = 0;
    for (const item of investigationsStore.values()) {
      const ok = await saveInvestigationToSupabase(item);
      if (ok) synced++;
    }

    res.json({
      success: true,
      syncedCount: synced,
      totalCount: investigationsStore.size,
      message: `Successfully synced ${synced} investigation(s) to Supabase table "investigations".`,
    });
  } catch (err: any) {
    res.status(500).json({
      success: false,
      message: err?.message || 'Failed to sync to Supabase',
    });
  }
});

// 3. POST /api/analyze-email
app.post('/api/analyze-email', async (req, res) => {
  try {
    const { rawEmail, from, to, subject, body, headers, isDemo } = req.body || {};

    if (!rawEmail && !body && !subject) {
      return res.status(400).json({
        error: 'Email input is empty. Please provide email body, headers, or raw RFC 822 content.',
      });
    }

    const result = await executeThreatAnalysis(
      { rawEmail, from, to, subject, body, headers },
      Boolean(isDemo)
    );

    // Save to investigation store
    investigationsStore.set(result.case_id, result);

    // Asynchronously replicate to Supabase without blocking user response
    saveInvestigationToSupabase(result).catch((err) => {
      console.warn('[ThreatTrace SOC] Background Supabase persist failed:', err);
    });

    res.json(result);
  } catch (err: any) {
    console.error('Error analyzing email:', err);
    res.status(500).json({
      error: 'An internal error occurred during forensic analysis. Rule-based inspection was retained.',
      message: err?.message || 'Unknown forensic engine exception',
    });
  }
});

// 4. GET /api/investigations
app.get('/api/investigations', async (req, res) => {
  try {
    const { verdict, search } = req.query;

    // Refresh from Supabase if active
    const remoteCases = await fetchInvestigationsFromSupabase();
    if (remoteCases && remoteCases.length > 0) {
      for (const item of remoteCases) {
        investigationsStore.set(item.case_id, item);
      }
    }

    let cases: AnalysisResult[] = Array.from(investigationsStore.values());

    if (verdict && typeof verdict === 'string' && verdict !== 'ALL') {
      cases = cases.filter((c) => c.classification.toUpperCase() === verdict.toUpperCase());
    }

    if (search && typeof search === 'string') {
      const q = search.toLowerCase();
      cases = cases.filter(
        (c) =>
          c.case_id.toLowerCase().includes(q) ||
          c.metadata.subject.toLowerCase().includes(q) ||
          c.metadata.from.toLowerCase().includes(q) ||
          c.ioc_table.some((i) => i.indicator.toLowerCase().includes(q))
      );
    }

    // Sort newest first
    cases.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

    const summaries: InvestigationSummary[] = cases.map((c) => ({
      id: c.case_id,
      date: c.created_at,
      sender: c.metadata.from,
      subject: c.metadata.subject,
      verdict: c.classification,
      risk_score: c.threat_risk_score,
      model_confidence: c.model_confidence,
      status: c.classification === 'PHISHING' ? 'Investigated' : c.classification === 'SUSPICIOUS' ? 'Under Review' : 'Closed',
      is_demo: Boolean(c.is_demo_sample),
    }));

    res.json({
      total: summaries.length,
      cases: summaries,
      stats: {
        total: summaries.length,
        phishing: summaries.filter((s) => s.verdict === 'PHISHING').length,
        suspicious: summaries.filter((s) => s.verdict === 'SUSPICIOUS').length,
        safe: summaries.filter((s) => s.verdict === 'SAFE').length,
      },
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to retrieve investigation cases' });
  }
});

// 5. GET /api/investigations/:id
app.get('/api/investigations/:id', (req, res) => {
  const caseId = req.params.id;
  const item = investigationsStore.get(caseId);
  if (!item) {
    return res.status(404).json({ error: `Investigation case ${caseId} not found` });
  }
  res.json(item);
});

// 6. DELETE /api/investigations/:id
app.delete('/api/investigations/:id', async (req, res) => {
  const caseId = req.params.id;
  if (!investigationsStore.has(caseId)) {
    return res.status(404).json({ error: `Case ${caseId} not found` });
  }
  investigationsStore.delete(caseId);

  // Also remove from Supabase
  deleteInvestigationFromSupabase(caseId).catch((err) => {
    console.warn('[ThreatTrace SOC] Supabase delete error:', err);
  });

  res.json({ success: true, message: `Case ${caseId} removed from docket` });
});

// 7. GET /api/model/metrics
app.get('/api/model/metrics', (req, res) => {
  res.json(HELD_OUT_MODEL_METRICS);
});

// 8. GET /api/geolocation/:ip
app.get('/api/geolocation/:ip', async (req, res) => {
  const ip = req.params.ip;
  if (!ip) return res.status(400).json({ error: 'IP address required' });
  const data = await resolveIpGeolocation(ip);
  res.json(data);
});

// 9. POST /api/report/:id
app.post('/api/report/:id', (req, res) => {
  const caseId = req.params.id;
  const item = investigationsStore.get(caseId);
  if (!item) {
    return res.status(404).json({ error: 'Case not found for report generation' });
  }
  res.json({
    report_id: `REP-${caseId}`,
    generated_at: new Date().toISOString(),
    dossier: item,
  });
});

// ----------------------------------------------------
// Vite Middleware / Static Servicing
// ----------------------------------------------------
async function startServer() {
  await seedDemoCases();

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[ThreatTrace SOC] Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
