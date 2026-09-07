-- ============================================================================
-- ThreatTrace SOC: Complete Supabase / PostgreSQL Schema
-- Database Schema for Phishing Forensic Analysis & Investigation Repository
-- ============================================================================

-- 1. MAIN INVESTIGATIONS TABLE
-- Stores full forensic telemetry, extracted indicators, and complete dossier JSONB
CREATE TABLE IF NOT EXISTS investigations (
  id TEXT PRIMARY KEY,                           -- Unique Case ID (e.g., CASE-20260907-4821)
  case_id TEXT NOT NULL,                         -- Case ID reference
  created_at TIMESTAMPTZ DEFAULT NOW(),          -- Analysis timestamp
  updated_at TIMESTAMPTZ DEFAULT NOW(),          -- Last update timestamp
  classification TEXT NOT NULL                   -- Verdict: 'PHISHING', 'SUSPICIOUS', or 'SAFE'
    CHECK (classification IN ('PHISHING', 'SUSPICIOUS', 'SAFE')),
  risk_level TEXT DEFAULT 'LOW'                  -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  threat_risk_score INTEGER NOT NULL             -- 0 - 100 aggregate threat score
    CHECK (threat_risk_score >= 0 AND threat_risk_score <= 100),
  model_confidence NUMERIC(6, 4) DEFAULT 0.0,    -- ML model confidence (0.0 to 1.0)
  sender TEXT,                                   -- Sender From email / address
  recipient TEXT,                                -- Target recipient To header
  subject TEXT,                                  -- Email subject line
  spf_status TEXT DEFAULT 'NONE',                -- SPF authentication verdict
  dkim_status TEXT DEFAULT 'NONE',               -- DKIM authentication verdict
  dmarc_status TEXT DEFAULT 'NONE',              -- DMARC policy verdict
  originating_ip TEXT,                           -- Inferred sender IP address
  originating_country TEXT,                      -- Geolocation country of sender IP
  urls_count INTEGER DEFAULT 0,                  -- Number of extracted hyperlinks
  investigation_story TEXT,                      -- Executive narrative explanation
  is_demo BOOLEAN DEFAULT FALSE,                 -- True if seeded demo dataset
  dossier JSONB NOT NULL DEFAULT '{}'::jsonb     -- Complete forensic dossier JSON object
);

-- Ensure all columns exist if table was previously created with minimal columns
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS risk_level TEXT DEFAULT 'LOW';
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS recipient TEXT;
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS spf_status TEXT DEFAULT 'NONE';
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS dkim_status TEXT DEFAULT 'NONE';
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS dmarc_status TEXT DEFAULT 'NONE';
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS originating_ip TEXT;
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS originating_country TEXT;
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS urls_count INTEGER DEFAULT 0;
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS investigation_story TEXT;
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS is_demo BOOLEAN DEFAULT FALSE;

-- 2. INDICATORS OF COMPROMISE (IOCs) TABLE
-- Granular table for threat hunting across IPs, Domains, URLs, and Hashes
CREATE TABLE IF NOT EXISTS threat_iocs (
  id BIGSERIAL PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  ioc_type TEXT NOT NULL,                        -- 'IP', 'Domain', 'URL', 'Sender', 'Reply-To'
  indicator TEXT NOT NULL,                       -- e.g., '185.220.101.42', 'paypal-secure-login.xyz'
  risk_level TEXT NOT NULL,                      -- 'Low', 'Medium', 'High', 'Critical'
  evidence TEXT,                                 -- Reason flagged (e.g., Known malicious ASN, SPF fail)
  action_recommended TEXT,                       -- e.g., 'Block at perimeter firewall', 'Revoke credentials'
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. SOC ANALYST AUDIT LOG TABLE
-- Logs analyst review actions, triage notes, and executive report downloads
CREATE TABLE IF NOT EXISTS soc_audit_log (
  id BIGSERIAL PRIMARY KEY,
  case_id TEXT REFERENCES investigations(id) ON DELETE SET NULL,
  analyst_user TEXT DEFAULT 'soc-analyst',
  action TEXT NOT NULL,                          -- 'ANALYZED', 'TRIAGED', 'DELETED', 'EXPORTED_REPORT'
  details TEXT,
  timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 4. PERFORMANCE INDEXES
CREATE INDEX IF NOT EXISTS idx_investigations_classification ON investigations (classification);
CREATE INDEX IF NOT EXISTS idx_investigations_risk_score ON investigations (threat_risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON investigations (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_investigations_sender ON investigations (sender);
CREATE INDEX IF NOT EXISTS idx_investigations_originating_ip ON investigations (originating_ip);
CREATE INDEX IF NOT EXISTS idx_investigations_dossier ON investigations USING GIN (dossier);
CREATE INDEX IF NOT EXISTS idx_threat_iocs_indicator ON threat_iocs (indicator);
CREATE INDEX IF NOT EXISTS idx_threat_iocs_case_id ON threat_iocs (case_id);

-- 5. ROW LEVEL SECURITY (RLS) POLICIES
-- Enables row security while granting read & write access to your application
ALTER TABLE investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_iocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE soc_audit_log ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  -- Policy for investigations
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'investigations' AND policyname = 'Allow full access to investigations'
  ) THEN
    CREATE POLICY "Allow full access to investigations" ON investigations FOR ALL USING (true) WITH CHECK (true);
  END IF;

  -- Policy for threat_iocs
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'threat_iocs' AND policyname = 'Allow full access to threat_iocs'
  ) THEN
    CREATE POLICY "Allow full access to threat_iocs" ON threat_iocs FOR ALL USING (true) WITH CHECK (true);
  END IF;

  -- Policy for soc_audit_log
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'soc_audit_log' AND policyname = 'Allow full access to soc_audit_log'
  ) THEN
    CREATE POLICY "Allow full access to soc_audit_log" ON soc_audit_log FOR ALL USING (true) WITH CHECK (true);
  END IF;
END
$$;

-- 6. REAL-TIME PUBLICATION (Optional: for real-time dashboard listeners)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE investigations;
  END IF;
EXCEPTION
  WHEN OTHERS THEN NULL;
END
$$;

-- 7. ANALYTICAL VIEWS FOR SOC TEAMS
-- High-Priority Phishing Threats View
CREATE OR REPLACE VIEW v_high_risk_phishing AS
SELECT 
  id AS case_id,
  created_at,
  classification,
  threat_risk_score,
  sender,
  subject,
  originating_ip,
  originating_country,
  urls_count,
  dossier->'threat_dna' AS threat_dna,
  dossier->'ml_breakdown'->>'phishingProbability' AS ml_phishing_probability
FROM investigations
WHERE classification = 'PHISHING' OR threat_risk_score >= 70
ORDER BY threat_risk_score DESC, created_at DESC;

-- Executive SOC Incident Summary Metrics View
CREATE OR REPLACE VIEW v_soc_summary_metrics AS
SELECT 
  COUNT(*) AS total_cases,
  COUNT(*) FILTER (WHERE classification = 'PHISHING') AS total_phishing,
  COUNT(*) FILTER (WHERE classification = 'SUSPICIOUS') AS total_suspicious,
  COUNT(*) FILTER (WHERE classification = 'SAFE') AS total_safe,
  ROUND(AVG(threat_risk_score), 1) AS average_risk_score,
  COUNT(*) FILTER (WHERE is_demo = false) AS real_world_cases
FROM investigations;
