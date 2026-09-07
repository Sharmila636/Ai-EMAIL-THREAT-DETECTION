export type ThreatClassification = 'SAFE' | 'SUSPICIOUS' | 'PHISHING';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type CaseStatus = 'New' | 'Under Review' | 'Investigated' | 'Closed';

export interface EmailMetadata {
  from: string;
  fromName?: string;
  fromDomain?: string;
  to: string;
  replyTo?: string;
  replyToDomain?: string;
  returnPath?: string;
  subject: string;
  date: string;
  messageId: string;
  receivedHeaders: string[];
  authenticationResults?: string;
  spf?: string;
  dkim?: string;
  dmarc?: string;
  contentType?: string;
  attachments: string[];
}

export interface HeaderAnomaly {
  field: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  observed: string;
  anomaly: string;
  explanation: string;
}

export interface IOCItem {
  id: string;
  type: 'IP' | 'Domain' | 'URL' | 'Sender' | 'Reply-To' | 'Message-ID';
  indicator: string;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  evidence: string;
  action: string;
}

export interface URLAnalysisItem {
  id: string;
  url: string;
  domain: string;
  protocol: string;
  path: string;
  isIpBased: boolean;
  isShortened: boolean;
  hasSubdomainAnomaly: boolean;
  isHttps: boolean;
  suspiciousKeywords: string[];
  isUnusualLength: boolean;
  hasEncodedChars: boolean;
  hasPunycode: boolean;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  explanations: string[];
}

export interface DomainAnalysisItem {
  domain: string;
  subdomain: string;
  tld: string;
  characteristics: string[];
  suspiciousPattern: boolean;
  lookalikeTarget?: string;
  associatedIp?: string;
  externalReputation: string;
}

export interface GeolocationInfo {
  ip: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  lat: number;
  lon: number;
  isp: string;
  org: string;
  asn: string;
  timezone: string;
  isPrivateOrReserved: boolean;
  status: 'available' | 'unavailable' | 'reserved';
  note?: string;
}

export interface ThreatDNA {
  identityRisk: number; // 0 - 100
  urlRisk: number; // 0 - 100
  languageRisk: number; // 0 - 100
  infrastructureRisk: number; // 0 - 100
  headerRisk: number; // 0 - 100
  credentialTheftRisk: number; // 0 - 100
}

export interface TimelineItem {
  order: number;
  stage: string;
  status: 'completed' | 'flagged' | 'warning' | 'clean';
  explanation: string;
  timestamp: string;
}

export interface RiskFactor {
  name: string;
  points: number;
  category: 'ML Prediction' | 'URL & Domain' | 'Identity & Headers' | 'Content & Urgency' | 'Infrastructure';
  description: string;
}

export interface AnalysisResult {
  case_id: string;
  created_at: string;
  classification: ThreatClassification;
  model_confidence: number; // 0.0 - 1.0 (e.g. 0.94)
  threat_risk_score: number; // 0 - 100
  risk_level: RiskLevel;
  threat_level?: string;
  reasons: string[];
  safe_evidence: string[];
  risk_factors: RiskFactor[];
  metadata: EmailMetadata;
  header_anomalies: HeaderAnomaly[];
  iocs: {
    ips: string[];
    domains: string[];
    urls: string[];
    sender: string;
    replyTo?: string;
    messageId?: string;
  };
  ioc_table: IOCItem[];
  url_analysis: URLAnalysisItem[];
  domain_analysis: DomainAnalysisItem[];
  geolocation: GeolocationInfo[];
  threat_dna: ThreatDNA;
  timeline: TimelineItem[];
  recommended_actions: string[];
  incident_response_playbook?: string[];
  investigation_story: string;
  raw_body_preview?: string;
  ml_breakdown?: {
    phishingProbability: number;
    topPhishingFeatures: { token: string; weight: number }[];
    topSafeFeatures: { token: string; weight: number }[];
  };
  ml_features: {
    url_count: number;
    ip_url_count: number;
    shortened_url_count: number;
    suspicious_domain_count: number;
    urgency_keyword_count: number;
    credential_keyword_count: number;
    financial_keyword_count: number;
    has_html_form: boolean;
    sender_replyto_mismatch: boolean;
    has_suspicious_tld: boolean;
    top_predictive_tokens: { token: string; weight: number }[];
  };
  is_demo_sample?: boolean;
}

export interface ModelMetrics {
  model_name: string;
  feature_extraction: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  confusion_matrix: {
    true_safe: number;
    false_safe: number; // False negative (missed phishing)
    true_phishing: number;
    false_phishing: number; // False positive (safe marked as phishing)
  };
  total_samples: number;
  training_samples: number;
  testing_samples: number;
  class_distribution: {
    safe_samples: number;
    phishing_samples: number;
    ratio: string;
  };
  datasets_used: string[];
  evaluation_method: string;
  stratified_split: boolean;
  recall_emphasis_note: string;
}

export interface InvestigationSummary {
  id: string;
  date: string;
  sender: string;
  subject: string;
  verdict: ThreatClassification;
  risk_score: number;
  model_confidence: number;
  status: CaseStatus;
  is_demo: boolean;
}
