-- SENTINEL Initial PostgreSQL Schema Migration (001_initial_schema.sql)
-- Supports all 13 mandatory tables plus sessions for multi-server (Web01/Web02) shared persistence.

CREATE TABLE IF NOT EXISTS roles (
  id SERIAL PRIMARY KEY,
  name VARCHAR(64) UNIQUE NOT NULL,
  description TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(64) UNIQUE NOT NULL,
  email VARCHAR(128) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_sessions (
  token_hash VARCHAR(128) PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token VARCHAR(128) NOT NULL,
  ip_address VARCHAR(64),
  user_agent TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS authorized_domains (
  id SERIAL PRIMARY KEY,
  domain VARCHAR(253) UNIQUE NOT NULL,
  description TEXT,
  added_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scans (
  id VARCHAR(64) PRIMARY KEY,
  domain VARCHAR(253) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'running',
  initiated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  authorization_confirmed BOOLEAN NOT NULL DEFAULT TRUE,
  current_stage_number INTEGER NOT NULL DEFAULT 1,
  current_stage_key VARCHAR(64) NOT NULL DEFAULT 'VALIDATE_DOMAIN',
  provider_status_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  provider_failures_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  takeover_indicators_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);

CREATE TABLE IF NOT EXISTS scan_stages (
  id SERIAL PRIMARY KEY,
  scan_id VARCHAR(64) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  stage_number INTEGER NOT NULL,
  stage_key VARCHAR(64) NOT NULL,
  stage_label VARCHAR(128) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  detail TEXT,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  UNIQUE(scan_id, stage_number)
);

CREATE TABLE IF NOT EXISTS assets (
  id SERIAL PRIMARY KEY,
  scan_id VARCHAR(64) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  domain VARCHAR(253) NOT NULL,
  subdomain VARCHAR(253) NOT NULL,
  ip_address VARCHAR(64),
  ipv4_addresses_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  ipv6_address VARCHAR(128),
  ipv6_addresses_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  cname VARCHAR(253),
  cname_targets_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  hosting_provider VARCHAR(128),
  dns_status VARCHAR(64) NOT NULL DEFAULT 'UNKNOWN',
  resolves BOOLEAN NOT NULL DEFAULT FALSE,
  exposed_ports_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  associated_cves_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  cpes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  certificate_count INTEGER NOT NULL DEFAULT 0,
  risk_level VARCHAR(32) NOT NULL DEFAULT 'Informational',
  risk_classification_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  takeover_indicator_json JSONB,
  source TEXT NOT NULL,
  first_observed TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_observed TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(scan_id, subdomain)
);

CREATE INDEX IF NOT EXISTS idx_assets_subdomain ON assets(subdomain);
CREATE INDEX IF NOT EXISTS idx_assets_risk_level ON assets(risk_level);

CREATE TABLE IF NOT EXISTS dns_records (
  id SERIAL PRIMARY KEY,
  scan_id VARCHAR(64) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  hostname VARCHAR(253) NOT NULL,
  record_type VARCHAR(16) NOT NULL,
  value TEXT NOT NULL,
  ttl INTEGER,
  provider VARCHAR(64) NOT NULL DEFAULT 'Cloudflare DoH',
  resolution_status VARCHAR(32) NOT NULL DEFAULT 'NOERROR',
  last_observed TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dns_records_hostname ON dns_records(hostname);
CREATE INDEX IF NOT EXISTS idx_dns_records_type ON dns_records(record_type);

CREATE TABLE IF NOT EXISTS ip_exposures (
  id SERIAL PRIMARY KEY,
  scan_id VARCHAR(64) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  ip_address VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'success',
  open_ports_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  hostnames_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  cpes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  cves_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  tags_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  associated_hostnames_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  source VARCHAR(64) NOT NULL DEFAULT 'Shodan InternetDB',
  last_enriched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(scan_id, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_ip_exposures_ip ON ip_exposures(ip_address);

CREATE TABLE IF NOT EXISTS cve_records (
  id SERIAL PRIMARY KEY,
  scan_id VARCHAR(64) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  cve_id VARCHAR(32) NOT NULL,
  cvss_score NUMERIC(4,1),
  cvss_version VARCHAR(16),
  severity VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
  description TEXT NOT NULL,
  affected_assets_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  associated_ips_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  associated_cpes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  weaknesses_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  references_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  published_date VARCHAR(64),
  last_modified_date VARCHAR(64),
  verification_status VARCHAR(64) NOT NULL DEFAULT 'CVE_ASSOCIATION_OBSERVED',
  verification_note TEXT,
  source VARCHAR(64) NOT NULL DEFAULT 'NIST NVD',
  retrieved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(scan_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_cve_records_cve_id ON cve_records(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_records_severity ON cve_records(severity);

CREATE TABLE IF NOT EXISTS findings (
  id SERIAL PRIMARY KEY,
  scan_id VARCHAR(64) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  finding_type VARCHAR(64) NOT NULL,
  title TEXT NOT NULL,
  severity VARCHAR(32) NOT NULL,
  confidence VARCHAR(128) NOT NULL,
  affected_asset VARCHAR(253) NOT NULL,
  ip_address VARCHAR(64),
  port INTEGER,
  cname_target VARCHAR(253),
  provider_pattern VARCHAR(128),
  cve_id VARCHAR(32),
  cvss_score NUMERIC(4,1),
  reason TEXT NOT NULL,
  supporting_evidence TEXT NOT NULL,
  source VARCHAR(128) NOT NULL,
  recommended_action TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type);

CREATE TABLE IF NOT EXISTS certificates (
  id SERIAL PRIMARY KEY,
  scan_id VARCHAR(64) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  certificate_id VARCHAR(64) NOT NULL,
  common_name VARCHAR(253),
  subject_alt_names_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  issuer_name TEXT,
  serial_number VARCHAR(128),
  not_before VARCHAR(64),
  not_after VARCHAR(64),
  source VARCHAR(64) NOT NULL DEFAULT 'crt.sh',
  retrieved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(scan_id, certificate_id)
);

CREATE TABLE IF NOT EXISTS api_provider_logs (
  id SERIAL PRIMARY KEY,
  provider_name VARCHAR(64) NOT NULL,
  target_query TEXT NOT NULL,
  status VARCHAR(32) NOT NULL,
  latency_ms INTEGER,
  error_message TEXT,
  server_id VARCHAR(32) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  username VARCHAR(64),
  action VARCHAR(128) NOT NULL,
  resource_type VARCHAR(64),
  resource_id VARCHAR(128),
  details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip_address VARCHAR(64),
  server_id VARCHAR(32) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
