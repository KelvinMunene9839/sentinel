const crypto = require('crypto');
const { query, withTransaction } = require('../database/db');
const { SCAN_STAGE_DEFINITIONS } = require('../services/discovery/discovery.orchestrator');

function generateScanId() {
  return `scan_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

async function getAuthorizedDomainsList() {
  const res = await query('SELECT domain FROM authorized_domains WHERE is_active = TRUE ORDER BY domain ASC');
  return res.rows.map((r) => r.domain);
}

async function createInitialScanRecord({ domain, userId }) {
  const scanId = generateScanId();
  await withTransaction(async (client) => {
    await client.query(
      `INSERT INTO scans (id, domain, status, initiated_by, authorization_confirmed, current_stage_number, current_stage_key)
       VALUES ($1, $2, 'running', $3, TRUE, 1, 'VALIDATE_DOMAIN')`,
      [scanId, domain, userId || null]
    );

    for (const st of SCAN_STAGE_DEFINITIONS) {
      await client.query(
        `INSERT INTO scan_stages (scan_id, stage_number, stage_key, stage_label, status)
         VALUES ($1, $2, $3, $4, 'pending')`,
        [scanId, st.stageNumber, st.key, st.label]
      );
    }
  });
  return scanId;
}

async function updateScanStageProgress(scanId, progressPayload) {
  const { currentStageNumber, currentStageKey, status, detail } = progressPayload;
  await query(
    `UPDATE scans
     SET current_stage_number = $1, current_stage_key = $2
     WHERE id = $3`,
    [currentStageNumber, currentStageKey, scanId]
  );

  await query(
    `UPDATE scan_stages
     SET status = $1::varchar,
         detail = $2,
         started_at = COALESCE(started_at, NOW()),
         completed_at = CASE WHEN $1::varchar IN ('completed', 'partial', 'failed', 'skipped') THEN NOW() ELSE completed_at END
     WHERE scan_id = $3 AND stage_number = $4`,
    [status, detail, scanId, currentStageNumber]
  );
}

async function saveCompletedScanResults(scanId, result) {
  await withTransaction(async (client) => {
    await client.query(
      `UPDATE scans
       SET status = $1,
           current_stage_number = 11,
           current_stage_key = 'CLASSIFY_RISK',
           provider_status_json = $2,
           provider_failures_json = $3,
           summary_json = $4,
           takeover_indicators_json = $5,
           completed_at = $6
       WHERE id = $7`,
      [
        result.status,
        JSON.stringify(result.providerStatusSummary || {}),
        JSON.stringify(result.providerFailures || []),
        JSON.stringify(result.summary || {}),
        JSON.stringify(result.takeoverIndicators || []),
        result.completedAt || new Date().toISOString(),
        scanId,
      ]
    );

    for (const a of result.assets || []) {
      await client.query(
        `INSERT INTO assets (
           scan_id, domain, subdomain, ip_address, ipv4_addresses_json,
           ipv6_address, ipv6_addresses_json, cname, cname_targets_json,
           hosting_provider, dns_status, resolves, exposed_ports_json,
           associated_cves_json, cpes_json, certificate_count, risk_level,
           risk_classification_json, takeover_indicator_json, source,
           first_observed, last_observed
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
           $14, $15, $16, $17, $18, $19, $20, $21, $22
         ) ON CONFLICT (scan_id, subdomain) DO NOTHING`,
        [
          scanId,
          a.domain,
          a.subdomain,
          a.ipAddress,
          JSON.stringify(a.ipv4Addresses || []),
          a.ipv6Address,
          JSON.stringify(a.ipv6Addresses || []),
          a.cname,
          JSON.stringify(a.cnameTargets || []),
          a.hostingProvider,
          a.dnsStatus,
          a.resolves,
          JSON.stringify(a.exposedPorts || []),
          JSON.stringify(a.associatedCves || []),
          JSON.stringify(a.cpes || []),
          a.certificateCount || 0,
          a.riskLevel,
          JSON.stringify(a.riskClassification || {}),
          a.takeoverIndicator ? JSON.stringify(a.takeoverIndicator) : null,
          a.source,
          a.firstObserved,
          a.lastObserved,
        ]
      );
    }

    for (const r of result.dnsRecords || []) {
      await client.query(
        `INSERT INTO dns_records (scan_id, hostname, record_type, value, ttl, provider, resolution_status, last_observed)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
          scanId,
          r.hostname,
          r.recordType,
          r.value,
          r.ttl,
          r.provider || 'Cloudflare DoH',
          r.resolutionStatus || 'NOERROR',
          r.retrievedAt || new Date().toISOString(),
        ]
      );
    }

    for (const exp of result.ipExposures || []) {
      await client.query(
        `INSERT INTO ip_exposures (
           scan_id, ip_address, status, open_ports_json, hostnames_json,
           cpes_json, cves_json, tags_json, associated_hostnames_json,
           source, last_enriched_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT (scan_id, ip_address) DO NOTHING`,
        [
          scanId,
          exp.ip,
          exp.status,
          JSON.stringify(exp.openPorts || []),
          JSON.stringify(exp.hostnames || []),
          JSON.stringify(exp.cpes || []),
          JSON.stringify(exp.cves || []),
          JSON.stringify(exp.tags || []),
          JSON.stringify(exp.associatedHostnames || []),
          exp.source || 'Shodan InternetDB',
          exp.retrievedAt || new Date().toISOString(),
        ]
      );
    }

    for (const v of result.vulnerabilities || []) {
      await client.query(
        `INSERT INTO cve_records (
           scan_id, cve_id, cvss_score, cvss_version, severity, description,
           affected_assets_json, associated_ips_json, associated_cpes_json,
           weaknesses_json, references_json, published_date, last_modified_date,
           verification_status, verification_note, source, retrieved_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
         ON CONFLICT (scan_id, cve_id) DO NOTHING`,
        [
          scanId,
          v.cveId,
          v.cvssScore,
          v.cvssVersion,
          v.severity || 'UNKNOWN',
          v.description || '',
          JSON.stringify(v.affectedAssets || []),
          JSON.stringify(v.associatedIps || []),
          JSON.stringify(v.associatedCpes || []),
          JSON.stringify(v.weaknesses || []),
          JSON.stringify(v.references || []),
          v.publishedDate,
          v.lastModifiedDate,
          v.verificationStatus || 'CVE_ASSOCIATION_OBSERVED',
          v.verificationNote || '',
          v.source || 'NIST NVD',
          v.retrievedAt || new Date().toISOString(),
        ]
      );
    }

    for (const f of result.findings || []) {
      await client.query(
        `INSERT INTO findings (
           scan_id, finding_type, title, severity, confidence, affected_asset,
           ip_address, port, cname_target, provider_pattern, cve_id, cvss_score,
           reason, supporting_evidence, source, recommended_action
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
        [
          scanId,
          f.findingType,
          f.title,
          f.severity,
          f.confidence,
          f.affectedAsset,
          f.ipAddress || null,
          f.port || null,
          f.cnameTarget || null,
          f.providerPattern || null,
          f.cveId || null,
          f.cvssScore ?? null,
          f.reason,
          f.supportingEvidence,
          f.source,
          f.recommendedAction,
        ]
      );
    }

    for (const cert of (result.certificates || []).slice(0, 100)) {
      await client.query(
        `INSERT INTO certificates (
           scan_id, certificate_id, common_name, subject_alt_names_json,
           issuer_name, serial_number, not_before, not_after, source
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (scan_id, certificate_id) DO NOTHING`,
        [
          scanId,
          String(cert.certificateId),
          cert.commonName,
          JSON.stringify(cert.subjectAlternativeNames || []),
          cert.issuerName,
          cert.serialNumber,
          cert.notBefore,
          cert.notAfter,
          cert.source || 'crt.sh',
        ]
      );
    }
  });
}

function mapAssetRow(row) {
  return {
    id: row.id,
    scanId: row.scan_id,
    domain: row.domain,
    subdomain: row.subdomain,
    ipAddress: row.ip_address,
    ipv4Addresses: row.ipv4_addresses_json || [],
    ipv6Address: row.ipv6_address,
    ipv6Addresses: row.ipv6_addresses_json || [],
    cname: row.cname,
    cnameTargets: row.cname_targets_json || [],
    hostingProvider: row.hosting_provider,
    dnsStatus: row.dns_status,
    resolves: row.resolves,
    exposedPorts: row.exposed_ports_json || [],
    associatedCves: row.associated_cves_json || [],
    cpes: row.cpes_json || [],
    certificateCount: row.certificate_count,
    riskLevel: row.risk_level,
    riskClassification: row.risk_classification_json || {},
    takeoverIndicator: row.takeover_indicator_json || null,
    source: row.source,
    firstObserved: row.first_observed,
    lastObserved: row.last_observed,
  };
}

async function getScanDetailsById(scanId) {
  const scanRes = await query('SELECT * FROM scans WHERE id = $1', [scanId]);
  if (scanRes.rows.length === 0) return null;
  const s = scanRes.rows[0];

  const [stagesRes, assetsRes, dnsRes, expRes, cveRes, findRes] = await Promise.all([
    query('SELECT * FROM scan_stages WHERE scan_id = $1 ORDER BY stage_number ASC', [scanId]),
    query('SELECT * FROM assets WHERE scan_id = $1 ORDER BY subdomain ASC', [scanId]),
    query('SELECT * FROM dns_records WHERE scan_id = $1 ORDER BY hostname ASC, record_type ASC', [scanId]),
    query('SELECT * FROM ip_exposures WHERE scan_id = $1 ORDER BY ip_address ASC', [scanId]),
    query('SELECT * FROM cve_records WHERE scan_id = $1 ORDER BY cvss_score DESC NULLS LAST', [scanId]),
    query('SELECT * FROM findings WHERE scan_id = $1 ORDER BY id ASC', [scanId]),
  ]);

  return {
    id: s.id,
    domain: s.domain,
    status: s.status,
    currentStageNumber: s.current_stage_number,
    currentStageKey: s.current_stage_key,
    providerStatusSummary: s.provider_status_json || {},
    providerFailures: s.provider_failures_json || [],
    summary: s.summary_json || {},
    takeoverIndicators: s.takeover_indicators_json || [],
    startedAt: s.started_at,
    completedAt: s.completed_at,
    stages: stagesRes.rows.map((st) => ({
      stageNumber: st.stage_number,
      key: st.stage_key,
      label: st.stage_label,
      status: st.status,
      detail: st.detail,
      startedAt: st.started_at,
      completedAt: st.completed_at,
    })),
    assets: assetsRes.rows.map(mapAssetRow),
    dnsRecords: dnsRes.rows.map((r) => ({
      id: r.id,
      scanId: r.scan_id,
      hostname: r.hostname,
      recordType: r.record_type,
      value: r.value,
      ttl: r.ttl,
      provider: r.provider,
      resolutionStatus: r.resolution_status,
      lastObserved: r.last_observed,
    })),
    ipExposures: expRes.rows.map((e) => ({
      id: e.id,
      scanId: e.scan_id,
      ip: e.ip_address,
      status: e.status,
      openPorts: e.open_ports_json || [],
      hostnames: e.hostnames_json || [],
      cpes: e.cpes_json || [],
      cves: e.cves_json || [],
      tags: e.tags_json || [],
      associatedHostnames: e.associated_hostnames_json || [],
      source: e.source,
      lastEnrichedAt: e.last_enriched_at,
    })),
    vulnerabilities: cveRes.rows.map((v) => ({
      id: v.id,
      scanId: v.scan_id,
      cveId: v.cve_id,
      cvssScore: v.cvss_score !== null ? Number(v.cvss_score) : null,
      cvssVersion: v.cvss_version,
      severity: v.severity,
      description: v.description,
      affectedAssets: v.affected_assets_json || [],
      associatedIps: v.associated_ips_json || [],
      associatedCpes: v.associated_cpes_json || [],
      weaknesses: v.weaknesses_json || [],
      references: v.references_json || [],
      publishedDate: v.published_date,
      lastModifiedDate: v.last_modified_date,
      verificationStatus: v.verification_status,
      verificationNote: v.verification_note,
      source: v.source,
      retrievedAt: v.retrieved_at,
    })),
    findings: findRes.rows.map((f) => ({
      id: f.id,
      scanId: f.scan_id,
      findingType: f.finding_type,
      title: f.title,
      severity: f.severity,
      confidence: f.confidence,
      affectedAsset: f.affected_asset,
      ipAddress: f.ip_address,
      port: f.port,
      cnameTarget: f.cname_target,
      providerPattern: f.provider_pattern,
      cveId: f.cve_id,
      cvssScore: f.cvss_score !== null ? Number(f.cvss_score) : null,
      reason: f.reason,
      supportingEvidence: f.supporting_evidence,
      source: f.source,
      recommendedAction: f.recommended_action,
      timestamp: f.created_at,
    })),
  };
}

module.exports = {
  getAuthorizedDomainsList,
  createInitialScanRecord,
  updateScanStageProgress,
  saveCompletedScanResults,
  getScanDetailsById,
  mapAssetRow,
};
