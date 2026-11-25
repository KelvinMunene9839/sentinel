function escapeCsvCell(val) {
  if (val === null || val === undefined) return '""';
  const str = typeof val === 'object' ? JSON.stringify(val) : String(val);
  // Prevent CSV formula injection
  const safeStr = /^[=+\-@]/.test(str) ? `'${str}` : str;
  return `"${safeStr.replace(/"/g, '""')}"`;
}

function buildCsvString(headers, rows) {
  const headerLine = headers.map(escapeCsvCell).join(',');
  const dataLines = rows.map((row) => row.map(escapeCsvCell).join(','));
  return [headerLine, ...dataLines].join('\r\n');
}

function formatExportFilename(domain, reportType, extension) {
  const cleanDomain = String(domain || 'all-domains').replace(/[^a-zA-Z0-9.-]/g, '_');
  const datePart = new Date().toISOString().slice(0, 10);
  return `SENTINEL_${cleanDomain}_${reportType}_${datePart}.${extension}`;
}

function generateAssetInventoryCsv(scan) {
  const headers = [
    'Target Domain',
    'Scan Identifier',
    'Scan Date',
    'Subdomain',
    'IPv4 Address',
    'IPv6 Address',
    'CNAME',
    'Hosting Provider',
    'DNS Status',
    'Exposed Ports',
    'Associated CVEs',
    'Risk Classification',
    'Risk Reason',
    'Finding Evidence',
    'Confidence',
    'Data Source',
    'Retrieval Timestamp',
    'Limitations & Unavailable Providers',
  ];

  const limitations = (scan.providerFailures || []).length > 0
    ? `Unavailable providers: ${scan.providerFailures.join('; ')}`
    : 'All external intelligence providers operational';

  const rows = (scan.assets || []).map((a) => [
    scan.domain,
    scan.id,
    scan.completedAt || scan.startedAt,
    a.subdomain,
    (a.ipv4Addresses || []).join('; ') || a.ipAddress || '',
    (a.ipv6Addresses || []).join('; ') || a.ipv6Address || '',
    a.cname || '',
    a.hostingProvider || '',
    a.dnsStatus,
    (a.exposedPorts || []).join('; '),
    (a.associatedCves || []).join('; '),
    a.riskLevel,
    a.riskClassification?.reason || '',
    a.riskClassification?.supportingEvidence || '',
    a.riskClassification?.confidence || '',
    a.source,
    a.lastObserved,
    limitations,
  ]);

  return {
    filename: formatExportFilename(scan.domain, 'Asset-Inventory', 'csv'),
    contentType: 'text/csv; charset=utf-8',
    content: buildCsvString(headers, rows),
  };
}

function generateVulnerabilityCsv(scan) {
  const headers = [
    'Target Domain',
    'Scan Identifier',
    'Scan Date',
    'CVE Identifier',
    'CVSS Score',
    'CVSS Version',
    'Severity',
    'Verification Status',
    'Affected Assets',
    'Associated IPs',
    'Associated CPEs',
    'Description',
    'Published Date',
    'Data Source',
    'Retrieval Timestamp',
    'Limitations & Unavailable Providers',
  ];

  const limitations = (scan.providerFailures || []).length > 0
    ? `Unavailable providers: ${scan.providerFailures.join('; ')}`
    : 'Passive CPE/IP observation only; patch level not actively verified';

  const rows = (scan.vulnerabilities || []).map((v) => [
    scan.domain,
    scan.id,
    scan.completedAt || scan.startedAt,
    v.cveId,
    v.cvssScore ?? 'N/A',
    v.cvssVersion || 'N/A',
    v.severity,
    v.verificationStatus,
    (v.affectedAssets || []).join('; '),
    (v.associatedIps || []).join('; '),
    (v.associatedCpes || []).join('; '),
    v.description,
    v.publishedDate || '',
    v.source || 'NIST NVD + Shodan InternetDB',
    v.retrievedAt,
    limitations,
  ]);

  return {
    filename: formatExportFilename(scan.domain, 'Vulnerability-Report', 'csv'),
    contentType: 'text/csv; charset=utf-8',
    content: buildCsvString(headers, rows),
  };
}

function generateDnsInventoryCsv(scan) {
  const headers = [
    'Target Domain',
    'Scan Identifier',
    'Scan Date',
    'Hostname',
    'Record Type',
    'Value',
    'TTL',
    'Resolution Status',
    'Provider',
    'Retrieval Timestamp',
    'Limitations & Unavailable Providers',
  ];

  const limitations = (scan.providerFailures || []).join('; ') || 'None';

  const rows = (scan.dnsRecords || []).map((r) => [
    scan.domain,
    scan.id,
    scan.completedAt || scan.startedAt,
    r.hostname,
    r.recordType,
    r.value,
    r.ttl ?? '',
    r.resolutionStatus,
    r.provider,
    r.lastObserved,
    limitations,
  ]);

  return {
    filename: formatExportFilename(scan.domain, 'DNS-Inventory', 'csv'),
    contentType: 'text/csv; charset=utf-8',
    content: buildCsvString(headers, rows),
  };
}

function generateConsolidatedJsonReport(scan) {
  const payload = {
    reportMetadata: {
      platform: 'SENTINEL Cloud & Enterprise Attack Surface Intelligence Platform',
      reportType: 'Consolidated Passive Reconnaissance & Attack Surface Report',
      targetDomain: scan.domain,
      scanIdentifier: scan.id,
      scanStartedAt: scan.startedAt,
      scanCompletedAt: scan.completedAt,
      scanStatus: scan.status,
      generatedAt: new Date().toISOString(),
      dataSources: ['crt.sh', 'Cloudflare DNS-over-HTTPS', 'Shodan InternetDB', 'NIST NVD v2.0'],
      providerStatusSummary: scan.providerStatusSummary,
      limitationsAndUnavailableProviders: {
        unavailableProviders: scan.providerFailures || [],
        methodologyNotice:
          'All findings are derived from passive reconnaissance. Observed CVE associations reflect passive IP/CPE correlation and must be verified against installed software patch levels before assuming exploitability.',
        shodanLicensingNotice:
          'Shodan InternetDB data is provided for non-commercial use. Commercial deployment requires a separate Shodan commercial license review.',
      },
    },
    executiveSummary: scan.summary,
    assets: scan.assets,
    findings: scan.findings,
    subdomainTakeoverIndicators: scan.takeoverIndicators,
    vulnerabilities: scan.vulnerabilities,
    ipExposures: scan.ipExposures,
    dnsRecords: scan.dnsRecords,
  };

  return {
    filename: formatExportFilename(scan.domain, 'Consolidated-Report', 'json'),
    contentType: 'application/json; charset=utf-8',
    content: JSON.stringify(payload, null, 2),
  };
}

module.exports = {
  formatExportFilename,
  generateAssetInventoryCsv,
  generateVulnerabilityCsv,
  generateDnsInventoryCsv,
  generateConsolidatedJsonReport,
};
