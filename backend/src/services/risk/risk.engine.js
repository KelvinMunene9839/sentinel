const {
  SENSITIVE_PORTS,
  SEVERITY_RANK,
  getHigherSeverity,
  classifyExposedPorts,
} = require('./port.rules');

function classifyAssetRisk(context) {
  const {
    hostname,
    rootDomain,
    dnsProfile = {},
    ipExposures = [],
    enrichedCves = [],
    takeoverAnalysis = null,
    providerFailures = [],
    evaluatedAt = new Date().toISOString(),
  } = context;

  let highestSeverity = 'Informational';
  const reasons = [];
  const evidenceItems = [];
  const sources = new Set();
  if (!providerFailures.some((f) => f.startsWith('crt.sh'))) {
    sources.add('crt.sh');
  }
  if (dnsProfile.status === 'success' || dnsProfile.resolves) {
    sources.add('Cloudflare DoH');
  }
  const actions = [];
  const findings = [];

  // 1. Flag missing provider data (never silently treat missing data as safe)
  if (providerFailures.length > 0) {
    const joined = providerFailures.join(', ');
    reasons.push(`Incomplete intelligence due to upstream provider failure(s): ${joined}`);
    evidenceItems.push(`Providers unavailable during scan: ${joined}`);
    actions.push('Re-run discovery or check provider status to verify unassessed exposure.');
  }

  // 2. Subdomain Takeover / Dangling DNS Indicator
  if (takeoverAnalysis && takeoverAnalysis.hasIndicator) {
    const sev = takeoverAnalysis.severity || 'Medium';
    highestSeverity = getHigherSeverity(highestSeverity, sev);
    reasons.push(`Subdomain takeover / dangling DNS indicator (${takeoverAnalysis.confidence})`);
    evidenceItems.push(takeoverAnalysis.evidence);
    actions.push(takeoverAnalysis.recommendedRemediation);

    findings.push({
      findingType: 'SUBDOMAIN_TAKEOVER_INDICATOR',
      title: `Dangling DNS / Potential Subdomain Takeover on ${hostname}`,
      severity: sev,
      confidence: takeoverAnalysis.confidence,
      affectedAsset: hostname,
      cnameTarget: takeoverAnalysis.cnameDestination,
      providerPattern: takeoverAnalysis.detectedProviderPattern,
      reason: `CNAME points to unresolved destination (${takeoverAnalysis.cnameDestination}).`,
      supportingEvidence: takeoverAnalysis.evidence,
      source: 'Cloudflare DoH + Passive Takeover Analyzer',
      timestamp: evaluatedAt,
      recommendedAction: takeoverAnalysis.recommendedRemediation,
    });
  }

  // 3. Root Domain DNS Policy Checks (SPF & CAA)
  if (hostname === rootDomain && dnsProfile.resolves) {
    const txtList = dnsProfile.txtRecords || [];
    const caaList = dnsProfile.caaRecords || [];

    if (!txtList.some((t) => /v=spf1/i.test(t))) {
      highestSeverity = getHigherSeverity(highestSeverity, 'Low');
      findings.push({
        findingType: 'DNS_CONFIGURATION',
        title: `Missing SPF TXT Policy on Root Domain (${hostname})`,
        severity: 'Low',
        confidence: 'Verified misconfiguration',
        affectedAsset: hostname,
        reason: 'No SPF (v=spf1) TXT record was observed on the root domain.',
        supportingEvidence: `Cloudflare DoH returned ${txtList.length} TXT record(s), none containing v=spf1.`,
        source: 'Cloudflare DoH',
        timestamp: evaluatedAt,
        recommendedAction: 'Publish an authoritative SPF TXT record to prevent email spoofing.',
      });
    }

    if (caaList.length === 0) {
      findings.push({
        findingType: 'DNS_CONFIGURATION',
        title: `No CAA Record on ${hostname}`,
        severity: 'Informational',
        confidence: 'Informational',
        affectedAsset: hostname,
        reason: 'No CAA DNS record restricts TLS certificate issuance for this domain.',
        supportingEvidence: `Cloudflare DoH CAA query for ${hostname} returned 0 records.`,
        source: 'Cloudflare DoH',
        timestamp: evaluatedAt,
        recommendedAction: 'Add CAA records to restrict certificate issuance to authorized CAs.',
      });
    }
  }

  // 4. Public IP Port Exposure (Shodan InternetDB)
  const allOpenPorts = new Set();
  for (const exp of ipExposures) {
    if (!exp || exp.status !== 'success') continue;
    sources.add('Shodan InternetDB');
    (exp.openPorts || []).forEach((p) => allOpenPorts.add(p));

    const { sensitiveExposures } = classifyExposedPorts(exp.openPorts);
    for (const sens of sensitiveExposures) {
      highestSeverity = getHigherSeverity(highestSeverity, sens.severity);
      reasons.push(`Sensitive service port ${sens.port} (${sens.service}) exposed on public IP ${exp.ip}`);
      evidenceItems.push(
        `Shodan InternetDB observed port ${sens.port} (${sens.service}) open on ${exp.ip} (${hostname}). Note: An exposed port is an exposure indicator, not a confirmed vulnerability.`
      );
      actions.push(`Restrict public access to port ${sens.port} (${sens.service}) on ${exp.ip}.`);

      findings.push({
        findingType: 'SENSITIVE_PORT_EXPOSURE',
        title: `Exposed ${sens.service} Port (${sens.port}) on ${exp.ip} (${hostname})`,
        severity: sens.severity,
        confidence: 'Medium',
        affectedAsset: hostname,
        ipAddress: exp.ip,
        port: sens.port,
        serviceName: sens.service,
        reason: sens.note,
        supportingEvidence: `Observed open port ${sens.port} on IP ${exp.ip} via Shodan InternetDB at ${exp.retrievedAt}.`,
        source: 'Shodan InternetDB',
        timestamp: evaluatedAt,
        recommendedAction: `Restrict port ${sens.port} (${sens.service}) via firewall or VPN.`,
      });
    }
  }

  // 5. Observed CVE Associations (NIST NVD + Shodan InternetDB)
  for (const cve of enrichedCves) {
    if (!cve || !cve.cveId) continue;
    sources.add('NIST NVD');

    const score = typeof cve.cvssScore === 'number' ? cve.cvssScore : null;
    let cveSev = 'Medium';
    if (score !== null) {
      if (score >= 9.0) cveSev = 'Critical';
      else if (score >= 7.0) cveSev = 'High';
      else if (score >= 4.0) cveSev = 'Medium';
      else cveSev = 'Low';
    } else if (cve.severity === 'CRITICAL') cveSev = 'Critical';
    else if (cve.severity === 'HIGH') cveSev = 'High';

    highestSeverity = getHigherSeverity(highestSeverity, cveSev);
    reasons.push(`Observed CVE association: ${cve.cveId} (CVSS: ${score ?? 'N/A'})`);
    evidenceItems.push(
      `${cve.cveId} associated via passive IP/CPE fingerprint on ${hostname}. Status: ${cve.verificationStatus}.`
    );
    actions.push(`Verify installed software version for ${cve.cveId} and apply vendor security patches.`);

    findings.push({
      findingType: 'CVE_ASSOCIATION_OBSERVED',
      title: `Observed Vulnerability Association: ${cve.cveId} on ${hostname}`,
      severity: cveSev,
      confidence: 'Medium (Passive CPE/IP Association - Unverified Patch Level)',
      affectedAsset: hostname,
      cveId: cve.cveId,
      cvssScore: score,
      reason: `Shodan associated ${cve.cveId} with ${hostname}. NVD CVSS score: ${score ?? 'N/A'} (${cve.severity}).`,
      supportingEvidence: `${cve.description} (Verification Status: ${cve.verificationStatus})`,
      source: 'Shodan InternetDB + NIST NVD',
      timestamp: evaluatedAt,
      recommendedAction: `Verify installed software build on ${hostname} before treating ${cve.cveId} as exploitable.`,
    });
  }

  // 6. Default baseline explanation
  if (reasons.length === 0) {
    if (dnsProfile.resolves) {
      reasons.push('Active DNS-resolving asset with no sensitive ports, dangling CNAMEs, or CVE associations.');
      evidenceItems.push(`Resolved via Cloudflare DoH (${(dnsProfile.ipv4Addresses || []).join(', ')})`);
      actions.push('Continue routine attack-surface monitoring.');
    } else {
      reasons.push('Historical certificate subdomain not currently resolving to an active public IP.');
      evidenceItems.push(`DNS status: ${dnsProfile.resolutionStatus || 'UNRESOLVED'}`);
      actions.push('Periodically review dormant DNS entries.');
    }
  }

  const confidence = providerFailures.length > 0
    ? 'Partial (Incomplete Provider Data)'
    : enrichedCves.length > 0
    ? 'Medium (Passive Intelligence Correlation)'
    : 'High (Authoritative Passive DNS & CT Verification)';

  return {
    riskLevel: highestSeverity,
    reason: reasons.join('; '),
    supportingEvidence: evidenceItems.join(' | '),
    source: Array.from(sources).join(', '),
    confidence,
    timestamp: evaluatedAt,
    recommendedAction: Array.from(new Set(actions)).join(' '),
    dataFreshness: providerFailures.length > 0 ? 'INCOMPLETE_LIVE_SCAN' : 'FRESH_LIVE_SCAN',
    findings,
  };
}

module.exports = {
  SENSITIVE_PORTS,
  SEVERITY_RANK,
  classifyExposedPorts,
  classifyAssetRisk,
};
