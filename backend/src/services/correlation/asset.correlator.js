const { analyzeSubdomainTakeoverRisk } = require('../risk/takeover.analyzer');
const { classifyAssetRisk, SEVERITY_RANK } = require('../risk/risk.engine');

function inferHostingIndicator(dnsProfile, ipExposures = []) {
  const host = dnsProfile.hostname || '';
  const cname = (dnsProfile.cnameTargets || [])[0] || '';
  const ns = (dnsProfile.nameServers || []).join(' ');

  if (/\.vercel\.app$/i.test(host) || /vercel/i.test(cname)) return 'Vercel';
  if (/\.netlify\.app$/i.test(host) || /netlify/i.test(cname)) return 'Netlify';
  if (/\.github\.io$/i.test(host) || /github\.io/i.test(cname)) return 'GitHub Pages';
  if (/\.herokuapp\.com$/i.test(host) || /herokuapp|herokudns/i.test(cname)) return 'Heroku';
  if (/cloudflare/i.test(cname) || /cloudflare/i.test(ns)) return 'Cloudflare';
  if (/amazonaws|cloudfront|aws/i.test(cname) || /awsdns/i.test(ns)) return 'Amazon Web Services (AWS)';
  if (/azure|windows\.net|trafficmanager/i.test(cname) || /azure-dns/i.test(ns)) return 'Microsoft Azure';
  if (/fastly/i.test(cname)) return 'Fastly CDN';
  if (/google|1e100/i.test(cname) || /googledomains/i.test(ns)) return 'Google Cloud';
  if (/akamai|edgekey/i.test(cname)) return 'Akamai';

  for (const exp of ipExposures) {
    const hostStr = (exp.hostnames || []).join(' ');
    const tagStr = (exp.tags || []).join(' ');
    if (/cloudflare/i.test(hostStr) || /cdn/i.test(tagStr)) return 'CDN / Edge Network';
    if (/amazonaws/i.test(hostStr)) return 'Amazon Web Services (AWS)';
    if (/googleusercontent|1e100/i.test(hostStr)) return 'Google Cloud';
  }

  return dnsProfile.resolves ? 'Standard Public Hosting' : 'Unresolved / Dormant';
}

function correlateDomainAssets({
  cleanDomain,
  targetSubdomains,
  dnsProfilesMap,
  ipExposuresMap,
  enrichedCvesMap,
  providerFailures,
}) {
  const correlatedAssets = [];
  const allFindings = [];
  const takeoverIndicators = [];
  const nowIso = new Date().toISOString();

  for (const subEntry of targetSubdomains) {
    const hostname = subEntry.subdomain;
    const dnsProfile = dnsProfilesMap.get(hostname) || {
      hostname,
      resolves: false,
      resolutionStatus: 'UNRESOLVED',
      ipv4Addresses: [],
      ipv6Addresses: [],
      cnameTargets: [],
      records: [],
    };

    const assetIps = [...(dnsProfile.ipv4Addresses || []), ...(dnsProfile.ipv6Addresses || [])];
    const assetExposures = assetIps.map((ip) => ipExposuresMap.get(ip)).filter(Boolean);

    const portsSet = new Set();
    const cveIdsSet = new Set();
    const cpesSet = new Set();

    for (const exp of assetExposures) {
      (exp.openPorts || []).forEach((p) => portsSet.add(p));
      (exp.cves || []).forEach((c) => cveIdsSet.add(c));
      (exp.cpes || []).forEach((cpe) => cpesSet.add(cpe));
    }

    const assetEnrichedCves = Array.from(cveIdsSet).map(
      (id) =>
        enrichedCvesMap.get(id) || {
          cveId: id,
          severity: 'UNKNOWN',
          cvssScore: null,
          verificationStatus: 'CVE_ASSOCIATION_OBSERVED',
        }
    );

    const takeoverAnalysis = analyzeSubdomainTakeoverRisk(dnsProfile);
    if (takeoverAnalysis) {
      takeoverIndicators.push(takeoverAnalysis);
    }

    const risk = classifyAssetRisk({
      hostname,
      rootDomain: cleanDomain,
      dnsProfile,
      ipExposures: assetExposures,
      enrichedCves: assetEnrichedCves,
      takeoverAnalysis,
      providerFailures,
      evaluatedAt: nowIso,
    });

    risk.findings.forEach((f) => allFindings.push(f));

    const sources = [];
    if (!providerFailures.some((f) => f.startsWith('crt.sh'))) {
      sources.push('crt.sh');
    }
    if (dnsProfile.status === 'success') sources.push('Cloudflare DoH');
    if (assetExposures.some((e) => e.status === 'success')) sources.push('Shodan InternetDB');
    if (assetEnrichedCves.some((c) => c.status === 'success')) sources.push('NIST NVD');

    if (sources.length === 0) sources.push('Passive DNS Fallback');
    correlatedAssets.push({
      domain: cleanDomain,
      subdomain: hostname,
      ipAddress: (dnsProfile.ipv4Addresses || [])[0] || null,
      ipv4Addresses: dnsProfile.ipv4Addresses || [],
      ipv6Address: (dnsProfile.ipv6Addresses || [])[0] || null,
      ipv6Addresses: dnsProfile.ipv6Addresses || [],
      cname: (dnsProfile.cnameTargets || [])[0] || null,
      cnameTargets: dnsProfile.cnameTargets || [],
      hostingProvider: inferHostingIndicator(dnsProfile, assetExposures),
      dnsStatus: dnsProfile.resolutionStatus || 'UNKNOWN',
      resolves: Boolean(dnsProfile.resolves),
      exposedPorts: Array.from(portsSet).sort((a, b) => a - b),
      associatedCves: Array.from(cveIdsSet),
      cpes: Array.from(cpesSet),
      certificateCount: subEntry.certificateCount || 0,
      riskLevel: risk.riskLevel,
      riskClassification: {
        reason: risk.reason,
        supportingEvidence: risk.supportingEvidence,
        source: risk.source,
        confidence: risk.confidence,
        timestamp: risk.timestamp,
        recommendedAction: risk.recommendedAction,
        dataFreshness: risk.dataFreshness,
      },
      takeoverIndicator: takeoverAnalysis,
      firstObserved: nowIso,
      lastObserved: nowIso,
      source: sources.join(', '),
    });
  }

  allFindings.sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0));

  const riskDistribution = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Informational: 0,
  };
  for (const asset of correlatedAssets) {
    riskDistribution[asset.riskLevel] = (riskDistribution[asset.riskLevel] || 0) + 1;
  }

  return {
    correlatedAssets,
    allFindings,
    takeoverIndicators,
    riskDistribution,
  };
}

module.exports = {
  inferHostingIndicator,
  correlateDomainAssets,
};
