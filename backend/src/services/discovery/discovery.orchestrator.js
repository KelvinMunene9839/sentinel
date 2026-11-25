const {
  normalizeDomain,
  isValidDomain,
  isDomainAuthorized,
  validatePublicIp,
} = require('../../validators/network.validator');
const { discoverCertificates } = require('../providers/crtsh.service');
const { resolveHostnameProfile } = require('../providers/cloudflare.service');
const { enrichPublicIp } = require('../providers/shodan.service');
const { enrichCveBatch } = require('../providers/nvd.service');
const {
  inferHostingIndicator,
  correlateDomainAssets,
} = require('../correlation/asset.correlator');
const { compareScanResults } = require('../correlation/scan.comparator');

const SCAN_STAGE_DEFINITIONS = [
  { stageNumber: 1, key: 'VALIDATE_DOMAIN', label: 'Validate Target Domain' },
  { stageNumber: 2, key: 'VERIFY_SCOPE', label: 'Verify Authorization Scope' },
  { stageNumber: 3, key: 'QUERY_CRTSH', label: 'Query crt.sh Certificate Transparency' },
  { stageNumber: 4, key: 'NORMALIZE_SUBDOMAINS', label: 'Normalize Discovered Subdomains' },
  { stageNumber: 5, key: 'QUERY_CLOUDFLARE_DOH', label: 'Resolve DNS via Cloudflare DoH' },
  { stageNumber: 6, key: 'IDENTIFY_PUBLIC_IPS', label: 'Identify & Validate Public IPs' },
  { stageNumber: 7, key: 'QUERY_SHODAN_INTERNETDB', label: 'Enrich IPs via Shodan InternetDB' },
  { stageNumber: 8, key: 'EXTRACT_CVES', label: 'Extract Unique CVE Identifiers' },
  { stageNumber: 9, key: 'QUERY_NIST_NVD', label: 'Enrich CVEs via NIST NVD' },
  { stageNumber: 10, key: 'CORRELATE_FINDINGS', label: 'Correlate Assets, DNS, Exposures & CVEs' },
  { stageNumber: 11, key: 'CLASSIFY_RISK', label: 'Run Deterministic Risk & Takeover Engine' },
];

async function executeDomainDiscoveryPipeline(params) {
  const {
    domain,
    authorizationConfirmed = false,
    authorizedDomainsList = null,
    maxSubdomainsToResolve = 25,
    maxCvesToEnrich = 12,
    onStageUpdate = async () => {},
    providerOptions = {},
  } = params;

  const startedAt = new Date().toISOString();
  const stages = SCAN_STAGE_DEFINITIONS.map((s) => ({
    ...s,
    status: 'pending',
    startedAt: null,
    completedAt: null,
    detail: null,
  }));

  const providerFailures = [];
  const providerStatusSummary = {
    crtsh: 'pending',
    cloudflare: 'pending',
    shodan: 'pending',
    nvd: 'pending',
  };

  async function updateStage(stageNumber, status, detail) {
    const st = stages.find((s) => s.stageNumber === stageNumber);
    if (st) {
      if (status === 'in_progress' && !st.startedAt) st.startedAt = new Date().toISOString();
      if (['completed', 'partial', 'failed', 'skipped'].includes(status)) {
        st.completedAt = new Date().toISOString();
      }
      st.status = status;
      st.detail = detail;
    }
    await onStageUpdate({
      currentStageNumber: stageNumber,
      currentStageKey: st ? st.key : 'UNKNOWN',
      status,
      detail,
      stages: [...stages],
    });
  }

  // Stage 1: Validate domain
  await updateStage(1, 'in_progress', 'Validating domain format');
  const cleanDomain = normalizeDomain(domain);
  if (!isValidDomain(cleanDomain)) {
    await updateStage(1, 'failed', `Invalid domain syntax: "${domain}"`);
    const err = new Error(`Invalid target domain: "${domain}"`);
    err.statusCode = 400;
    throw err;
  }
  await updateStage(1, 'completed', `Normalized target domain: ${cleanDomain}`);

  // Stage 2: Verify scope & confirmation
  await updateStage(2, 'in_progress', 'Verifying explicit authorization confirmation and allowlist scope');
  if (!authorizationConfirmed) {
    await updateStage(2, 'failed', 'Explicit authorization confirmation was not provided');
    const err = new Error('Explicit authorization confirmation is required before starting passive discovery.');
    err.statusCode = 403;
    throw err;
  }
  if (!isDomainAuthorized(cleanDomain, authorizedDomainsList)) {
    await updateStage(2, 'failed', `Domain "${cleanDomain}" is not in the authorized allowlist`);
    const err = new Error(`Domain "${cleanDomain}" is outside the configured authorized domain allowlist.`);
    err.statusCode = 403;
    throw err;
  }
  await updateStage(2, 'completed', `Domain "${cleanDomain}" verified against authorized scope`);

  // Stage 3: Query crt.sh
  await updateStage(3, 'in_progress', `Querying crt.sh Certificate Transparency logs for ${cleanDomain}`);
  const CONCESSION_SUBDOMAINS = ['www', 'api', 'mail', 'dev', 'staging', 'app', 'portal', 'cdn', 'docs'];
  let crtResult = await discoverCertificates(cleanDomain, providerOptions.crtsh || {});
  if (crtResult.status === 'success') {
    providerStatusSummary.crtsh = 'success';
    await updateStage(3, 'completed', `Retrieved ${crtResult.certificates.length} unique certificate(s)`);
  } else {
    providerStatusSummary.crtsh = 'failed';
    providerFailures.push(`crt.sh (${crtResult.error || 'unavailable'})`);
    await updateStage(
      3,
      'partial',
      `crt.sh returned ${crtResult.error}; activating Cloudflare DoH subdomain discovery fallback`
    );

    // Passive DNS fallback: probe common enterprise subdomains via Cloudflare DoH when crt.sh is down
    if (!providerOptions.crtsh?.fetchImpl) {
      const candidateChecks = await Promise.all(
        CONCESSION_SUBDOMAINS.map(async (prefix) => {
          const fqdn = `${prefix}.${cleanDomain}`;
          const prof = await resolveHostnameProfile(fqdn, {
            recordTypes: ['A', 'AAAA', 'CNAME'],
            ...(providerOptions.cloudflare || {}),
          });
          return prof.resolves || (prof.cnameTargets && prof.cnameTargets.length > 0) ? fqdn : null;
        })
      );
      for (const foundFqdn of candidateChecks.filter(Boolean)) {
        if (!crtResult.subdomains.some((s) => s.subdomain === foundFqdn)) {
          crtResult.subdomains.push({
            subdomain: foundFqdn,
            rootDomain: cleanDomain,
            source: 'Cloudflare DoH',
            certificateCount: 0,
            issuers: [],
          });
        }
      }
    }
  }

  // Stage 4: Normalize subdomains
  await updateStage(4, 'in_progress', 'Deduplicating discovered subdomains');
  const allSubdomains = crtResult.subdomains || [];
  const sortedSubdomains = [...allSubdomains].sort((a, b) => {
    if (a.subdomain === cleanDomain) return -1;
    if (b.subdomain === cleanDomain) return 1;
    return (b.certificateCount || 0) - (a.certificateCount || 0);
  });
  const targetSubdomains = sortedSubdomains.slice(0, maxSubdomainsToResolve);
  await updateStage(4, 'completed', `Selected ${targetSubdomains.length}/${allSubdomains.length} subdomain(s) for DNS resolution`);

  // Stage 5: Query Cloudflare DoH
  await updateStage(5, 'in_progress', `Resolving DNS via Cloudflare DoH for ${targetSubdomains.length} hostname(s)`);
  const dnsProfilesMap = new Map();
  const allDnsRecords = [];
  let dohSuccessCount = 0;
  let dohFailCount = 0;

  for (let i = 0; i < targetSubdomains.length; i += 5) {
    const slice = targetSubdomains.slice(i, i + 5);
    const profiles = await Promise.all(
      slice.map((sub) => {
        const recordTypes = sub.subdomain === cleanDomain
          ? ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'CAA', 'SOA']
          : ['A', 'AAAA', 'CNAME', 'TXT'];
        return resolveHostnameProfile(sub.subdomain, {
          recordTypes,
          ...(providerOptions.cloudflare || {}),
        });
      })
    );
    for (const prof of profiles) {
      dnsProfilesMap.set(prof.hostname, prof);
      if (prof.status === 'success') dohSuccessCount += 1;
      else dohFailCount += 1;
      prof.records.forEach((r) => allDnsRecords.push(r));
    }
  }

  if (dohSuccessCount > 0) {
    providerStatusSummary.cloudflare = dohFailCount > 0 ? 'partial' : 'success';
    await updateStage(5, dohFailCount > 0 ? 'partial' : 'completed', `Resolved ${allDnsRecords.length} DNS records`);
  } else {
    providerStatusSummary.cloudflare = 'failed';
    providerFailures.push('Cloudflare DoH (all DNS queries failed)');
    await updateStage(5, 'failed', 'Cloudflare DoH failed to resolve target hostnames');
  }

  // Stage 6: Extract & validate public IPs
  await updateStage(6, 'in_progress', 'Validating public IPv4/IPv6 addresses');
  const uniquePublicIps = new Map();
  for (const prof of dnsProfilesMap.values()) {
    const ips = [...(prof.ipv4Addresses || []), ...(prof.ipv6Addresses || [])];
    for (const ip of ips) {
      const check = validatePublicIp(ip);
      if (check.valid) {
        if (!uniquePublicIps.has(check.ip)) {
          uniquePublicIps.set(check.ip, { ip: check.ip, version: check.version, associatedHostnames: [prof.hostname] });
        } else {
          const entry = uniquePublicIps.get(check.ip);
          if (!entry.associatedHostnames.includes(prof.hostname)) entry.associatedHostnames.push(prof.hostname);
        }
      }
    }
  }
  await updateStage(6, 'completed', `Identified ${uniquePublicIps.size} eligible public IP(s)`);

  // Stage 7: Query Shodan InternetDB
  await updateStage(7, 'in_progress', `Querying Shodan InternetDB for ${uniquePublicIps.size} IP(s)`);
  const ipExposuresMap = new Map();
  let shodanSuccess = 0;
  let shodanFailed = 0;

  const ipList = Array.from(uniquePublicIps.keys());
  for (let i = 0; i < ipList.length; i += 4) {
    const batch = await Promise.all(
      ipList.slice(i, i + 4).map((ip) => enrichPublicIp(ip, providerOptions.shodan || {}))
    );
    for (const res of batch) {
      const meta = uniquePublicIps.get(res.ip);
      ipExposuresMap.set(res.ip, { ...res, associatedHostnames: meta ? meta.associatedHostnames : [] });
      if (res.status === 'success' || res.status === 'not_indexed') shodanSuccess += 1;
      else if (res.status === 'failed') shodanFailed += 1;
    }
  }

  if (ipList.length === 0) {
    providerStatusSummary.shodan = 'skipped';
    await updateStage(7, 'completed', 'No public IPs to query');
  } else if (shodanSuccess > 0) {
    providerStatusSummary.shodan = shodanFailed > 0 ? 'partial' : 'success';
    await updateStage(7, shodanFailed > 0 ? 'partial' : 'completed', `Enriched ${shodanSuccess}/${ipList.length} IP(s)`);
  } else {
    providerStatusSummary.shodan = 'failed';
    providerFailures.push('Shodan InternetDB (unavailable)');
    await updateStage(7, 'partial', 'Shodan InternetDB unavailable; continuing with DNS & CT data');
  }

  // Stage 8: Extract CVEs
  await updateStage(8, 'in_progress', 'Extracting unique CVE identifiers');
  const cveToAssetsMap = new Map();
  for (const exp of ipExposuresMap.values()) {
    for (const cveId of exp.cves || []) {
      if (!cveToAssetsMap.has(cveId)) {
        cveToAssetsMap.set(cveId, {
          cveId,
          ips: new Set([exp.ip]),
          hostnames: new Set(exp.associatedHostnames || []),
          cpes: new Set(exp.cpes || []),
        });
      } else {
        const entry = cveToAssetsMap.get(cveId);
        entry.ips.add(exp.ip);
        (exp.associatedHostnames || []).forEach((h) => entry.hostnames.add(h));
        (exp.cpes || []).forEach((c) => entry.cpes.add(c));
      }
    }
  }
  const allUniqueCveIds = Array.from(cveToAssetsMap.keys());
  await updateStage(8, 'completed', `Extracted ${allUniqueCveIds.length} unique CVE(s)`);

  // Stage 9: Query NIST NVD
  const enrichedCvesMap = new Map();
  if (allUniqueCveIds.length === 0) {
    providerStatusSummary.nvd = 'skipped';
    await updateStage(9, 'completed', 'No CVEs observed; NIST NVD query skipped');
  } else {
    await updateStage(9, 'in_progress', `Enriching ${allUniqueCveIds.length} CVE(s) via NIST NVD`);
    const nvdBatch = await enrichCveBatch(allUniqueCveIds, {
      maxBatchSize: maxCvesToEnrich,
      ...(providerOptions.nvd || {}),
    });
    for (const rec of nvdBatch.records) {
      const assoc = cveToAssetsMap.get(rec.cveId);
      enrichedCvesMap.set(rec.cveId, {
        ...rec,
        affectedAssets: assoc ? Array.from(assoc.hostnames) : [],
        associatedIps: assoc ? Array.from(assoc.ips) : [],
        associatedCpes: assoc ? Array.from(assoc.cpes) : [],
      });
    }
    if (nvdBatch.enrichedCount > 0) {
      providerStatusSummary.nvd = nvdBatch.failedCount > 0 ? 'partial' : 'success';
      await updateStage(9, nvdBatch.failedCount > 0 ? 'partial' : 'completed', `Enriched ${nvdBatch.enrichedCount} CVE(s)`);
    } else {
      providerStatusSummary.nvd = 'failed';
      providerFailures.push('NIST NVD (unavailable)');
      await updateStage(9, 'partial', 'NIST NVD unavailable; keeping observed CVE associations');
    }
  }

  // Stage 10 & 11: Correlate & classify risk
  await updateStage(10, 'in_progress', 'Correlating assets, DNS, IPs, ports, and CVEs');
  const {
    correlatedAssets,
    allFindings,
    takeoverIndicators,
    riskDistribution,
  } = correlateDomainAssets({
    cleanDomain,
    targetSubdomains,
    dnsProfilesMap,
    ipExposuresMap,
    enrichedCvesMap,
    providerFailures,
  });
  await updateStage(10, 'completed', `Correlated ${correlatedAssets.length} asset(s)`);

  await updateStage(11, 'in_progress', 'Finalizing risk severity distribution');
  await updateStage(11, 'completed', `Generated ${allFindings.length} finding(s)`);

  return {
    domain: cleanDomain,
    status: providerFailures.length > 0 ? 'completed_with_warnings' : 'completed',
    startedAt,
    completedAt: new Date().toISOString(),
    providerStatusSummary,
    providerFailures,
    stages,
    summary: {
      totalAssets: correlatedAssets.length,
      activeAssets: correlatedAssets.filter((a) => a.resolves).length,
      uniquePublicIps: uniquePublicIps.size,
      totalSubdomainsDiscoverable: allSubdomains.length,
      totalDnsRecords: allDnsRecords.length,
      totalExposedPorts: Array.from(ipExposuresMap.values()).reduce(
        (acc, exp) => acc + (exp.openPorts ? exp.openPorts.length : 0),
        0
      ),
      totalCveAssociations: enrichedCvesMap.size,
      potentialTakeoverIndicators: takeoverIndicators.filter((t) => t.hasIndicator).length,
      findingsCount: allFindings.length,
      riskDistribution,
    },
    assets: correlatedAssets,
    dnsRecords: allDnsRecords,
    ipExposures: Array.from(ipExposuresMap.values()),
    vulnerabilities: Array.from(enrichedCvesMap.values()),
    certificates: crtResult.certificates || [],
    takeoverIndicators,
    findings: allFindings,
  };
}

module.exports = {
  SCAN_STAGE_DEFINITIONS,
  inferHostingIndicator,
  executeDomainDiscoveryPipeline,
  compareScanResults,
};
