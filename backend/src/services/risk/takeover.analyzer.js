/**
 * Passive Subdomain Takeover Risk Analysis Module
 *
 * Strictly passive DNS misconfiguration analysis.
 * Never attempts to register, claim, or modify external cloud resources.
 *
 * Transparent Confidence Categories:
 * 1. Informational
 * 2. Suspicious
 * 3. Potentially vulnerable
 * 4. Verified misconfiguration
 * 5. Confirmed takeover
 */

const CLOUD_CNAME_PATTERNS = [
  {
    provider: 'GitHub Pages',
    pattern: /\.github\.io$/i,
    remediation: 'Remove the CNAME record if the GitHub Pages repository is decommissioned, or configure the custom domain in the authorized repository.',
  },
  {
    provider: 'Amazon S3',
    pattern: /\.s3([.-][a-z0-9-]+)?\.amazonaws\.com$/i,
    remediation: 'Delete the dangling CNAME record pointing to the unused S3 bucket endpoint or recreate the bucket within your AWS organization account.',
  },
  {
    provider: 'Heroku',
    pattern: /\.(herokuapp|herokudns)\.com$/i,
    remediation: 'Remove the DNS CNAME entry pointing to the decommissioned Heroku app or bind the custom domain in Heroku.',
  },
  {
    provider: 'Microsoft Azure',
    pattern: /\.(azurewebsites\.net|cloudapp\.net|azureedge\.net|trafficmanager\.net|blob\.core\.windows\.net|azure-api\.net)$/i,
    remediation: 'Remove the dangling CNAME record pointing to the unallocated Azure resource or reclaim the subdomain in Azure Portal.',
  },
  {
    provider: 'Fastly CDN',
    pattern: /\.fastly\.net$/i,
    remediation: 'Remove the CNAME pointing to Fastly if the service has been deleted, or add the domain to your active Fastly service configuration.',
  },
  {
    provider: 'Shopify',
    pattern: /\.myshopify\.com$/i,
    remediation: 'Delete the CNAME pointing to myshopify.com if the storefront is no longer active.',
  },
  {
    provider: 'Pantheon',
    pattern: /\.pantheonsite\.io$/i,
    remediation: 'Remove the CNAME record referencing the unused Pantheon environment.',
  },
  {
    provider: 'Ghost / Tumblr / WordPress.com',
    pattern: /\.(ghost\.io|domains\.tumblr\.com|wordpress\.com)$/i,
    remediation: 'Delete the stale CNAME record referencing the third-party publishing platform.',
  },
  {
    provider: 'Vercel / Netlify / Render',
    pattern: /\.(vercel\.app|netlify\.app|onrender\.com)$/i,
    remediation: 'Remove the CNAME record if the deployment project has been deleted, or bind the domain in your project settings.',
  },
  {
    provider: 'Amazon CloudFront / Elastic Beanstalk',
    pattern: /\.(cloudfront\.net|elasticbeanstalk\.com)$/i,
    remediation: 'Audit the CloudFront distribution or Elastic Beanstalk environment and delete dangling DNS records.',
  },
];

function detectCloudProviderPattern(cnameTarget) {
  if (!cnameTarget || typeof cnameTarget !== 'string') return null;
  const clean = cnameTarget.trim().toLowerCase().replace(/\.$/, '');
  for (const entry of CLOUD_CNAME_PATTERNS) {
    if (entry.pattern.test(clean)) {
      return entry;
    }
  }
  return null;
}

/**
 * Analyze a single hostname's DNS profile for passive subdomain takeover risk indicators.
 */
function analyzeSubdomainTakeoverRisk(dnsProfile) {
  const hostname = dnsProfile.hostname;
  const cnameTargets = Array.isArray(dnsProfile.cnameTargets) ? dnsProfile.cnameTargets : [];
  const resolves = Boolean(dnsProfile.resolves);
  const cnameTargetResolves = Boolean(dnsProfile.cnameTargetResolves);
  const cnameResolutionStatus = dnsProfile.cnameResolutionStatus || dnsProfile.resolutionStatus;
  const verificationDate = dnsProfile.retrievedAt || new Date().toISOString();

  if (cnameTargets.length === 0) {
    // Check if subdomain was discovered in Certificate Transparency but now returns NXDOMAIN
    if (dnsProfile.resolutionStatus === 'NXDOMAIN') {
      return {
        hasIndicator: false,
        affectedHostname: hostname,
        cnameDestination: null,
        detectedProviderPattern: null,
        confidence: 'Informational',
        severity: 'Informational',
        evidence: `Hostname "${hostname}" appears in historical certificates (crt.sh) but currently returns NXDOMAIN with no CNAME record.`,
        recommendedRemediation: 'No immediate takeover risk via CNAME. Ensure expired certificates are not reused.',
        verificationDate,
      };
    }
    return null;
  }

  const primaryCname = cnameTargets[0];
  const providerMatch = detectCloudProviderPattern(primaryCname);

  // Case 1: CNAME points to a known cloud service AND the CNAME target returns NXDOMAIN
  if (providerMatch && !cnameTargetResolves && cnameResolutionStatus === 'NXDOMAIN') {
    return {
      hasIndicator: true,
      affectedHostname: hostname,
      cnameDestination: primaryCname,
      detectedProviderPattern: providerMatch.provider,
      confidence: 'Verified misconfiguration',
      severity: 'High',
      evidence: `Dangling CNAME detected: "${hostname}" points to third-party cloud service "${primaryCname}" (${providerMatch.provider}), and the destination returns NXDOMAIN. Note: Passive DNS analysis verifies the dangling misconfiguration; it does not claim "Confirmed takeover" without active resource verification.`,
      recommendedRemediation: providerMatch.remediation,
      verificationDate,
    };
  }

  // Case 2: CNAME points to a known cloud service AND fails to resolve (SERVFAIL / UNRESOLVED / NODATA)
  if (providerMatch && !cnameTargetResolves) {
    return {
      hasIndicator: true,
      affectedHostname: hostname,
      cnameDestination: primaryCname,
      detectedProviderPattern: providerMatch.provider,
      confidence: 'Potentially vulnerable',
      severity: 'Medium',
      evidence: `CNAME "${hostname}" -> "${primaryCname}" matches ${providerMatch.provider} pattern and currently fails to resolve to an active IP (${cnameResolutionStatus}).`,
      recommendedRemediation: providerMatch.remediation,
      verificationDate,
    };
  }

  // Case 3: CNAME points to a non-cloud or generic external domain and returns NXDOMAIN (dangling CNAME)
  if (!providerMatch && !cnameTargetResolves && cnameResolutionStatus === 'NXDOMAIN') {
    return {
      hasIndicator: true,
      affectedHostname: hostname,
      cnameDestination: primaryCname,
      detectedProviderPattern: 'External / Custom CNAME Target',
      confidence: 'Suspicious',
      severity: 'Medium',
      evidence: `Dangling CNAME record: "${hostname}" points to "${primaryCname}", which returns NXDOMAIN. If the target domain or zone expires, it could be registered by an unauthorized party.`,
      recommendedRemediation: `Remove the dangling CNAME record for "${hostname}" pointing to "${primaryCname}" if the destination service is retired.`,
      verificationDate,
    };
  }

  // Case 4: CNAME points to a non-cloud target and does not resolve
  if (!providerMatch && !cnameTargetResolves) {
    return {
      hasIndicator: true,
      affectedHostname: hostname,
      cnameDestination: primaryCname,
      detectedProviderPattern: 'Unresolved CNAME Target',
      confidence: 'Suspicious',
      severity: 'Low',
      evidence: `CNAME "${hostname}" -> "${primaryCname}" did not resolve to an A/AAAA record (${cnameResolutionStatus}).`,
      recommendedRemediation: `Verify whether "${primaryCname}" is still an active internal or external endpoint.`,
      verificationDate,
    };
  }

  // Case 5: CNAME points to a known cloud service and resolves normally
  if (providerMatch && resolves) {
    return {
      hasIndicator: false,
      affectedHostname: hostname,
      cnameDestination: primaryCname,
      detectedProviderPattern: providerMatch.provider,
      confidence: 'Informational',
      severity: 'Informational',
      evidence: `CNAME "${hostname}" points to active ${providerMatch.provider} endpoint "${primaryCname}" which resolves normally. No dangling DNS indicator detected via passive DNS.`,
      recommendedRemediation: 'Maintain inventory of external cloud service bindings and remove DNS records prior to decommissioning cloud resources.',
      verificationDate,
    };
  }

  return null;
}

module.exports = {
  CLOUD_CNAME_PATTERNS,
  detectCloudProviderPattern,
  analyzeSubdomainTakeoverRisk,
};
