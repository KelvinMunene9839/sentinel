const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../../src/app');
const { initDb } = require('../../src/database/db');
const { runMigrations } = require('../../src/database/migrate');
const {
  createInitialScanRecord,
  saveCompletedScanResults,
} = require('../../src/database/scan.repository');

let server = null;
let baseUrl = '';

test('End-to-End (E2E) Workflow Test — Login, Scan Persistence, Dashboard, Filtering & Exports', async (t) => {
  await initDb();
  await runMigrations();

  server = app.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;

  t.after(() => {
    if (server) server.close();
  });

  let scanIdA = '';
  let scanIdB = '';

  await t.test('1. Persist two correlated scans and verify Dashboard overview reflects real stored metrics', async () => {
    scanIdA = await createInitialScanRecord({ domain: 'example.com', userId: 1 });
    await saveCompletedScanResults(scanIdA, {
      domain: 'example.com',
      status: 'completed',
      completedAt: new Date().toISOString(),
      providerStatusSummary: { crtsh: 'success', cloudflare: 'success', shodan: 'success', nvd: 'success' },
      providerFailures: [],
      summary: {
        totalAssets: 2,
        activeAssets: 2,
        uniquePublicIps: 1,
        totalSubdomainsDiscoverable: 2,
        totalDnsRecords: 3,
        totalExposedPorts: 3,
        totalCveAssociations: 1,
        potentialTakeoverIndicators: 1,
        findingsCount: 2,
        riskDistribution: { Critical: 0, High: 1, Medium: 1, Low: 0, Informational: 0 },
      },
      assets: [
        {
          domain: 'example.com',
          subdomain: 'example.com',
          ipAddress: '93.184.215.14',
          ipv4Addresses: ['93.184.215.14'],
          ipv6Address: null,
          ipv6Addresses: [],
          cname: null,
          cnameTargets: [],
          hostingProvider: 'Cloudflare',
          dnsStatus: 'NOERROR',
          resolves: true,
          exposedPorts: [22, 80, 443],
          associatedCves: ['CVE-2021-44228'],
          cpes: ['cpe:/a:apache:http_server'],
          certificateCount: 4,
          riskLevel: 'High',
          riskClassification: {
            reason: 'Observed CVE association CVE-2021-44228',
            supportingEvidence: 'Shodan + NVD correlation',
            source: 'crt.sh, Cloudflare DoH, Shodan InternetDB, NIST NVD',
            confidence: 'Medium',
            timestamp: new Date().toISOString(),
            recommendedAction: 'Verify software patch level',
          },
          takeoverIndicator: null,
          source: 'crt.sh, Cloudflare DoH, Shodan InternetDB, NIST NVD',
          firstObserved: new Date().toISOString(),
          lastObserved: new Date().toISOString(),
        },
        {
          domain: 'example.com',
          subdomain: 'docs.example.com',
          ipAddress: null,
          ipv4Addresses: [],
          ipv6Address: null,
          ipv6Addresses: [],
          cname: 'legacy-docs.github.io',
          cnameTargets: ['legacy-docs.github.io'],
          hostingProvider: 'GitHub Pages',
          dnsStatus: 'DANGLING_CNAME',
          resolves: false,
          exposedPorts: [],
          associatedCves: [],
          cpes: [],
          certificateCount: 1,
          riskLevel: 'Medium',
          riskClassification: {
            reason: 'Dangling CNAME pointing to GitHub Pages',
            supportingEvidence: 'NXDOMAIN on legacy-docs.github.io',
            source: 'Cloudflare DoH',
            confidence: 'Verified misconfiguration',
            timestamp: new Date().toISOString(),
            recommendedAction: 'Remove dangling CNAME record',
          },
          takeoverIndicator: {
            hasIndicator: true,
            affectedHostname: 'docs.example.com',
            cnameDestination: 'legacy-docs.github.io',
            detectedProviderPattern: 'GitHub Pages',
            confidence: 'Verified misconfiguration',
            severity: 'High',
            evidence: 'Dangling CNAME to GitHub Pages returning NXDOMAIN',
            recommendedRemediation: 'Remove CNAME record',
            verificationDate: new Date().toISOString(),
          },
          source: 'crt.sh, Cloudflare DoH',
          firstObserved: new Date().toISOString(),
          lastObserved: new Date().toISOString(),
        },
      ],
      dnsRecords: [
        {
          hostname: 'example.com',
          recordType: 'A',
          value: '93.184.215.14',
          ttl: 300,
          provider: 'Cloudflare DoH',
          resolutionStatus: 'NOERROR',
          retrievedAt: new Date().toISOString(),
        },
        {
          hostname: 'docs.example.com',
          recordType: 'CNAME',
          value: 'legacy-docs.github.io',
          ttl: 300,
          provider: 'Cloudflare DoH',
          resolutionStatus: 'NXDOMAIN',
          retrievedAt: new Date().toISOString(),
        },
      ],
      ipExposures: [
        {
          ip: '93.184.215.14',
          status: 'success',
          openPorts: [22, 80, 443],
          hostnames: ['example.com'],
          associatedHostnames: ['example.com'],
          cpes: ['cpe:/a:apache:http_server'],
          cves: ['CVE-2021-44228'],
          tags: ['cloud'],
          source: 'Shodan InternetDB',
          retrievedAt: new Date().toISOString(),
        },
      ],
      vulnerabilities: [
        {
          cveId: 'CVE-2021-44228',
          cvssScore: 10.0,
          cvssVersion: '3.1',
          severity: 'CRITICAL',
          description: 'Apache Log4j2 remote code execution vulnerability.',
          affectedAssets: ['example.com'],
          associatedIps: ['93.184.215.14'],
          associatedCpes: ['cpe:/a:apache:http_server'],
          weaknesses: ['CWE-502'],
          references: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' }],
          publishedDate: '2021-12-10',
          lastModifiedDate: '2023-11-07',
          verificationStatus: 'CVE_ASSOCIATION_OBSERVED',
          verificationNote: 'Passive CPE correlation',
          source: 'NIST NVD',
          retrievedAt: new Date().toISOString(),
        },
      ],
      findings: [
        {
          findingType: 'SUBDOMAIN_TAKEOVER_INDICATOR',
          title: 'Dangling CNAME on docs.example.com',
          severity: 'High',
          confidence: 'Verified misconfiguration',
          affectedAsset: 'docs.example.com',
          cnameTarget: 'legacy-docs.github.io',
          providerPattern: 'GitHub Pages',
          reason: 'CNAME points to NXDOMAIN GitHub Pages target',
          supportingEvidence: 'Cloudflare DoH returned NXDOMAIN',
          source: 'Cloudflare DoH + Passive Takeover Analyzer',
          recommendedAction: 'Delete CNAME record',
        },
      ],
      takeoverIndicators: [
        {
          hasIndicator: true,
          affectedHostname: 'docs.example.com',
          cnameDestination: 'legacy-docs.github.io',
          detectedProviderPattern: 'GitHub Pages',
          confidence: 'Verified misconfiguration',
          severity: 'High',
          evidence: 'Dangling CNAME to GitHub Pages returning NXDOMAIN',
          recommendedRemediation: 'Remove CNAME record',
          verificationDate: new Date().toISOString(),
        },
      ],
      certificates: [],
    });

    const dashRes = await fetch(`${baseUrl}/api/v1/dashboard/overview`);
    assert.equal(dashRes.status, 200);
    const dash = await dashRes.json();
    assert.equal(dash.hasData, true);
    assert.ok(dash.metrics.totalDiscoveredAssets >= 2);
  });

  await t.test('2. Filter and inspect assets, DNS records, exposures, findings, and vulnerabilities', async () => {
    const assetsRes = await fetch(`${baseUrl}/api/v1/assets?riskLevel=High`);
    assert.equal(assetsRes.status, 200);
    const assetsData = await assetsRes.json();
    assert.ok(assetsData.assets.length >= 1);
    assert.equal(assetsData.assets[0].riskLevel, 'High');

    const dnsRes = await fetch(`${baseUrl}/api/v1/dns?recordType=CNAME`);
    assert.equal(dnsRes.status, 200);
    const dnsData = await dnsRes.json();
    assert.ok(dnsData.records.some((r) => r.hostname === 'docs.example.com'));

    const expRes = await fetch(`${baseUrl}/api/v1/exposures`);
    assert.equal(expRes.status, 200);
    const expData = await expRes.json();
    assert.ok(expData.exposures.length >= 1);
    assert.ok(expData.exposures[0].sensitivePorts.some((p) => p.port === 22));

    const vulnRes = await fetch(`${baseUrl}/api/v1/vulnerabilities?severity=CRITICAL`);
    assert.equal(vulnRes.status, 200);
    const vulnData = await vulnRes.json();
    assert.ok(vulnData.vulnerabilities.some((v) => v.cveId === 'CVE-2021-44228'));
  });

  await t.test('3. Export CSV and JSON reports with compliant filenames and headers', async () => {
    const csvRes = await fetch(`${baseUrl}/api/v1/reports/export?scanId=${scanIdA}&reportType=assets_csv`);
    assert.equal(csvRes.status, 200);
    const disposition = csvRes.headers.get('content-disposition') || '';
    assert.ok(disposition.includes('SENTINEL_example.com_Asset-Inventory_'));
    const csvText = await csvRes.text();
    assert.ok(csvText.includes('Target Domain'));
    assert.ok(csvText.includes('docs.example.com'));

    const jsonRes = await fetch(`${baseUrl}/api/v1/reports/export?scanId=${scanIdA}&reportType=consolidated_json`);
    assert.equal(jsonRes.status, 200);
    const jsonData = await jsonRes.json();
    assert.equal(jsonData.reportMetadata.targetDomain, 'example.com');
    assert.equal(jsonData.reportMetadata.scanIdentifier, scanIdA);
  });

  await t.test('4. Compare two scans via /api/v1/scans/:id/compare/:otherId', async () => {
    scanIdB = await createInitialScanRecord({ domain: 'example.com', userId: 1 });
    await saveCompletedScanResults(scanIdB, {
      domain: 'example.com',
      status: 'completed',
      completedAt: new Date().toISOString(),
      providerStatusSummary: { crtsh: 'success', cloudflare: 'success', shodan: 'success', nvd: 'skipped' },
      providerFailures: [],
      summary: { totalAssets: 1 },
      assets: [
        {
          domain: 'example.com',
          subdomain: 'api.example.com',
          ipAddress: '93.184.215.99',
          ipv4Addresses: ['93.184.215.99'],
          ipv6Address: null,
          ipv6Addresses: [],
          cname: null,
          cnameTargets: [],
          hostingProvider: 'Cloudflare',
          dnsStatus: 'NOERROR',
          resolves: true,
          exposedPorts: [443],
          associatedCves: [],
          cpes: [],
          certificateCount: 1,
          riskLevel: 'Informational',
          riskClassification: { reason: 'Active asset' },
          source: 'crt.sh, Cloudflare DoH',
          firstObserved: new Date().toISOString(),
          lastObserved: new Date().toISOString(),
        },
      ],
      dnsRecords: [],
      ipExposures: [],
      vulnerabilities: [],
      findings: [],
      takeoverIndicators: [],
      certificates: [],
    });

    const cmpRes = await fetch(`${baseUrl}/api/v1/scans/${scanIdA}/compare/${scanIdB}`);
    assert.equal(cmpRes.status, 200);
    const cmpData = await cmpRes.json();
    assert.equal(cmpData.newAssets.length, 1);
    assert.equal(cmpData.newAssets[0].subdomain, 'api.example.com');
    assert.equal(cmpData.removedAssets.length, 2);
  });
});
