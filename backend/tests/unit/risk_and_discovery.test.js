const test = require('node:test');
const assert = require('node:assert/strict');

const {
  analyzeSubdomainTakeoverRisk,
} = require('../../src/services/risk/takeover.analyzer');
const {
  classifyAssetRisk,
} = require('../../src/services/risk/risk.engine');
const {
  executeDomainDiscoveryPipeline,
  compareScanResults,
} = require('../../src/services/discovery/discovery.orchestrator');

test('Passive Subdomain Takeover Risk Analysis', async (t) => {
  await t.test('detects dangling cloud CNAME with NXDOMAIN as Verified misconfiguration (not Confirmed takeover)', () => {
    const dnsProfile = {
      hostname: 'docs.example.com',
      resolves: false,
      cnameTargets: ['example-legacy.github.io'],
      cnameTargetResolves: false,
      cnameResolutionStatus: 'NXDOMAIN',
      retrievedAt: '2026-11-21T08:00:00Z',
    };
    const res = analyzeSubdomainTakeoverRisk(dnsProfile);
    assert.equal(res.hasIndicator, true);
    assert.equal(res.detectedProviderPattern, 'GitHub Pages');
    assert.equal(res.confidence, 'Verified misconfiguration');
    assert.equal(res.severity, 'High');
    assert.ok(res.evidence.includes('does not claim "Confirmed takeover"'));
  });

  await t.test('marks resolving cloud CNAME as Informational with no indicator', () => {
    const dnsProfile = {
      hostname: 'app.example.com',
      resolves: true,
      cnameTargets: ['prod-app.herokuapp.com'],
      cnameTargetResolves: true,
      cnameResolutionStatus: 'NOERROR',
      retrievedAt: '2026-11-21T08:00:00Z',
    };
    const res = analyzeSubdomainTakeoverRisk(dnsProfile);
    assert.equal(res.hasIndicator, false);
    assert.equal(res.confidence, 'Informational');
  });
});

test('Deterministic Risk Classification Engine', async (t) => {
  await t.test('classifies exposed sensitive ports and observed CVEs with explainable evidence', () => {
    const result = classifyAssetRisk({
      hostname: 'db.example.com',
      rootDomain: 'example.com',
      dnsProfile: {
        hostname: 'db.example.com',
        resolves: true,
        ipv4Addresses: ['93.184.215.14'],
      },
      ipExposures: [
        {
          status: 'success',
          ip: '93.184.215.14',
          openPorts: [22, 443, 6379],
          cpes: ['cpe:/a:redis:redis'],
          retrievedAt: '2026-11-21T08:00:00Z',
        },
      ],
      enrichedCves: [
        {
          cveId: 'CVE-2022-0543',
          cvssScore: 10.0,
          severity: 'CRITICAL',
          description: 'Redis Lua sandbox escape vulnerability.',
          verificationStatus: 'CVE_ASSOCIATION_OBSERVED',
        },
      ],
      takeoverAnalysis: null,
      providerFailures: [],
      evaluatedAt: '2026-11-21T08:00:00Z',
    });

    assert.equal(result.riskLevel, 'Critical');
    assert.ok(result.reason.includes('Redis'));
    assert.ok(result.reason.includes('CVE-2022-0543'));
    assert.ok(result.supportingEvidence.includes('CVE_ASSOCIATION_OBSERVED'));
    assert.ok(result.findings.length >= 2);
  });

  await t.test('never silently converts missing provider data into a safe/high-confidence result', () => {
    const result = classifyAssetRisk({
      hostname: 'api.example.com',
      rootDomain: 'example.com',
      dnsProfile: {
        hostname: 'api.example.com',
        resolves: true,
        ipv4Addresses: ['93.184.215.14'],
      },
      ipExposures: [],
      enrichedCves: [],
      takeoverAnalysis: null,
      providerFailures: ['Shodan InternetDB (timeout)'],
      evaluatedAt: '2026-11-21T08:00:00Z',
    });

    assert.equal(result.confidence, 'Partial (Incomplete Provider Data)');
    assert.equal(result.dataFreshness, 'INCOMPLETE_LIVE_SCAN');
    assert.ok(result.reason.includes('Incomplete intelligence'));
  });
});

test('Discovery Orchestrator Scope Validation & Scan Comparison', async (t) => {
  await t.test('rejects scans without explicit authorization confirmation', async () => {
    await assert.rejects(
      async () => {
        await executeDomainDiscoveryPipeline({
          domain: 'example.com',
          authorizationConfirmed: false,
        });
      },
      /Explicit authorization confirmation is required/
    );
  });

  await t.test('rejects scans for unauthorized domains outside allowlist', async () => {
    await assert.rejects(
      async () => {
        await executeDomainDiscoveryPipeline({
          domain: 'unauthorized-corp.internal',
          authorizationConfirmed: true,
          authorizedDomainsList: ['example.com'],
        });
      },
      /outside the configured authorized domain allowlist/
    );
  });

  await t.test('compares two scans to detect new assets, removed assets, port changes, and risk changes', () => {
    const scanA = {
      id: 'scan-1',
      domain: 'example.com',
      assets: [
        {
          subdomain: 'example.com',
          ipAddress: '93.184.215.14',
          cname: null,
          dnsStatus: 'NOERROR',
          exposedPorts: [80, 443],
          associatedCves: [],
          riskLevel: 'Informational',
        },
        {
          subdomain: 'legacy.example.com',
          ipAddress: '93.184.215.15',
          cname: null,
          dnsStatus: 'NOERROR',
          exposedPorts: [80],
          associatedCves: [],
          riskLevel: 'Low',
        },
      ],
    };

    const scanB = {
      id: 'scan-2',
      domain: 'example.com',
      assets: [
        {
          subdomain: 'example.com',
          ipAddress: '93.184.215.14',
          cname: null,
          dnsStatus: 'NOERROR',
          exposedPorts: [80, 443, 6379],
          associatedCves: ['CVE-2022-0543'],
          riskLevel: 'Critical',
        },
        {
          subdomain: 'new-api.example.com',
          ipAddress: '93.184.215.99',
          cname: null,
          dnsStatus: 'NOERROR',
          exposedPorts: [443],
          associatedCves: [],
          riskLevel: 'Informational',
        },
      ],
    };

    const diff = compareScanResults(scanA, scanB);
    assert.equal(diff.newAssets.length, 1);
    assert.equal(diff.newAssets[0].subdomain, 'new-api.example.com');
    assert.equal(diff.removedAssets.length, 1);
    assert.equal(diff.removedAssets[0].subdomain, 'legacy.example.com');
    assert.equal(diff.newExposedPorts.length, 1);
    assert.deepEqual(diff.newExposedPorts[0].addedPorts, [6379]);
    assert.equal(diff.newCveAssociations.length, 1);
    assert.deepEqual(diff.newCveAssociations[0].addedCves, ['CVE-2022-0543']);
    assert.equal(diff.riskChanges.length, 1);
    assert.equal(diff.riskChanges[0].currentRisk, 'Critical');
  });
});
