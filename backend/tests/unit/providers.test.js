const test = require('node:test');
const assert = require('node:assert/strict');

const {
  normalizeDomain,
  isValidDomain,
  isSubdomainOf,
  isDomainAuthorized,
  validatePublicIp,
  isValidCveId,
} = require('../../src/validators/network.validator');

const {
  normalizeCrtshEntries,
  discoverCertificates,
} = require('../../src/services/providers/crtsh.service');

const {
  normalizeDohResponse,
  queryDnsRecordType,
} = require('../../src/services/providers/cloudflare.service');

const {
  normalizeInternetDbPayload,
  enrichPublicIp,
} = require('../../src/services/providers/shodan.service');

const {
  normalizeNvdCveItem,
  enrichCve,
} = require('../../src/services/providers/nvd.service');

const { clearProviderCache } = require('../../src/services/providers/http.client');

test('Domain & Network Validator unit tests', async (t) => {
  await t.test('validates and normalizes domain names accurately', () => {
    assert.equal(normalizeDomain('  *.Sub.Example.COM. '), 'sub.example.com');
    assert.equal(isValidDomain('example.com'), true);
    assert.equal(isValidDomain('api.dev.example.com'), true);
    assert.equal(isValidDomain('127.0.0.1'), false);
    assert.equal(isValidDomain('http://example.com'), false);
    assert.equal(isValidDomain('-invalid.com'), false);
    assert.equal(isSubdomainOf('a.b.example.com', 'example.com'), true);
    assert.equal(isSubdomainOf('evil-example.com', 'example.com'), false);
    assert.equal(isDomainAuthorized('sub.example.com', ['example.com']), true);
    assert.equal(isDomainAuthorized('unauthorized.org', ['example.com']), false);
  });

  await t.test('rejects private, loopback, link-local, multicast, and reserved IPs (SSRF prevention)', () => {
    assert.equal(validatePublicIp('127.0.0.1').valid, false);
    assert.equal(validatePublicIp('10.0.0.1').valid, false);
    assert.equal(validatePublicIp('172.16.5.4').valid, false);
    assert.equal(validatePublicIp('192.168.1.1').valid, false);
    assert.equal(validatePublicIp('169.254.169.254').valid, false); // Cloud metadata SSRF
    assert.equal(validatePublicIp('100.64.0.1').valid, false); // CGNAT
    assert.equal(validatePublicIp('224.0.0.1').valid, false); // Multicast
    assert.equal(validatePublicIp('::1').valid, false);
    assert.equal(validatePublicIp('fe80::1').valid, false);
    assert.equal(validatePublicIp('fc00::1').valid, false);

    // Valid public IPs
    assert.equal(validatePublicIp('1.1.1.1').valid, true);
    assert.equal(validatePublicIp('93.184.215.14').valid, true);
    assert.equal(validatePublicIp('2606:4700:4700::1111').valid, true);
  });

  await t.test('validates CVE ID format', () => {
    assert.equal(isValidCveId('CVE-2021-44228'), true);
    assert.equal(isValidCveId('cve-2024-12345'), true);
    assert.equal(isValidCveId('CVE-202-123'), false);
    assert.equal(isValidCveId('INVALID-123'), false);
  });
});

test('crt.sh provider normalization and error handling', async (t) => {
  clearProviderCache();

  await t.test('deduplicates subdomains, strips wildcards, and filters out-of-scope entries', () => {
    const sample = [
      {
        id: 101,
        common_name: '*.example.com',
        name_value: '*.example.com\nwww.example.com\napi.example.com\nadmin@example.com\notherdomain.org',
        issuer_name: 'DigiCert Inc',
        not_before: '2025-01-01T00:00:00',
        not_after: '2026-01-01T00:00:00',
      },
      {
        id: 102,
        common_name: 'www.example.com',
        name_value: 'WWW.EXAMPLE.COM',
        issuer_name: "Let's Encrypt",
      },
    ];

    const normalized = normalizeCrtshEntries(sample, 'example.com');
    const hostList = normalized.subdomains.map((s) => s.subdomain);
    assert.deepEqual(hostList, ['api.example.com', 'example.com', 'www.example.com']);
    const wwwRecord = normalized.subdomains.find((s) => s.subdomain === 'www.example.com');
    assert.equal(wwwRecord.certificateCount, 2);
    assert.equal(normalized.certificates.length, 2);
  });

  await t.test('handles malformed JSON from crt.sh gracefully without crashing', async () => {
    clearProviderCache();
    const fakeFetch = async () => ({
      status: 200,
      text: async () => '<html>502 Bad Gateway</html>',
      headers: new Map(),
    });
    const res = await discoverCertificates('example.com', {
      bypassCache: true,
      maxRetries: 0,
      fetchImpl: fakeFetch,
    });
    assert.equal(res.status, 'failed');
    assert.ok(res.error.includes('Invalid JSON'));
    assert.equal(res.subdomains.length, 1); // Fallback root domain preserved
  });
});

test('Cloudflare DoH provider normalization', async (t) => {
  clearProviderCache();
  const payload = {
    Status: 0,
    Answer: [
      { name: 'example.com.', type: 1, TTL: 300, data: '93.184.215.14' },
      { name: 'example.com.', type: 5, TTL: 300, data: 'target.example.net.' },
    ],
  };
  const normalized = normalizeDohResponse('example.com', 'A', payload, '2026-11-21T08:00:00Z');
  assert.equal(normalized.status, 'NOERROR');
  assert.equal(normalized.records.length, 2);
  assert.equal(normalized.records[0].recordType, 'A');
  assert.equal(normalized.records[0].value, '93.184.215.14');
  assert.equal(normalized.records[1].recordType, 'CNAME');
  assert.equal(normalized.records[1].value, 'target.example.net');
});

test('Shodan InternetDB provider normalization and private IP rejection', async (t) => {
  clearProviderCache();

  await t.test('rejects private IP addresses before making external requests', async () => {
    const res = await enrichPublicIp('192.168.1.50');
    assert.equal(res.status, 'rejected');
    assert.ok(res.error.includes('not eligible'));
  });

  await t.test('normalizes InternetDB response accurately', () => {
    const raw = {
      ip: '1.1.1.1',
      ports: [443, 80, 53, 80],
      hostnames: ['one.one.one.one'],
      cpes: ['cpe:/a:cloudflare:dns'],
      vulns: ['cve-2023-12345', 'INVALID'],
      tags: ['cdn', 'cloud'],
    };
    const norm = normalizeInternetDbPayload('1.1.1.1', raw, '2026-11-21T08:00:00Z');
    assert.deepEqual(norm.openPorts, [53, 80, 443]);
    assert.deepEqual(norm.cves, ['CVE-2023-12345']);
    assert.deepEqual(norm.tags, ['cdn', 'cloud']);
  });
});

test('NIST NVD provider normalization and evidence distinction', async (t) => {
  clearProviderCache();
  const sampleCve = {
    id: 'CVE-2021-44228',
    published: '2021-12-10T10:15:09.143',
    lastModified: '2023-11-07T03:39:36.750',
    vulnStatus: 'Analyzed',
    descriptions: [{ lang: 'en', value: 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.' }],
    metrics: {
      cvssMetricV31: [
        {
          type: 'Primary',
          cvssData: {
            version: '3.1',
            vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            baseScore: 10.0,
            baseSeverity: 'CRITICAL',
          },
        },
      ],
    },
    weaknesses: [{ description: [{ lang: 'en', value: 'CWE-502' }] }],
    references: [{ url: 'https://logging.apache.org/log4j/2.x/security.html', source: 'Apache' }],
  };

  const norm = normalizeNvdCveItem(sampleCve, '2026-11-21T08:00:00Z');
  assert.equal(norm.cveId, 'CVE-2021-44228');
  assert.equal(norm.cvssScore, 10.0);
  assert.equal(norm.cvssVersion, '3.1');
  assert.equal(norm.severity, 'CRITICAL');
  assert.equal(norm.verificationStatus, 'CVE_ASSOCIATION_OBSERVED');
  assert.deepEqual(norm.weaknesses, ['CWE-502']);
});
