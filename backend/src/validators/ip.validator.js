const net = require('net');

function isPrivateOrReservedIPv4(ip) {
  const parts = ip.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return true;
  }
  const [a, b, c] = parts;

  if (a === 0 || a === 10 || a === 127) return true; // 0/8, 10/8, 127/8
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64/10 CGNAT
  if (a === 169 && b === 254) return true;           // 169.254/16 Link-local / Cloud Metadata
  if (a === 172 && b >= 16 && b <= 31) return true;  // 172.16/12 Private
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true; // 192.0.0/24, 192.0.2/24
  if (a === 192 && b === 168) return true;           // 192.168/16 Private
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18/15 Benchmarking
  if (a === 198 && b === 51 && c === 100) return true;  // 198.51.100/24 TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true;   // 203.0.113/24 TEST-NET-3
  if (a >= 224) return true;                         // 224/4 Multicast & 240/4 Reserved

  return false;
}

function isPrivateOrReservedIPv6(ip) {
  const normalized = ip.trim().toLowerCase();
  if (normalized === '::' || normalized === '::1') return true;

  if (normalized.startsWith('::ffff:')) {
    const ipv4Part = normalized.replace('::ffff:', '');
    if (net.isIPv4(ipv4Part)) return isPrivateOrReservedIPv4(ipv4Part);
  }

  if (/^fe[89ab][0-9a-f]:/.test(normalized)) return true; // fe80::/10 Link-local
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true; // fc00::/7 Unique local
  if (normalized.startsWith('ff')) return true; // ff00::/8 Multicast
  if (normalized.startsWith('2001:db8:') || normalized.startsWith('2001:0db8:')) return true;

  return false;
}

function validatePublicIp(ip) {
  if (typeof ip !== 'string') {
    return { valid: false, reason: 'IP must be a string' };
  }
  const clean = ip.trim();
  const version = net.isIP(clean);

  if (version === 4) {
    if (isPrivateOrReservedIPv4(clean)) {
      return { valid: false, reason: 'Private, loopback, link-local, or reserved IPv4 is not eligible for public enrichment' };
    }
    return { valid: true, version: 4, ip: clean };
  }

  if (version === 6) {
    if (isPrivateOrReservedIPv6(clean)) {
      return { valid: false, reason: 'Private, loopback, link-local, or reserved IPv6 is not eligible for public enrichment' };
    }
    return { valid: true, version: 6, ip: clean.toLowerCase() };
  }

  return { valid: false, reason: 'Malformed IP address' };
}

module.exports = {
  isPrivateOrReservedIPv4,
  isPrivateOrReservedIPv6,
  validatePublicIp,
};
