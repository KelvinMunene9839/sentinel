const config = require('../config');

const DOMAIN_REGEX = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;

function normalizeDomain(input) {
  if (typeof input !== 'string') return '';
  let clean = input.trim().toLowerCase();
  clean = clean.replace(/^https?:\/\//i, '');
  clean = clean.split('/')[0].split('?')[0].split('#')[0].split(':')[0];
  clean = clean.replace(/^\*\./, '');
  clean = clean.replace(/\.$/, '');
  return clean;
}

function isValidDomain(domain) {
  if (typeof domain !== 'string') return false;
  const raw = domain.trim();
  if (/^https?:\/\//i.test(raw) || raw.includes('/') || raw.includes(':')) return false;
  const clean = normalizeDomain(raw);
  if (!clean || clean.length > 253) return false;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(clean)) return false;
  return DOMAIN_REGEX.test(clean);
}

function isSubdomainOf(hostname, rootDomain) {
  const cleanHost = normalizeDomain(hostname);
  const cleanRoot = normalizeDomain(rootDomain);
  if (!isValidDomain(cleanHost) || !isValidDomain(cleanRoot)) return false;
  return cleanHost === cleanRoot || cleanHost.endsWith(`.${cleanRoot}`);
}

function isDomainAuthorized(domain, authorizedList = null) {
  const clean = normalizeDomain(domain);
  if (!isValidDomain(clean)) return false;

  const list = Array.isArray(authorizedList) && authorizedList.length > 0
    ? authorizedList
    : config.defaultAuthorizedDomains;

  return list.some((allowed) => {
    const cleanAllowed = normalizeDomain(allowed);
    return clean === cleanAllowed || clean.endsWith(`.${cleanAllowed}`);
  });
}

module.exports = {
  normalizeDomain,
  isValidDomain,
  isSubdomainOf,
  isDomainAuthorized,
};
