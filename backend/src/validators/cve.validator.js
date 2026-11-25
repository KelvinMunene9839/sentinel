const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/i;

function isValidCveId(cveId) {
  if (typeof cveId !== 'string') return false;
  return CVE_REGEX.test(cveId.trim());
}

module.exports = { isValidCveId };
