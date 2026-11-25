function compareScanResults(baseScan, targetScan) {
  const baseAssetsMap = new Map((baseScan.assets || []).map((a) => [a.subdomain, a]));
  const targetAssetsMap = new Map((targetScan.assets || []).map((a) => [a.subdomain, a]));

  const newAssets = [];
  const removedAssets = [];
  const newExposedPorts = [];
  const newCveAssociations = [];
  const dnsChanges = [];
  const riskChanges = [];

  for (const [subdomain, targetAsset] of targetAssetsMap.entries()) {
    const baseAsset = baseAssetsMap.get(subdomain);
    if (!baseAsset) {
      newAssets.push({
        subdomain,
        ipAddress: targetAsset.ipAddress,
        riskLevel: targetAsset.riskLevel,
      });
      continue;
    }

    const basePorts = new Set(baseAsset.exposedPorts || []);
    const addedPorts = (targetAsset.exposedPorts || []).filter((p) => !basePorts.has(p));
    if (addedPorts.length > 0) {
      newExposedPorts.push({
        subdomain,
        ipAddress: targetAsset.ipAddress,
        addedPorts,
      });
    }

    const baseCves = new Set(baseAsset.associatedCves || []);
    const addedCves = (targetAsset.associatedCves || []).filter((c) => !baseCves.has(c));
    if (addedCves.length > 0) {
      newCveAssociations.push({ subdomain, addedCves });
    }

    if (
      baseAsset.ipAddress !== targetAsset.ipAddress ||
      baseAsset.cname !== targetAsset.cname ||
      baseAsset.dnsStatus !== targetAsset.dnsStatus
    ) {
      dnsChanges.push({
        subdomain,
        before: {
          ipAddress: baseAsset.ipAddress,
          cname: baseAsset.cname,
          dnsStatus: baseAsset.dnsStatus,
        },
        after: {
          ipAddress: targetAsset.ipAddress,
          cname: targetAsset.cname,
          dnsStatus: targetAsset.dnsStatus,
        },
      });
    }

    if (baseAsset.riskLevel !== targetAsset.riskLevel) {
      riskChanges.push({
        subdomain,
        previousRisk: baseAsset.riskLevel,
        currentRisk: targetAsset.riskLevel,
      });
    }
  }

  for (const [subdomain, baseAsset] of baseAssetsMap.entries()) {
    if (!targetAssetsMap.has(subdomain)) {
      removedAssets.push({
        subdomain,
        previousIpAddress: baseAsset.ipAddress,
        previousRiskLevel: baseAsset.riskLevel,
      });
    }
  }

  return {
    baseScanId: baseScan.id || null,
    targetScanId: targetScan.id || null,
    domain: targetScan.domain || baseScan.domain,
    comparedAt: new Date().toISOString(),
    newAssets,
    removedAssets,
    newExposedPorts,
    newCveAssociations,
    dnsChanges,
    riskChanges,
  };
}

module.exports = { compareScanResults };
