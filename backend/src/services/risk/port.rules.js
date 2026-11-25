const SENSITIVE_PORTS = {
  21: { service: 'FTP', severity: 'Medium', note: 'Cleartext file transfer protocol exposed publicly.' },
  22: { service: 'SSH', severity: 'Low', note: 'Remote shell exposed; require SSH keys and fail2ban.' },
  23: { service: 'Telnet', severity: 'High', note: 'Unencrypted legacy remote access port exposed.' },
  25: { service: 'SMTP', severity: 'Low', note: 'Mail transfer port exposed; verify relay & SPF/DMARC.' },
  445: { service: 'SMB', severity: 'High', note: 'SMB file sharing exposed to the public internet.' },
  1433: { service: 'MSSQL', severity: 'High', note: 'Microsoft SQL Server port exposed publicly.' },
  1521: { service: 'Oracle DB', severity: 'High', note: 'Oracle Database listener exposed publicly.' },
  2375: { service: 'Docker API', severity: 'Critical', note: 'Unencrypted Docker socket port exposed.' },
  3306: { service: 'MySQL', severity: 'High', note: 'MySQL database port exposed publicly.' },
  3389: { service: 'RDP', severity: 'High', note: 'Remote Desktop Protocol exposed publicly.' },
  5432: { service: 'PostgreSQL', severity: 'High', note: 'PostgreSQL database port exposed publicly.' },
  5601: { service: 'Kibana', severity: 'Medium', note: 'Kibana dashboard port exposed publicly.' },
  5900: { service: 'VNC', severity: 'High', note: 'VNC remote desktop port exposed publicly.' },
  6379: { service: 'Redis', severity: 'High', note: 'Redis key-value store port exposed publicly.' },
  9200: { service: 'Elasticsearch', severity: 'High', note: 'Elasticsearch HTTP API exposed publicly.' },
  11211: { service: 'Memcached', severity: 'High', note: 'Memcached service port exposed publicly.' },
  27017: { service: 'MongoDB', severity: 'High', note: 'MongoDB database port exposed publicly.' },
};

const SEVERITY_RANK = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Informational: 1,
};

function getHigherSeverity(sevA, sevB) {
  return (SEVERITY_RANK[sevA] || 1) >= (SEVERITY_RANK[sevB] || 1) ? sevA : sevB;
}

function classifyExposedPorts(openPorts = []) {
  const sensitiveExposures = [];
  const standardPorts = [];

  for (const port of openPorts) {
    const p = Number(port);
    if (SENSITIVE_PORTS[p]) {
      sensitiveExposures.push({ port: p, ...SENSITIVE_PORTS[p] });
    } else {
      standardPorts.push(p);
    }
  }

  return { sensitiveExposures, standardPorts };
}

module.exports = {
  SENSITIVE_PORTS,
  SEVERITY_RANK,
  getHigherSeverity,
  classifyExposedPorts,
};
