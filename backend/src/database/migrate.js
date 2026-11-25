const fs = require('fs');
const path = require('path');
const { initDb, exec, query, closeDb } = require('./db');
const { hashPassword } = require('../utils/crypto');
const config = require('../config');
const logger = require('../utils/logger');

let migrationCompleted = false;

async function runMigrations() {
  if (migrationCompleted) return;
  await initDb();

  const sqlPath = path.resolve(__dirname, '../../migrations/001_initial_schema.sql');
  const sqlText = fs.readFileSync(sqlPath, 'utf8');
  await exec(sqlText);

  // Seed default roles
  const defaultRoles = [
    { name: 'Administrator', description: 'Full platform administration, scan management, and scope configuration' },
    { name: 'Security Analyst', description: 'Launch passive discovery scans, analyze assets/CVEs, and export reports' },
    { name: 'Read-only Auditor', description: 'View and export dashboards, scan history, assets, and compliance reports' },
  ];

  for (const r of defaultRoles) {
    await query(
      `INSERT INTO roles (name, description)
       VALUES ($1, $2)
       ON CONFLICT (name) DO NOTHING`,
      [r.name, r.description]
    );
  }

  // Seed default users for each role
  const rolesRes = await query('SELECT id, name FROM roles');
  const roleMap = new Map(rolesRes.rows.map((r) => [r.name, r.id]));

  const defaultUsers = [
    {
      username: 'admin',
      email: 'admin@sentinel.internal',
      password: 'AdminPassword123!',
      roleId: roleMap.get('Administrator'),
    },
    {
      username: 'analyst',
      email: 'analyst@sentinel.internal',
      password: 'AnalystPassword123!',
      roleId: roleMap.get('Security Analyst'),
    },
    {
      username: 'auditor',
      email: 'auditor@sentinel.internal',
      password: 'AuditorPassword123!',
      roleId: roleMap.get('Read-only Auditor'),
    },
  ];

  for (const u of defaultUsers) {
    if (!u.roleId) continue;
    const existing = await query('SELECT id FROM users WHERE username = $1', [u.username]);
    if (existing.rows.length === 0) {
      await query(
        `INSERT INTO users (username, email, password_hash, role_id)
         VALUES ($1, $2, $3, $4)`,
        [u.username, u.email, hashPassword(u.password), u.roleId]
      );
    }
  }

  // Seed default authorized domains
  for (const domain of config.defaultAuthorizedDomains) {
    await query(
      `INSERT INTO authorized_domains (domain, description)
       VALUES ($1, $2)
       ON CONFLICT (domain) DO NOTHING`,
      [domain, 'Default authorized reconnaissance target']
    );
  }

  migrationCompleted = true;
  logger.info('Database migrations and default seed data verified');
}

if (require.main === module) {
  runMigrations()
    .then(async () => {
      console.log('Migrations completed successfully.');
      await closeDb();
      process.exit(0);
    })
    .catch(async (err) => {
      console.error('Migration failed:', err);
      await closeDb();
      process.exit(1);
    });
}

module.exports = { runMigrations };
