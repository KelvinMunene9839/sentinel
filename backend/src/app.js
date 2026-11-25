const express = require('express');
const path = require('path');
const config = require('./config');
const { helmetHeaders } = require('./middleware/security');
const { attachSession } = require('./middleware/auth.middleware');
const { createRateLimiter } = require('./middleware/rateLimit.middleware');

const systemRoutes = require('./routes/system.routes');
const authRoutes = require('./routes/auth.routes');
const dashboardRoutes = require('./routes/dashboard.routes');
const scansRoutes = require('./routes/scans.routes');
const assetsRoutes = require('./routes/assets.routes');
const dnsRoutes = require('./routes/dns.routes');
const exposuresRoutes = require('./routes/exposures.routes');
const findingsRoutes = require('./routes/findings.routes');
const vulnerabilitiesRoutes = require('./routes/vulnerabilities.routes');
const reportsRoutes = require('./routes/reports.routes');

const app = express();

// Tag every response with X-Sentinel-Server header for HAProxy load balancing observability
app.use((req, res, next) => {
  res.setHeader('X-Sentinel-Server', config.serverId);
  next();
});

// Security headers
app.use(helmetHeaders);

// CORS protection
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && config.security.corsAllowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token');
  }
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

// Chrome DevTools well-known probe handler (eliminates console 404/CSP warning in Chrome)
app.get('/.well-known/appspecific/com.chrome.devtools.json', (req, res) => {
  res.status(200).json({});
});

// Body parsing with strict size limits
app.use(express.json({ limit: '512kb' }));
app.use(express.urlencoded({ extended: false, limit: '512kb' }));

// Attach session user if cookie present
app.use(attachSession);

// Global API rate limiter
app.use('/api/v1', createRateLimiter({ windowMs: 60000, maxRequests: 300 }));

// Mount Versioned REST API Routes
app.use('/api/v1', systemRoutes);
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/dashboard', dashboardRoutes);
app.use('/api/v1/scans', scansRoutes);
app.use('/api/v1/assets', assetsRoutes);
app.use('/api/v1/dns', dnsRoutes);
app.use('/api/v1/exposures', exposuresRoutes);
app.use('/api/v1/findings', findingsRoutes);
app.use('/api/v1/vulnerabilities', vulnerabilitiesRoutes);
app.use('/api/v1/reports', reportsRoutes);

// Serve Frontend Static Files (with explicit HTML route mappings and no-cache headers on HTML)
const frontendPath = path.resolve(__dirname, '../../frontend');
app.use(
  express.static(frontendPath, {
    extensions: ['html'],
    setHeaders(res, filePath) {
      if (filePath.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      }
    },
  })
);

const frontendPages = [
  'index',
  'login',
  'dashboard',
  'scans',
  'assets',
  'dns',
  'findings',
  'vulnerabilities',
  'reports',
];

for (const page of frontendPages) {
  app.get([`/${page}`, `/${page}.html`], (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.sendFile(path.join(frontendPath, `${page}.html`));
  });
}

// API 404 Handler
app.use('/api', (req, res) => {
  res.status(404).json({
    error: 'NotFound',
    message: `API endpoint ${req.method} ${req.originalUrl} does not exist`,
    serverId: config.serverId,
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  const status = err.statusCode || 500;
  res.status(status).json({
    error: err.name || 'InternalServerError',
    message:
      status === 500 && config.env === 'production'
        ? 'An unexpected server error occurred'
        : err.message,
    serverId: config.serverId,
  });
});

module.exports = app;
