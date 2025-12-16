require('dotenv').config();
const mysql = require('mysql2/promise');

(async () => {
  try {
    const dsn = process.env.DATABASE_URL;
    if (!dsn) { console.error('No DATABASE_URL set'); process.exit(1); }
    const u = new URL(dsn);
    const dbName = u.pathname.replace(/^\//, '');
    const sslMode = (u.searchParams.get('ssl-mode') || u.searchParams.get('sslmode') || '').toUpperCase();
    let ssl;
    if (sslMode === 'REQUIRED') ssl = { rejectUnauthorized: false };

    const pool = await mysql.createPool({
      host: u.hostname,
      port: Number(u.port) || 3306,
      user: decodeURIComponent(u.username),
      password: decodeURIComponent(u.password),
      database: dbName,
      ssl,
      connectionLimit: 4,
      waitForConnections: true
    });

    const [countRows] = await pool.query('SELECT COUNT(*) AS n FROM user_mb_cdrs_backup');
    const before = countRows[0].n;

    await pool.query('DELETE FROM user_mb_cdrs_backup');

    const [afterRows] = await pool.query('SELECT COUNT(*) AS n FROM user_mb_cdrs_backup');
    const after = afterRows[0].n;

    console.log(JSON.stringify({ before, after }, null, 2));
    await pool.end();
  } catch (err) {
    console.error('delete-backup-error', err.message || err);
    process.exit(1);
  }
})();
