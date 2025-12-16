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

    const userId = 1;           // portal user id for 876544
    const magnusUserId = '2';   // Magnus user id for 876544

    // 1) Ensure backup table exists
    await pool.query('CREATE TABLE IF NOT EXISTS user_mb_cdrs_backup LIKE user_mb_cdrs');

    // 2) Counts before
    const [beforeMainRows] = await pool.query('SELECT COUNT(*) AS n FROM user_mb_cdrs WHERE user_id = ?', [userId]);
    const beforeMain = beforeMainRows[0].n;
    const [beforeBackupRows] = await pool.query('SELECT COUNT(*) AS n FROM user_mb_cdrs_backup WHERE user_id = ?', [userId]);
    const beforeBackup = beforeBackupRows[0].n;

    // 3) Backup current rows for this user
    const [insertRes] = await pool.query(
      'INSERT INTO user_mb_cdrs_backup SELECT * FROM user_mb_cdrs WHERE user_id = ?',
      [userId]
    );

    const [afterBackupRows] = await pool.query('SELECT COUNT(*) AS n FROM user_mb_cdrs_backup WHERE user_id = ?', [userId]);
    const afterBackup = afterBackupRows[0].n;

    // 4) Delete from main mirror
    const [deleteMainRes] = await pool.query('DELETE FROM user_mb_cdrs WHERE user_id = ?', [userId]);
    const [afterMainRows] = await pool.query('SELECT COUNT(*) AS n FROM user_mb_cdrs WHERE user_id = ?', [userId]);
    const afterMain = afterMainRows[0].n;

    // 5) Reset import cursor for this Magnus user
    const [deleteCursorRes] = await pool.query('DELETE FROM cdr_import_cursors WHERE magnus_user_id = ?', [magnusUserId]);

    console.log(JSON.stringify({
      userId,
      magnusUserId,
      beforeMain,
      beforeBackup,
      insertedToBackup: insertRes.affectedRows || 0,
      afterBackup,
      deletedFromMain: deleteMainRes.affectedRows || 0,
      afterMain,
      cursorsDeleted: deleteCursorRes.affectedRows || 0
    }, null, 2));

    await pool.end();
  } catch (err) {
    console.error('cleanup-error', err.message || err);
    process.exit(1);
  }
})();
