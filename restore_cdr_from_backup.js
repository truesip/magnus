require('dotenv').config();
const mysql = require('mysql2/promise');

function belongsToUserRaw(row, idUser, username, email) {
  if (!row || typeof row !== 'object') return false;
  const idStr = String(idUser || '');
  const u = (username || '').toString().toLowerCase();
  const em = (email || '').toString().toLowerCase();

  const idMatches = idStr && [row.id, row.user_id, row.uid, row.id_user, row.idUser, row.userid]
    .some(v => String(v || '') === idStr);

  const userMatches = u && [row.username, row.name, row.sipuser, row.user]
    .some(v => String(v || '').toLowerCase() === u);

  const emailMatches = em && [row.email, row.mail, row.user_email]
    .some(v => String(v || '').toLowerCase() === em);

  return Boolean(idMatches || userMatches || emailMatches);
}

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
    const username = '876544';
    const email = 'noc@truesip.net';

    // Read backup rows for this user
    const [rows] = await pool.query(
      'SELECT id, cdr_id, user_id, magnus_user_id, direction, src_number, dst_number, did_number, time_start, duration, billsec, price, raw_cdr FROM user_mb_cdrs_backup WHERE user_id = ?',
      [userId]
    );

    let considered = 0;
    let owned = 0;
    let inserted = 0;
    let skippedNoRaw = 0;
    let skippedNotOwned = 0;
    let parseErrors = 0;

    const insertSql = 'INSERT IGNORE INTO user_mb_cdrs (cdr_id, user_id, magnus_user_id, direction, src_number, dst_number, did_number, time_start, duration, billsec, price, raw_cdr) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

    for (const row of rows) {
      considered++;
      if (!row.raw_cdr) {
        skippedNoRaw++;
        continue;
      }
      let raw;
      try {
        raw = JSON.parse(row.raw_cdr);
      } catch (e) {
        parseErrors++;
        continue;
      }
      if (!belongsToUserRaw(raw, magnusUserId, username, email)) {
        skippedNotOwned++;
        continue;
      }
      owned++;

      await pool.execute(insertSql, [
        row.cdr_id,
        row.user_id,
        row.magnus_user_id,
        row.direction,
        row.src_number,
        row.dst_number,
        row.did_number,
        row.time_start,
        row.duration,
        row.billsec,
        row.price,
        row.raw_cdr
      ]);
      inserted++;
    }

    const [afterMainRows] = await pool.query('SELECT COUNT(*) AS n FROM user_mb_cdrs WHERE user_id = ?', [userId]);
    const afterMain = afterMainRows[0].n;

    console.log(JSON.stringify({
      userId,
      magnusUserId,
      considered,
      owned,
      inserted,
      skippedNoRaw,
      skippedNotOwned,
      parseErrors,
      afterMain
    }, null, 2));

    await pool.end();
  } catch (err) {
    console.error('restore-error', err.message || err);
    process.exit(1);
  }
})();
