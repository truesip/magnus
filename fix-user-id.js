require('dotenv').config();
const mysql = require('mysql2/promise');
const fs = require('fs');

async function fixUserId() {
  const dsn = process.env.DATABASE_URL;
  if (!dsn) {
    console.error('DATABASE_URL not set');
    process.exit(1);
  }
  
  const u = new URL(dsn);
  const dbName = u.pathname.replace(/^\//, '');
  
  // TLS options
  const sslMode = (u.searchParams.get('ssl-mode') || u.searchParams.get('sslmode') || '').toUpperCase();
  const caPath = process.env.DATABASE_CA_CERT;
  let sslOptions;
  if (caPath && fs.existsSync(caPath)) {
    sslOptions = { ca: fs.readFileSync(caPath, 'utf8'), rejectUnauthorized: true };
  } else if (sslMode === 'REQUIRED') {
    sslOptions = { rejectUnauthorized: false };
  }

  const pool = mysql.createPool({
    host: u.hostname,
    port: Number(u.port) || 3306,
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database: dbName,
    ssl: sslOptions,
    connectionLimit: 1
  });
  
  console.log('Checking current user data...');
  const [rows] = await pool.execute('SELECT id, username, email, magnus_user_id FROM signup_users WHERE username = ?', ['876544']);
  
  if (rows.length === 0) {
    console.error('User 876544 not found');
    process.exit(1);
  }
  
  console.log('Current data:', rows[0]);
  
  console.log('\nUpdating magnus_user_id from 1 to 75...');
  await pool.execute('UPDATE signup_users SET magnus_user_id = ? WHERE username = ?', ['75', '876544']);
  
  const [updated] = await pool.execute('SELECT id, username, email, magnus_user_id FROM signup_users WHERE username = ?', ['876544']);
  console.log('Updated data:', updated[0]);
  
  console.log('\nDone! Please restart the server and log in again.');
  
  await pool.end();
}

fixUserId().catch(err => {
  console.error('Error:', err);
  process.exit(1);
});
