require('dotenv').config();
const mysql = require('mysql2/promise');
const fs = require('fs');

async function checkProfile() {
  const dsn = process.env.DATABASE_URL;
  if (!dsn) {
    console.error('DATABASE_URL not set');
    process.exit(1);
  }
  
  const u = new URL(dsn);
  const dbName = u.pathname.replace(/^\//, '');
  
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
  
  console.log('Checking user 876544 profile data...');
  const [rows] = await pool.execute('SELECT * FROM signup_users WHERE username = ?', ['876544']);
  
  if (rows.length === 0) {
    console.error('User 876544 not found');
    process.exit(1);
  }
  
  console.log('\nCurrent data:', rows[0]);
  
  if (!rows[0].firstname || !rows[0].lastname) {
    console.log('\nFirstname and/or lastname are missing. Updating to "trexx rewer"...');
    await pool.execute(
      'UPDATE signup_users SET firstname = ?, lastname = ? WHERE username = ?',
      ['trexx', 'rewer', '876544']
    );
    console.log('Updated!');
    
    const [updated] = await pool.execute('SELECT firstname, lastname FROM signup_users WHERE username = ?', ['876544']);
    console.log('New data:', updated[0]);
  }
  
  await pool.end();
}

checkProfile().catch(err => {
  console.error('Error:', err);
  process.exit(1);
});
