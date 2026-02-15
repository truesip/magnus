// Migration to fix dialer_call_logs foreign key constraint for audio-only campaigns
require('dotenv').config();
const mysql = require('mysql2/promise');
const fs = require('fs');

async function runMigration() {
  const dsn = process.env.DATABASE_URL;
  if (!dsn) {
    console.error('ERROR: DATABASE_URL environment variable not set');
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
    connectionLimit: 1,
    waitForConnections: true
  });

  try {
    console.log('Starting migration: Fix dialer_call_logs foreign key for audio-only campaigns...');

    // Step 1: Drop existing foreign key
    console.log('Step 1: Dropping existing foreign key fk_dialer_logs_agent...');
    try {
      await pool.execute('ALTER TABLE dialer_call_logs DROP FOREIGN KEY fk_dialer_logs_agent');
      console.log('✓ Foreign key dropped');
    } catch (e) {
      if (e.code === 'ER_CANT_DROP_FIELD_OR_KEY') {
        console.log('⚠ Foreign key does not exist or already dropped, continuing...');
      } else {
        throw e;
      }
    }

    // Step 2: Ensure column is nullable and type matches ai_agents.id (BIGINT)
    console.log('Step 2: Changing ai_agent_id to BIGINT NULL to match ai_agents.id...');
    await pool.execute('ALTER TABLE dialer_call_logs MODIFY COLUMN ai_agent_id BIGINT NULL');
    console.log('✓ Column modified to BIGINT NULL');

    // Step 3: Recreate foreign key with ON DELETE SET NULL
    console.log('Step 3: Recreating foreign key with ON DELETE SET NULL...');
    await pool.execute(`
      ALTER TABLE dialer_call_logs
      ADD CONSTRAINT fk_dialer_logs_agent
      FOREIGN KEY (ai_agent_id) 
      REFERENCES ai_agents(id) 
      ON DELETE SET NULL
    `);
    console.log('✓ Foreign key recreated');

    console.log('\n✅ Migration completed successfully!');
    console.log('Audio-only campaigns can now be created without foreign key constraint errors.');

  } catch (error) {
    console.error('\n❌ Migration failed:');
    console.error(error.message);
    console.error('\nFull error:', error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

runMigration().catch(err => {
  console.error('Unexpected error:', err);
  process.exit(1);
});
