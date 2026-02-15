require('dotenv').config();
const mysql = require('mysql2/promise');
const fs = require('fs');

async function updateAgentImage() {
  const dsn = process.env.DATABASE_URL;
  if (!dsn) {
    console.error('ERROR: DATABASE_URL not set');
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

  try {
    const newTag = 'audio-fix-2026-02-14-214151';
    const newImage = `truesip/agenttalkusa:${newTag}`;
    
    console.log(`Updating ai_agents docker_image to: ${newImage}`);
    
    const [result] = await pool.execute(
      `UPDATE ai_agents 
       SET docker_image = ?
       WHERE docker_image LIKE 'truesip/agenttalkusa:%'`,
      [newImage]
    );
    
    console.log(`✅ Updated ${result.affectedRows} agent(s)`);
    
    // Show updated agents
    const [agents] = await pool.execute(
      `SELECT id, display_name, pipecat_agent_name, docker_image 
       FROM ai_agents 
       WHERE docker_image LIKE 'truesip/agenttalkusa:%'
       LIMIT 10`
    );
    
    console.log('\nUpdated agents:');
    console.table(agents);
    
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

updateAgentImage();
