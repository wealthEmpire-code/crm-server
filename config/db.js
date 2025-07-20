// db.js
const mysql = require('mysql2/promise');

const db = mysql.createPool({
  host: 'srv1090.hstgr.io',    
  user: 'u799981322_wealthEmpire',
  password: 'wealthEmpire@1',
  database: 'u799981322_WealthEmpires',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: { rejectUnauthorized: true } 
});

module.exports = db;
