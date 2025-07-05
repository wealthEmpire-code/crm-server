// db.js
const mysql = require('mysql2/promise');

const db = mysql.createPool({
  host: 'gateway01.ap-southeast-1.prod.aws.tidbcloud.com',
  user: '3gNuM32pH7qHzgx.root',
  password: 'LD41aBSxxO5zQUPR',
  database: 'wealth_empires',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
   ssl: {
    rejectUnauthorized: true // or false, depending on provider
  }
});

module.exports = db;
