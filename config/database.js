const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, '../database.sqlite'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    refresh_token_hash TEXT,
    refresh_token_expiry INTEGER
  )
`);

module.exports = db;