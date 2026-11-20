const db = require('../config/database');
const bcrypt = require('bcryptjs');

class User {
    static findByName(name) {
        return db.prepare('SELECT * FROM users WHERE name = ?').get(name);
    }

    static create(name, email, password) {
        const hash = bcrypt.hashSync(password, 10);
        const info = db.prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)')
                        .run(name, email, hash);
        return { id: info.lastInsertRowid, name, email };
    }

    static verifyPassword(password, hash) {
        return bcrypt.compareSync(password, hash);
    }

    static saveRefreshToken(userId, tokenHash, expiry) {
        db.prepare('UPDATE users SET refresh_token_hash = ?, refresh_token_expiry = ? WHERE id = ?')
          .run(tokenHash, expiry, userId);
    }

    static findByRefreshTokenHash(tokenHash) {
        return db.prepare('SELECT * FROM users WHERE refresh_token_hash = ?').get(tokenHash);
    }

    static clearRefreshToken(userId) {
        db.prepare('UPDATE users SET refresh_token_hash = NULL, refresh_token_expiry = NULL WHERE id = ?')
          .run(userId);
    }
}

module.exports = User;