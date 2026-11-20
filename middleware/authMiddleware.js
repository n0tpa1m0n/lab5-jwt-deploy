const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Токен не предоставлен' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET, { algorithms: ['HS256'] });
        
        if (decoded.type !== 'access') {
            return res.status(401).json({ error: 'Неверный тип токена' });
        }

        req.user = decoded;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'TOKEN_EXPIRED' });
        }
        return res.status(401).json({ error: 'Недействительный токен' });
    }
};