const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const User = require('../models/user');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

async function sendNotification(userEmail, userName, action) {
    try {
        await transporter.sendMail({
            from: `"Lab4 Security" <${process.env.EMAIL_USER}>`,
            to: userEmail,
            subject: 'Безопасность аккаунта',
            text: `Привет, ${userName}!\n\nУведомление: ${action}\n\nЕсли это были не вы, срочно смените пароль.`,
            html: `<h2>Привет, ${userName}!</h2><p>Уведомление: <b>${action}</b></p><p>Если это были не вы, срочно смените пароль.</p>`
        });
        console.log(`[EMAIL SENT] Уведомление успешно отправлено на ${userEmail}`);
    } catch (error) {
        console.error(`[EMAIL ERROR] Ошибка отправки на ${userEmail}:`, error.message);
    }
}

// Генерация пары токенов
function generateTokens(user) {
    const accessToken = jwt.sign(
        { id: user.id, name: user.name, email: user.email, roles: ['user'], type: 'access' },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: '15m', algorithm: 'HS256' }
    );

    const refreshToken = crypto.randomBytes(40).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const expiry = Date.now() + 7 * 24 * 60 * 60 * 1000;

    User.saveRefreshToken(user.id, tokenHash, expiry);

    return { accessToken, refreshToken };
}

exports.register = (req, res) => {
    const { name, email, password } = req.body; 
    
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Введите имя, email и пароль' });
    }
    if (User.findByName(name)) {
        return res.status(400).json({ error: 'Пользователь уже существует' });
    }

    const user = User.create(name, email, password);
    res.status(201).json({ message: 'Успешно зарегистрирован', userId: user.id });
};

exports.login = (req, res) => {
    const { name, password } = req.body;
    const user = User.findByName(name);
    
    if (!user || !User.verifyPassword(password, user.password_hash)) {
        return res.status(401).json({ error: 'Неверное имя или пароль' });
    }

    const tokens = generateTokens(user);
    
    sendNotification(user.email, user.name, 'Выполнен вход в систему.');
    
    res.json(tokens);
};

exports.refresh = (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ error: 'Нет токена' });

    const incomingHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const user = User.findByRefreshTokenHash(incomingHash);

    if (!user || Date.now() > user.refresh_token_expiry) {
        return res.status(401).json({ error: 'Недействительный или истекший refresh-токен' });
    }

    const tokens = generateTokens(user);
    
    sendNotification(user.email, user.name, 'Токены успешно обновлены.');
    
    res.json(tokens);
};

exports.logout = (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'Нет токена' });

    const incomingHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const user = User.findByRefreshTokenHash(incomingHash);

    if (user) {
        User.clearRefreshToken(user.id);
        sendNotification(user.email, user.name, 'Выполнен выход из системы.');
    }
    
    res.json({ message: 'Выход выполнен. Токен удален.' });
};