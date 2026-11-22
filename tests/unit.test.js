// проверяет, что функция генерации токена работает (выдает валидный JWT)
const jwt = require('jsonwebtoken');
require('dotenv').config();

describe('Unit Tests: JWT', () => {
    it('Должен создавать валидный Access-токен', () => {
        const payload = { id: 1, name: 'test', type: 'access' };
        const token = jwt.sign(payload, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });
        
        const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
        expect(decoded.id).toBe(1);
        expect(decoded.type).toBe('access');
    });
});