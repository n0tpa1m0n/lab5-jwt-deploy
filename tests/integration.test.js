const request = require('supertest');
const express = require('express');
const authRoutes = require('../routes/authRoutes');

const app = express();
app.use(express.json());
app.use('/api/auth', authRoutes);

describe('Integration Tests: API', () => {
    it('Должен регистрировать нового пользователя', async () => {
        const res = await request(app)
            .post('/api/auth/register')
            .send({ name: 'testuser', email: 'test@test.com', password: '123' });
        
        expect(res.statusCode).toEqual(201);
        expect(res.body).toHaveProperty('userId');
    });

    it('Должен возвращать 401 при неверном пароле', async () => {
        const res = await request(app)
            .post('/api/auth/login')
            .send({ name: 'testuser', password: 'wrongpassword' });
        
        expect(res.statusCode).toEqual(401);
    });
});