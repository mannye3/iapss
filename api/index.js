import 'dotenv/config'; // Load environment variables from .env file
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

import userRoutes from './routes/users.js';
import authRoutes from './routes/auth.js';
import institutionRoutes from './routes/institutions.js';
import publicationRoutes from './routes/publications.js';
import adminRoutes from './routes/admin.js';
import { verifyToken } from './middlewares/authMiddleware.js';

const app = express();

// Middlewares
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Credentials', true);
    next();
});
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));
app.use(cookieParser());

// Public routes
app.use('/api/auth', authRoutes);

// Protected routes (apply verifyToken middleware)
app.use('/api/users', verifyToken, userRoutes);
app.use('/api/institutions', verifyToken, institutionRoutes);
app.use('/api/publications', verifyToken, publicationRoutes);
app.use('/api/admin', verifyToken, adminRoutes); // Use the admin routes

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something went wrong!');
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
