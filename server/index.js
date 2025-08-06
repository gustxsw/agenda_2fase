import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

// Load environment variables
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

// CORS configuration
const corsOptions = {
  origin: [
    'http://localhost:5173',
    'http://localhost:3000',
    'https://www.cartaoquiroferreira.com.br',
    'https://cartaoquiroferreira.com.br'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Serve static files from dist directory
app.use(express.static(path.join(__dirname, '../dist')));

// Import routes
import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';
import serviceRoutes from './routes/services.js';
import consultationRoutes from './routes/consultations.js';
import dependentRoutes from './routes/dependents.js';
import reportRoutes from './routes/reports.js';
import professionalRoutes from './routes/professionals.js';
import uploadRoutes from './routes/upload.js';
import paymentRoutes from './routes/payment.js';
import schedulingRoutes from './routes/scheduling.js';
import schedulingPaymentRoutes from './routes/schedulingPayment.js';
import privatePatientRoutes from './routes/privatePatients.js';
import medicalRecordsRoutes from './routes/medicalRecords.js';
import attendanceLocationRoutes from './routes/attendanceLocations.js';
import adminSchedulingAccessRoutes from './routes/adminSchedulingAccess.js';

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/services', serviceRoutes);
app.use('/api/service-categories', serviceRoutes);
app.use('/api/consultations', consultationRoutes);
app.use('/api/dependents', dependentRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/professionals', professionalRoutes);
app.use('/api/clients', consultationRoutes);
app.use('/api/upload-image', uploadRoutes);
app.use('/api/payment', paymentRoutes);
app.use('/api/create-subscription', paymentRoutes);
app.use('/api/professional/create-payment', paymentRoutes);
app.use('/api/scheduling', schedulingRoutes);
app.use('/api/scheduling-payment', schedulingPaymentRoutes);
app.use('/api/create-scheduling-subscription', schedulingPaymentRoutes);
app.use('/api/private-patients', privatePatientRoutes);
app.use('/api/medical-records', medicalRecordsRoutes);
app.use('/api/attendance-locations', attendanceLocationRoutes);
app.use('/api/admin', adminSchedulingAccessRoutes);
app.use('/api/admin/professionals-scheduling-access', adminSchedulingAccessRoutes);
app.use('/api/admin/grant-scheduling-access', adminSchedulingAccessRoutes);
app.use('/api/admin/revoke-scheduling-access', adminSchedulingAccessRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Serve React app for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ 
    message: 'Erro interno do servidor',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Database: ${process.env.DATABASE_URL ? 'Connected' : 'Not configured'}`);
});