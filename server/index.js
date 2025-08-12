import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

// Import routes
import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';
import serviceRoutes from './routes/services.js';
import consultationRoutes from './routes/consultations.js';
import dependentRoutes from './routes/dependents.js';
import professionalRoutes from './routes/professionals.js';
import appointmentRoutes from './routes/appointments.js';
import privatePatientRoutes from './routes/privatePatients.js';
import medicalRecordRoutes from './routes/medicalRecords.js';
import medicalDocumentRoutes from './routes/medicalDocuments.js';
import attendanceLocationRoutes from './routes/attendanceLocations.js';
import adminRoutes from './routes/admin.js';
import paymentRoutes from './routes/payments.js';
import uploadRoutes from './routes/upload.js';
import reportRoutes from './routes/reports.js';

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
    'https://cartaoquiroferreira.com.br',
    'https://www.cartaoquiroferreira.com.br'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/services', serviceRoutes);
app.use('/api/service-categories', serviceRoutes);
app.use('/api/consultations', consultationRoutes);
app.use('/api/dependents', dependentRoutes);
app.use('/api/professionals', professionalRoutes);
app.use('/api/clients', professionalRoutes);
app.use('/api/appointments', appointmentRoutes);
app.use('/api/private-patients', privatePatientRoutes);
app.use('/api/medical-records', medicalRecordRoutes);
app.use('/api/medical-documents', medicalDocumentRoutes);
app.use('/api/attendance-locations', attendanceLocationRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api', paymentRoutes);
app.use('/api', uploadRoutes);
app.use('/api/reports', reportRoutes);

// Serve static files from the dist directory
app.use(express.static(path.join(__dirname, '../dist')));

// Handle React Router routes - serve index.html for all non-API routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Global error handler:', err);
  res.status(500).json({ 
    message: 'Erro interno do servidor',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Erro interno'
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});