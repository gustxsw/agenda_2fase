import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from './db.js';

// Load environment variables
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

// =============================================================================
// DATABASE SCHEMA INITIALIZATION
// =============================================================================

const initializeDatabase = async () => {
  try {
    console.log('🔄 Initializing database schema...');

    // Create all tables in correct order
    await pool.query(`
      -- Service Categories
      CREATE TABLE IF NOT EXISTS service_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL UNIQUE,
        description TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      -- Users (Clients, Professionals, Admins)
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) NOT NULL UNIQUE,
        email VARCHAR(255),
        phone VARCHAR(20),
        birth_date DATE,
        address TEXT,
        address_number VARCHAR(20),
        address_complement VARCHAR(100),
        neighborhood VARCHAR(100),
        city VARCHAR(100),
        state VARCHAR(2),
        zip_code VARCHAR(8),
        password_hash VARCHAR(255) NOT NULL,
        roles JSONB NOT NULL DEFAULT '[]',
        percentage DECIMAL(5,2) DEFAULT 50.00,
        category_id INTEGER REFERENCES service_categories(id),
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry TIMESTAMP WITH TIME ZONE,
        photo_url TEXT,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      -- Services
      CREATE TABLE IF NOT EXISTS services (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        base_price DECIMAL(10,2) NOT NULL,
        category_id INTEGER REFERENCES service_categories(id),
        is_base_service BOOLEAN DEFAULT false,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      -- Dependents
      CREATE TABLE IF NOT EXISTS dependents (
        id SERIAL PRIMARY KEY,
        client_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) NOT NULL UNIQUE,
        birth_date DATE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      -- Private Patients (for professionals)
      CREATE TABLE IF NOT EXISTS private_patients (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) NOT NULL,
        email VARCHAR(255),
        phone VARCHAR(20),
        birth_date DATE,
        address TEXT,
        address_number VARCHAR(20),
        address_complement VARCHAR(100),
        neighborhood VARCHAR(100),
        city VARCHAR(100),
        state VARCHAR(2),
        zip_code VARCHAR(8),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(professional_id, cpf)
      );

      -- Attendance Locations
      CREATE TABLE IF NOT EXISTS attendance_locations (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        address TEXT,
        address_number VARCHAR(20),
        address_complement VARCHAR(100),
        neighborhood VARCHAR(100),
        city VARCHAR(100),
        state VARCHAR(2),
        zip_code VARCHAR(8),
        phone VARCHAR(20),
        is_default BOOLEAN DEFAULT false,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      -- Professional Schedule Settings
      CREATE TABLE IF NOT EXISTS professional_schedule_settings (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        work_days INTEGER[] DEFAULT '{1,2,3,4,5}',
        work_start_time TIME DEFAULT '08:00',
        work_end_time TIME DEFAULT '18:00',
        break_start_time TIME DEFAULT '12:00',
        break_end_time TIME DEFAULT '13:00',
        consultation_duration INTEGER DEFAULT 60,
        has_scheduling_subscription BOOLEAN DEFAULT true,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      -- Professional Scheduling Subscriptions
      CREATE TABLE IF NOT EXISTS professional_scheduling_subscriptions (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        status VARCHAR(20) DEFAULT 'active',
        expires_at TIMESTAMP WITH TIME ZONE,
        granted_by VARCHAR(255),
        granted_at TIMESTAMP WITH TIME ZONE,
        revoked_by VARCHAR(255),
        revoked_at TIMESTAMP WITH TIME ZONE,
        reason TEXT,
        is_admin_granted BOOLEAN DEFAULT false,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      -- Appointments
      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id),
        private_patient_id INTEGER REFERENCES private_patients(id),
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        service_id INTEGER REFERENCES services(id),
        appointment_date DATE NOT NULL,
        appointment_time TIME NOT NULL,
        location_id INTEGER REFERENCES attendance_locations(id),
        notes TEXT,
        value DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'scheduled',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CHECK (
          (private_patient_id IS NOT NULL AND client_id IS NULL AND dependent_id IS NULL) OR
          (private_patient_id IS NULL AND client_id IS NOT NULL AND dependent_id IS NULL) OR
          (private_patient_id IS NULL AND client_id IS NULL AND dependent_id IS NOT NULL)
        )
      );

      -- Consultations
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id),
        private_patient_id INTEGER REFERENCES private_patients(id),
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        service_id INTEGER REFERENCES services(id),
        location_id INTEGER REFERENCES attendance_locations(id),
        appointment_id INTEGER REFERENCES appointments(id),
        date TIMESTAMP WITH TIME ZONE NOT NULL,
        value DECIMAL(10,2) NOT NULL,
        notes TEXT,
        status VARCHAR(20) DEFAULT 'completed',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CHECK (
          (private_patient_id IS NOT NULL AND client_id IS NULL AND dependent_id IS NULL) OR
          (private_patient_id IS NULL AND client_id IS NOT NULL AND dependent_id IS NULL) OR
          (private_patient_id IS NULL AND client_id IS NULL AND dependent_id IS NOT NULL)
        )
      );

      -- Medical Records
      CREATE TABLE IF NOT EXISTS medical_records (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id),
        private_patient_id INTEGER REFERENCES private_patients(id),
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        appointment_id INTEGER REFERENCES appointments(id),
        chief_complaint TEXT,
        history_present_illness TEXT,
        past_medical_history TEXT,
        medications TEXT,
        allergies TEXT,
        physical_examination TEXT,
        diagnosis TEXT,
        treatment_plan TEXT,
        notes TEXT,
        vital_signs JSONB,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CHECK (
          (private_patient_id IS NOT NULL AND client_id IS NULL AND dependent_id IS NULL) OR
          (private_patient_id IS NULL AND client_id IS NOT NULL AND dependent_id IS NULL) OR
          (private_patient_id IS NULL AND client_id IS NULL AND dependent_id IS NOT NULL)
        )
      );

      -- Medical Documents
      CREATE TABLE IF NOT EXISTS medical_documents (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id),
        private_patient_id INTEGER REFERENCES private_patients(id),
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        document_type VARCHAR(50) NOT NULL,
        title VARCHAR(255) NOT NULL,
        document_url TEXT NOT NULL,
        template_data JSONB,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CHECK (
          (private_patient_id IS NOT NULL AND client_id IS NULL AND dependent_id IS NULL) OR
          (private_patient_id IS NULL AND client_id IS NOT NULL AND dependent_id IS NULL) OR
          (private_patient_id IS NULL AND client_id IS NULL AND dependent_id IS NOT NULL)
        )
      );

      -- Client Subscriptions
      CREATE TABLE IF NOT EXISTS client_subscriptions (
        id SERIAL PRIMARY KEY,
        client_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        status VARCHAR(20) DEFAULT 'pending',
        expires_at TIMESTAMP WITH TIME ZONE,
        payment_id INTEGER,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      -- Client Payments
      CREATE TABLE IF NOT EXISTS client_payments (
        id SERIAL PRIMARY KEY,
        client_id INTEGER NOT NULL REFERENCES users(id),
        mp_preference_id VARCHAR(255),
        mp_payment_id VARCHAR(255),
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        external_reference VARCHAR(255),
        dependent_count INTEGER DEFAULT 0,
        payment_date TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      -- Professional Payments
      CREATE TABLE IF NOT EXISTS professional_payments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id),
        mp_preference_id VARCHAR(255),
        mp_payment_id VARCHAR(255),
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        external_reference VARCHAR(255),
        payment_date TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      -- Professional Scheduling Payments
      CREATE TABLE IF NOT EXISTS professional_scheduling_payments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id),
        mp_preference_id VARCHAR(255),
        mp_payment_id VARCHAR(255),
        amount DECIMAL(10,2) NOT NULL DEFAULT 49.90,
        status VARCHAR(20) DEFAULT 'pending',
        external_reference VARCHAR(255),
        payment_date TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      -- System Logs
      CREATE TABLE IF NOT EXISTS system_logs (
        id SERIAL PRIMARY KEY,
        level VARCHAR(20) NOT NULL,
        message TEXT NOT NULL,
        meta JSONB,
        user_id INTEGER REFERENCES users(id),
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      -- Audit Trail
      CREATE TABLE IF NOT EXISTS audit_trail (
        id SERIAL PRIMARY KEY,
        table_name VARCHAR(100) NOT NULL,
        record_id INTEGER NOT NULL,
        action VARCHAR(20) NOT NULL,
        old_values JSONB,
        new_values JSONB,
        user_id INTEGER REFERENCES users(id),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create indexes for better performance
    await pool.query(`
      -- Performance indexes
      CREATE INDEX IF NOT EXISTS idx_users_cpf ON users(cpf);
      CREATE INDEX IF NOT EXISTS idx_users_roles ON users USING GIN(roles);
      CREATE INDEX IF NOT EXISTS idx_users_subscription_status ON users(subscription_status);
      CREATE INDEX IF NOT EXISTS idx_dependents_client_id ON dependents(client_id);
      CREATE INDEX IF NOT EXISTS idx_dependents_cpf ON dependents(cpf);
      CREATE INDEX IF NOT EXISTS idx_consultations_professional_id ON consultations(professional_id);
      CREATE INDEX IF NOT EXISTS idx_consultations_date ON consultations(date);
      CREATE INDEX IF NOT EXISTS idx_consultations_client_id ON consultations(client_id);
      CREATE INDEX IF NOT EXISTS idx_consultations_dependent_id ON consultations(dependent_id);
      CREATE INDEX IF NOT EXISTS idx_appointments_professional_id ON appointments(professional_id);
      CREATE INDEX IF NOT EXISTS idx_appointments_date ON appointments(appointment_date);
      CREATE INDEX IF NOT EXISTS idx_medical_records_professional_id ON medical_records(professional_id);
      CREATE INDEX IF NOT EXISTS idx_private_patients_professional_id ON private_patients(professional_id);
      CREATE INDEX IF NOT EXISTS idx_private_patients_cpf ON private_patients(cpf);
      CREATE INDEX IF NOT EXISTS idx_system_logs_created_at ON system_logs(created_at);
      CREATE INDEX IF NOT EXISTS idx_audit_trail_table_record ON audit_trail(table_name, record_id);
    `);

    // Insert default data
    await pool.query(`
      -- Insert default service categories
      INSERT INTO service_categories (name, description) VALUES
        ('Fisioterapia', 'Serviços de fisioterapia e reabilitação'),
        ('Psicologia', 'Atendimento psicológico e terapias'),
        ('Nutrição', 'Consultas nutricionais e acompanhamento'),
        ('Odontologia', 'Serviços odontológicos'),
        ('Medicina', 'Consultas médicas gerais'),
        ('Estética', 'Procedimentos estéticos e bem-estar'),
        ('Educação Física', 'Personal training e atividades físicas'),
        ('Terapias Alternativas', 'Acupuntura, massoterapia e outras terapias')
      ON CONFLICT (name) DO NOTHING;

      -- Insert default services
      INSERT INTO services (name, description, base_price, category_id, is_base_service) VALUES
        ('Consulta Fisioterapêutica', 'Avaliação e tratamento fisioterapêutico', 80.00, 1, true),
        ('Sessão de Fisioterapia', 'Sessão individual de fisioterapia', 60.00, 1, false),
        ('Consulta Psicológica', 'Sessão de psicoterapia individual', 120.00, 2, true),
        ('Consulta Nutricional', 'Avaliação nutricional completa', 100.00, 3, true),
        ('Limpeza Dental', 'Profilaxia e limpeza dentária', 80.00, 4, true),
        ('Consulta Médica', 'Consulta médica geral', 150.00, 5, true),
        ('Procedimento Estético', 'Diversos procedimentos estéticos', 200.00, 6, false),
        ('Personal Training', 'Sessão individual de treinamento', 80.00, 7, true),
        ('Sessão de Acupuntura', 'Tratamento com acupuntura', 90.00, 8, true)
      ON CONFLICT DO NOTHING;
    `);

    console.log('✅ Database schema initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
    throw error;
  }
};

// =============================================================================
// CLOUDINARY CONFIGURATION
// =============================================================================

const configureCloudinary = () => {
  try {
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    const apiKey = process.env.CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;
    
    console.log('🔍 Cloudinary credentials check:');
    console.log('Cloud Name:', cloudName ? '✅ Found' : '❌ Missing');
    console.log('API Key:', apiKey ? '✅ Found' : '❌ Missing');
    console.log('API Secret:', apiSecret ? '✅ Found' : '❌ Missing');
    
    if (!cloudName || !apiKey || !apiSecret) {
      console.warn('⚠️ Cloudinary credentials missing - image upload will be disabled');
      return false;
    }
    
    cloudinary.config({
      cloud_name: cloudName,
      api_key: apiKey,
      api_secret: apiSecret,
      secure: true
    });

    console.log('✅ Cloudinary configured successfully');
    return true;
  } catch (error) {
    console.error('❌ Error configuring Cloudinary:', error);
    return false;
  }
};

const isCloudinaryConfigured = configureCloudinary();

// Configure Cloudinary storage for multer
let storage;
if (isCloudinaryConfigured) {
  storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
      folder: 'quiro-ferreira/professionals',
      allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
      transformation: [
        {
          width: 400,
          height: 400,
          crop: 'fill',
          gravity: 'face',
          quality: 'auto:good'
        }
      ]
    },
  });
} else {
  storage = multer.memoryStorage();
}

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    console.log('🔄 File filter - File type:', file.mimetype);
    
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Apenas arquivos de imagem são permitidos'), false);
    }
  },
});

// =============================================================================
// MIDDLEWARE CONFIGURATION
// =============================================================================

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:3000',
      'http://localhost:4173',
      'https://cartaoquiroferreira.com.br',
      'https://www.cartaoquiroferreira.com.br',
      'https://convenioquiroferreira.onrender.com'
    ];
    
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.warn('🚫 CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
  exposedHeaders: ['Set-Cookie']
};

app.use(cors(corsOptions));

// Body parsing middleware
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    try {
      JSON.parse(buf);
    } catch (e) {
      console.error('❌ Invalid JSON received:', buf.toString().substring(0, 100));
      throw new Error('Invalid JSON');
    }
  }
}));

app.use(express.urlencoded({ 
  extended: true, 
  limit: '10mb' 
}));

app.use(cookieParser());

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`📡 ${timestamp} - ${req.method} ${req.path}`);
  
  if ((req.method === 'POST' || req.method === 'PUT') && req.body) {
    const logBody = { ...req.body };
    if (logBody.password) logBody.password = '[REDACTED]';
    if (logBody.currentPassword) logBody.currentPassword = '[REDACTED]';
    if (logBody.newPassword) logBody.newPassword = '[REDACTED]';
    console.log('📝 Request body:', JSON.stringify(logBody, null, 2));
  }
  
  next();
});

// Security headers middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  
  next();
});

// =============================================================================
// AUTHENTICATION MIDDLEWARE
// =============================================================================

const authenticate = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'Token de acesso não fornecido' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');

    const result = await pool.query(
      'SELECT id, name, cpf, email, roles FROM users WHERE id = $1',
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];
    let userRoles = [];
    
    try {
      userRoles = typeof user.roles === 'string' ? JSON.parse(user.roles) : user.roles || [];
    } catch (e) {
      userRoles = Array.isArray(user.roles) ? user.roles : [user.roles].filter(Boolean);
    }

    req.user = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      email: user.email,
      roles: userRoles,
      currentRole: decoded.currentRole || userRoles[0]
    };

    next();
  } catch (error) {
    console.error('❌ Authentication error:', error);
    return res.status(401).json({ message: 'Token inválido ou expirado' });
  }
};

const authorize = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.currentRole) {
      return res.status(403).json({ message: 'Acesso não autorizado - role não definida' });
    }

    if (!allowedRoles.includes(req.user.currentRole)) {
      return res.status(403).json({ 
        message: `Acesso não autorizado. Requer: ${allowedRoles.join(' ou ')}. Atual: ${req.user.currentRole}` 
      });
    }

    next();
  };
};

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

const parseRoles = (roles) => {
  if (!roles) return [];
  if (Array.isArray(roles)) return roles;
  if (typeof roles === 'string') {
    try {
      return JSON.parse(roles);
    } catch (e) {
      return roles.includes(',') ? roles.split(',').map(r => r.trim()) : [roles];
    }
  }
  return [roles];
};

const stringifyRoles = (roles) => {
  if (!roles) return JSON.stringify([]);
  if (Array.isArray(roles)) return JSON.stringify(roles);
  if (typeof roles === 'string') {
    try {
      JSON.parse(roles);
      return roles;
    } catch (e) {
      const rolesArray = roles.includes(',') ? roles.split(',').map(r => r.trim()) : [roles];
      return JSON.stringify(rolesArray);
    }
  }
  return JSON.stringify([roles]);
};

// =============================================================================
// STATIC FILES AND FRONTEND
// =============================================================================

app.use(express.static(path.join(__dirname, '../dist'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1y' : '0',
  etag: true,
  lastModified: true
}));

app.use('/public', express.static(path.join(__dirname, '../public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1y' : '0'
}));

// =============================================================================
// AUTHENTICATION ROUTES
// =============================================================================

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return res.status(400).json({ message: 'CPF e senha são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    const result = await pool.query(
      'SELECT id, name, cpf, email, password_hash, roles FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'CPF ou senha inválidos' });
    }

    const user = result.rows[0];

    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'CPF ou senha inválidos' });
    }

    const userRoles = parseRoles(user.roles);

    console.log('🔍 User found:', { id: user.id, name: user.name, roles: userRoles });

    const userData = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      email: user.email,
      roles: userRoles
    };

    res.json({ user: userData });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Role selection endpoint
app.post('/api/auth/select-role', async (req, res) => {
  try {
    const { userId, role } = req.body;

    if (!userId || !role) {
      return res.status(400).json({ message: 'ID do usuário e role são obrigatórios' });
    }

    const result = await pool.query(
      'SELECT id, name, cpf, email, roles FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];
    const userRoles = parseRoles(user.roles);

    if (!userRoles.includes(role)) {
      return res.status(403).json({ message: 'Usuário não possui esta role' });
    }

    const token = jwt.sign(
      { 
        id: user.id, 
        currentRole: role,
        roles: userRoles
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    });

    const userData = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      email: user.email,
      roles: userRoles,
      currentRole: role
    };

    res.json({ token, user: userData });
  } catch (error) {
    console.error('Role selection error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Switch role endpoint
app.post('/api/auth/switch-role', async (req, res) => {
  try {
    const { role } = req.body;
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'Token não fornecido' });
    }

    if (!role) {
      return res.status(400).json({ message: 'Role é obrigatória' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');

    const result = await pool.query(
      'SELECT id, name, cpf, email, roles FROM users WHERE id = $1',
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];
    const userRoles = parseRoles(user.roles);

    if (!userRoles.includes(role)) {
      return res.status(403).json({ message: 'Usuário não possui esta role' });
    }

    const newToken = jwt.sign(
      { 
        id: user.id, 
        currentRole: role,
        roles: userRoles
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.cookie('token', newToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    });

    const userData = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      email: user.email,
      roles: userRoles,
      currentRole: role
    };

    res.json({ token: newToken, user: userData });
  } catch (error) {
    console.error('Role switch error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      name,
      cpf,
      email,
      phone,
      birth_date,
      address,
      address_number,
      address_complement,
      neighborhood,
      city,
      state,
      password,
    } = req.body;

    if (!name || !cpf || !password) {
      return res.status(400).json({ message: 'Nome, CPF e senha são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const result = await pool.query(
      `INSERT INTO users 
       (name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password_hash, roles, 
        subscription_status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, CURRENT_TIMESTAMP)
       RETURNING id, name, cpf, email, roles`,
      [name, cleanCpf, email, phone, birth_date, address, address_number,
       address_complement, neighborhood, city, state, passwordHash, 
       stringifyRoles(['client']), 'pending']
    );

    const newUser = result.rows[0];
    const userRoles = parseRoles(newUser.roles);

    const userData = {
      id: newUser.id,
      name: newUser.name,
      cpf: newUser.cpf,
      email: newUser.email,
      roles: userRoles
    };

    res.status(201).json({ user: userData });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

// =============================================================================
// USER MANAGEMENT ROUTES
// =============================================================================

// Get all users
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.*, sc.name as category_name 
       FROM users u
       LEFT JOIN service_categories sc ON u.category_id = sc.id
       ORDER BY u.name`
    );

    const users = result.rows.map(user => ({
      ...user,
      roles: parseRoles(user.roles)
    }));

    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get specific user
app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `SELECT u.*, sc.name as category_name 
       FROM users u
       LEFT JOIN service_categories sc ON u.category_id = sc.id
       WHERE u.id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];
    user.roles = parseRoles(user.roles);

    res.json(user);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create new user
app.post('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const {
      name,
      cpf,
      email,
      phone,
      birth_date,
      address,
      address_number,
      address_complement,
      neighborhood,
      city,
      state,
      password,
      roles,
      percentage,
      category_id
    } = req.body;

    if (!name || !cpf || !password || !roles || roles.length === 0) {
      return res.status(400).json({ message: 'Nome, CPF, senha e pelo menos uma role são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const rolesArray = Array.isArray(roles) ? roles : [roles];
    const rolesJson = stringifyRoles(rolesArray);

    const subscriptionStatus = rolesArray.includes('client') ? 'pending' : null;

    const result = await pool.query(
      `INSERT INTO users 
       (name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password_hash, roles, 
        percentage, category_id, subscription_status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, CURRENT_TIMESTAMP)
       RETURNING id, name, cpf, email, roles`,
      [name, cleanCpf, email, phone, birth_date, address, address_number,
       address_complement, neighborhood, city, state, passwordHash, rolesJson,
       percentage, category_id, subscriptionStatus]
    );

    const newUser = result.rows[0];
    newUser.roles = parseRoles(newUser.roles);

    res.status(201).json({ user: newUser });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update user
app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      email,
      phone,
      birth_date,
      address,
      address_number,
      address_complement,
      neighborhood,
      city,
      state,
      roles,
      percentage,
      category_id,
      currentPassword,
      newPassword
    } = req.body;

    const userCheck = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const existingUser = userCheck.rows[0];

    let passwordHash = existingUser.password_hash;
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: 'Senha atual é obrigatória para alterar a senha' });
      }

      const isValidPassword = await bcrypt.compare(currentPassword, existingUser.password_hash);
      if (!isValidPassword) {
        return res.status(400).json({ message: 'Senha atual incorreta' });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({ message: 'Nova senha deve ter pelo menos 6 caracteres' });
      }

      const saltRounds = 10;
      passwordHash = await bcrypt.hash(newPassword, saltRounds);
    }

    let rolesJson = existingUser.roles;
    if (roles !== undefined) {
      const rolesArray = Array.isArray(roles) ? roles : [roles];
      rolesJson = stringifyRoles(rolesArray);
    }

    const result = await pool.query(
      `UPDATE users 
       SET name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
           address_number = $6, address_complement = $7, neighborhood = $8,
           city = $9, state = $10, roles = $11, percentage = $12, category_id = $13,
           password_hash = $14, updated_at = CURRENT_TIMESTAMP
       WHERE id = $15
       RETURNING id, name, cpf, email, roles, percentage, category_id`,
      [name, email, phone, birth_date, address, address_number, address_complement,
       neighborhood, city, state, rolesJson, percentage, category_id, passwordHash, id]
    );

    const updatedUser = result.rows[0];
    updatedUser.roles = parseRoles(updatedUser.roles);

    res.json(updatedUser);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Activate client subscription
app.put('/api/users/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { expiry_date } = req.body;

    if (!expiry_date) {
      return res.status(400).json({ message: 'Data de expiração é obrigatória' });
    }

    const userCheck = await pool.query(
      'SELECT id, roles FROM users WHERE id = $1',
      [id]
    );

    if (userCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = userCheck.rows[0];
    const userRoles = parseRoles(user.roles);

    if (!userRoles.includes('client')) {
      return res.status(400).json({ message: 'Usuário não é um cliente' });
    }

    const result = await pool.query(
      `UPDATE users 
       SET subscription_status = 'active', 
           subscription_expiry = $1,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $2
       RETURNING id, name, subscription_status, subscription_expiry`,
      [expiry_date, id]
    );

    res.json({
      message: 'Cliente ativado com sucesso',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('Error activating client:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete user
app.delete('/api/users/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    const consultationsCheck = await pool.query(
      `SELECT COUNT(*) FROM consultations WHERE client_id = $1 OR professional_id = $1`,
      [id]
    );

    if (parseInt(consultationsCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir usuário que possui consultas registradas' 
      });
    }

    const result = await pool.query(
      `DELETE FROM users WHERE id = $1 RETURNING *`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json({ message: 'Usuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// CLIENT ROUTES
// =============================================================================

// Lookup client by CPF
app.get('/api/clients/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.toString().replace(/\D/g, '');

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    const result = await pool.query(
      `SELECT id, name, cpf, email, phone, roles, subscription_status, subscription_expiry
       FROM users 
       WHERE cpf = $1 AND roles::jsonb ? 'client'`,
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    const client = result.rows[0];
    client.roles = parseRoles(client.roles);

    res.json(client);
  } catch (error) {
    console.error('Error looking up client:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get all clients (for admin)
app.get('/api/clients', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, cpf, email, phone, subscription_status, subscription_expiry, created_at
       FROM users 
       WHERE roles::jsonb ? 'client'
       ORDER BY name`
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching clients:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// PROFESSIONAL ROUTES
// =============================================================================

// Get all professionals
app.get('/api/professionals', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.phone, u.address, u.address_number, 
              u.address_complement, u.neighborhood, u.city, u.state, u.roles, u.photo_url,
              sc.name as category_name
       FROM users u
       LEFT JOIN service_categories sc ON u.category_id = sc.id
       WHERE u.roles::jsonb ? 'professional'
       ORDER BY u.name`
    );

    const professionals = result.rows.map(prof => ({
      ...prof,
      roles: parseRoles(prof.roles)
    }));

    res.json(professionals);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// DEPENDENTS ROUTES
// =============================================================================

// Get dependents for a client
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;

    if (req.user.currentRole === 'client' && req.user.id !== parseInt(clientId)) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    const result = await pool.query(
      'SELECT * FROM dependents WHERE client_id = $1 ORDER BY name',
      [clientId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching dependents:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Lookup dependent by CPF
app.get('/api/dependents/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.toString().replace(/\D/g, '');

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    const result = await pool.query(
      `SELECT d.*, u.name as client_name, u.subscription_status as client_subscription_status
       FROM dependents d
       JOIN users u ON d.client_id = u.id
       WHERE d.cpf = $1`,
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error looking up dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create dependent
app.post('/api/dependents', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    if (req.user.currentRole === 'client' && req.user.id !== client_id) {
      return res.status(403).json({ message: 'Você só pode adicionar dependentes para sua própria conta' });
    }

    if (!name || !cpf) {
      return res.status(400).json({ message: 'Nome e CPF são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    const existingDependent = await pool.query(
      'SELECT id FROM dependents WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingDependent.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado como dependente' });
    }

    const existingClient = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingClient.rows.length > 0) {
      return res.status(400).json({ message: 'Este CPF já está cadastrado como cliente' });
    }

    const dependentCount = await pool.query(
      'SELECT COUNT(*) FROM dependents WHERE client_id = $1',
      [client_id]
    );

    if (parseInt(dependentCount.rows[0].count) >= 10) {
      return res.status(400).json({ message: 'Limite máximo de 10 dependentes por cliente' });
    }

    const result = await pool.query(
      `INSERT INTO dependents (client_id, name, cpf, birth_date)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [client_id, name, cleanCpf, birth_date]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update dependent
app.put('/api/dependents/:id', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    const dependentCheck = await pool.query(
      'SELECT client_id FROM dependents WHERE id = $1',
      [id]
    );

    if (dependentCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    if (req.user.currentRole === 'client' && req.user.id !== dependentCheck.rows[0].client_id) {
      return res.status(403).json({ message: 'Você só pode editar seus próprios dependentes' });
    }

    const result = await pool.query(
      `UPDATE dependents 
       SET name = $1, birth_date = $2, updated_at = CURRENT_TIMESTAMP
       WHERE id = $3 RETURNING *`,
      [name, birth_date, id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete dependent
app.delete('/api/dependents/:id', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { id } = req.params;

    const dependentCheck = await pool.query(
      'SELECT client_id FROM dependents WHERE id = $1',
      [id]
    );

    if (dependentCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    if (req.user.currentRole === 'client' && req.user.id !== dependentCheck.rows[0].client_id) {
      return res.status(403).json({ message: 'Você só pode excluir seus próprios dependentes' });
    }

    const consultationsCheck = await pool.query(
      'SELECT COUNT(*) FROM consultations WHERE dependent_id = $1',
      [id]
    );

    if (parseInt(consultationsCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir dependente que possui consultas registradas' 
      });
    }

    await pool.query('DELETE FROM dependents WHERE id = $1', [id]);

    res.json({ message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// SERVICE CATEGORIES ROUTES
// =============================================================================

// Get all service categories
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM service_categories ORDER BY name'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching service categories:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create service category
app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome da categoria é obrigatório' });
    }

    const result = await pool.query(
      'INSERT INTO service_categories (name, description) VALUES ($1, $2) RETURNING *',
      [name, description]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating service category:', error);
    if (error.code === '23505') {
      res.status(400).json({ message: 'Já existe uma categoria com este nome' });
    } else {
      res.status(500).json({ message: 'Erro interno do servidor' });
    }
  }
});

// =============================================================================
// SERVICES ROUTES
// =============================================================================

// Get all services
app.get('/api/services', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.*, sc.name as category_name 
       FROM services s
       LEFT JOIN service_categories sc ON s.category_id = sc.id
       ORDER BY sc.name, s.name`
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create service
app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !description || !base_price) {
      return res.status(400).json({ message: 'Nome, descrição e preço base são obrigatórios' });
    }

    const result = await pool.query(
      `INSERT INTO services (name, description, base_price, category_id, is_base_service)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [name, description, base_price, category_id, is_base_service || false]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update service
app.put('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, base_price, category_id, is_base_service } = req.body;

    const result = await pool.query(
      `UPDATE services 
       SET name = $1, description = $2, base_price = $3, category_id = $4, 
           is_base_service = $5, updated_at = CURRENT_TIMESTAMP
       WHERE id = $6 RETURNING *`,
      [name, description, base_price, category_id, is_base_service, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete service
app.delete('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    const consultationsCheck = await pool.query(
      'SELECT COUNT(*) FROM consultations WHERE service_id = $1',
      [id]
    );

    if (parseInt(consultationsCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir serviço que possui consultas registradas' 
      });
    }

    const result = await pool.query(
      'DELETE FROM services WHERE id = $1 RETURNING *',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    res.json({ message: 'Serviço excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// PRIVATE PATIENTS ROUTES
// =============================================================================

// Get professional's private patients
app.get('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM private_patients 
       WHERE professional_id = $1 
       ORDER BY name`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching private patients:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create new private patient
app.post('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name,
      cpf,
      email,
      phone,
      birth_date,
      address,
      address_number,
      address_complement,
      neighborhood,
      city,
      state,
      zip_code
    } = req.body;

    const existingPatient = await pool.query(
      `SELECT id FROM private_patients WHERE cpf = $1 AND professional_id = $2`,
      [cpf, req.user.id]
    );

    if (existingPatient.rows.length > 0) {
      return res.status(400).json({ message: 'Já existe um paciente cadastrado com este CPF' });
    }

    const result = await pool.query(
      `INSERT INTO private_patients 
       (professional_id, name, cpf, email, phone, birth_date, address, 
        address_number, address_complement, neighborhood, city, state, zip_code)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING *`,
      [req.user.id, name, cpf, email, phone, birth_date, address, 
       address_number, address_complement, neighborhood, city, state, zip_code]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update private patient
app.put('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      email,
      phone,
      birth_date,
      address,
      address_number,
      address_complement,
      neighborhood,
      city,
      state,
      zip_code
    } = req.body;

    const result = await pool.query(
      `UPDATE private_patients 
       SET name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
           address_number = $6, address_complement = $7, neighborhood = $8,
           city = $9, state = $10, zip_code = $11, updated_at = CURRENT_TIMESTAMP
       WHERE id = $12 AND professional_id = $13
       RETURNING *`,
      [name, email, phone, birth_date, address, address_number, address_complement,
       neighborhood, city, state, zip_code, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete private patient
app.delete('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    const appointmentsCheck = await pool.query(
      `SELECT COUNT(*) FROM appointments WHERE private_patient_id = $1`,
      [id]
    );

    if (parseInt(appointmentsCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir paciente que possui agendamentos' 
      });
    }

    const result = await pool.query(
      `DELETE FROM private_patients WHERE id = $1 AND professional_id = $2 RETURNING *`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    res.json({ message: 'Paciente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// ATTENDANCE LOCATIONS ROUTES
// =============================================================================

// Get professional's attendance locations
app.get('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM attendance_locations 
       WHERE professional_id = $1 
       ORDER BY is_default DESC, name`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching attendance locations:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create new attendance location
app.post('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name,
      address,
      address_number,
      address_complement,
      neighborhood,
      city,
      state,
      zip_code,
      phone,
      is_default
    } = req.body;

    if (is_default) {
      await pool.query(
        `UPDATE attendance_locations SET is_default = false WHERE professional_id = $1`,
        [req.user.id]
      );
    }

    const result = await pool.query(
      `INSERT INTO attendance_locations 
       (professional_id, name, address, address_number, address_complement, 
        neighborhood, city, state, zip_code, phone, is_default)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING *`,
      [req.user.id, name, address, address_number, address_complement,
       neighborhood, city, state, zip_code, phone, is_default]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating attendance location:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update attendance location
app.put('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      address,
      address_number,
      address_complement,
      neighborhood,
      city,
      state,
      zip_code,
      phone,
      is_default
    } = req.body;

    if (is_default) {
      await pool.query(
        `UPDATE attendance_locations SET is_default = false 
         WHERE professional_id = $1 AND id != $2`,
        [req.user.id, id]
      );
    }

    const result = await pool.query(
      `UPDATE attendance_locations 
       SET name = $1, address = $2, address_number = $3, address_complement = $4,
           neighborhood = $5, city = $6, state = $7, zip_code = $8, phone = $9,
           is_default = $10, updated_at = CURRENT_TIMESTAMP
       WHERE id = $11 AND professional_id = $12
       RETURNING *`,
      [name, address, address_number, address_complement, neighborhood, city, state,
       zip_code, phone, is_default, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Local de atendimento não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating attendance location:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete attendance location
app.delete('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    const appointmentsCheck = await pool.query(
      `SELECT COUNT(*) FROM appointments WHERE location_id = $1`,
      [id]
    );

    if (parseInt(appointmentsCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir local que possui agendamentos' 
      });
    }

    const result = await pool.query(
      `DELETE FROM attendance_locations WHERE id = $1 AND professional_id = $2 RETURNING *`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Local de atendimento não encontrado' });
    }

    res.json({ message: 'Local de atendimento excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting attendance location:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// SCHEDULING ROUTES
// =============================================================================

// Get professional's schedule settings
app.get('/api/scheduling/settings', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM professional_schedule_settings WHERE professional_id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.json({
        professional_id: req.user.id,
        work_days: [1, 2, 3, 4, 5],
        work_start_time: '08:00',
        work_end_time: '18:00',
        break_start_time: '12:00',
        break_end_time: '13:00',
        consultation_duration: 60,
        has_scheduling_subscription: true
      });
    }

    const settings = result.rows[0];
    settings.has_scheduling_subscription = true;

    res.json(settings);
  } catch (error) {
    console.error('Error fetching schedule settings:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update professional's schedule settings
app.put('/api/scheduling/settings', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      work_days,
      work_start_time,
      work_end_time,
      break_start_time,
      break_end_time,
      consultation_duration
    } = req.body;

    const result = await pool.query(
      `INSERT INTO professional_schedule_settings 
       (professional_id, work_days, work_start_time, work_end_time, break_start_time, break_end_time, consultation_duration, has_scheduling_subscription)
       VALUES ($1, $2, $3, $4, $5, $6, $7, true)
       ON CONFLICT (professional_id) 
       DO UPDATE SET 
         work_days = $2,
         work_start_time = $3,
         work_end_time = $4,
         break_start_time = $5,
         break_end_time = $6,
         consultation_duration = $7,
         has_scheduling_subscription = true,
         updated_at = CURRENT_TIMESTAMP
       RETURNING *`,
      [req.user.id, work_days, work_start_time, work_end_time, break_start_time, break_end_time, consultation_duration]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating schedule settings:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get professional's appointments
app.get('/api/scheduling/appointments', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    const result = await pool.query(
      `SELECT a.*, 
              COALESCE(pp.name, c.name, d.name) as patient_name,
              COALESCE(pp.cpf, c.cpf, d.cpf) as patient_cpf,
              s.name as service_name,
              al.name as location_name,
              al.address as location_address
       FROM appointments a
       LEFT JOIN private_patients pp ON a.private_patient_id = pp.id
       LEFT JOIN users c ON a.client_id = c.id
       LEFT JOIN dependents d ON a.dependent_id = d.id
       LEFT JOIN services s ON a.service_id = s.id
       LEFT JOIN attendance_locations al ON a.location_id = al.id
       WHERE a.professional_id = $1
       AND a.appointment_date >= $2
       AND a.appointment_date <= $3
       ORDER BY a.appointment_date, a.appointment_time`,
      [req.user.id, start_date, end_date]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching appointments:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create new appointment
app.post('/api/scheduling/appointments', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      private_patient_id,
      client_id,
      dependent_id,
      service_id,
      appointment_date,
      appointment_time,
      location_id,
      notes,
      value
    } = req.body;

    const result = await pool.query(
      `INSERT INTO appointments 
       (professional_id, private_patient_id, client_id, dependent_id, service_id, 
        appointment_date, appointment_time, location_id, notes, value, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'scheduled')
       RETURNING *`,
      [req.user.id, private_patient_id, client_id, dependent_id, service_id, 
       appointment_date, appointment_time, location_id, notes, value]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating appointment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update appointment
app.put('/api/scheduling/appointments/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      appointment_date,
      appointment_time,
      location_id,
      notes,
      value,
      status
    } = req.body;

    const result = await pool.query(
      `UPDATE appointments 
       SET appointment_date = $1, appointment_time = $2, location_id = $3, 
           notes = $4, value = $5, status = $6, updated_at = CURRENT_TIMESTAMP
       WHERE id = $7 AND professional_id = $8
       RETURNING *`,
      [appointment_date, appointment_time, location_id, notes, value, status, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Agendamento não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating appointment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete appointment
app.delete('/api/scheduling/appointments/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `DELETE FROM appointments WHERE id = $1 AND professional_id = $2 RETURNING *`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Agendamento não encontrado' });
    }

    res.json({ message: 'Agendamento excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting appointment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// CONSULTATIONS ROUTES
// =============================================================================

// Get consultations for current user
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query;
    let params;
    
    if (req.user.currentRole === 'client') {
      query = `
        SELECT c.*, 
               COALESCE(pp.name, u.name, d.name) as client_name,
               CASE 
                 WHEN d.id IS NOT NULL THEN true 
                 ELSE false 
               END as is_dependent,
               s.name as service_name,
               prof.name as professional_name
        FROM consultations c
        LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
        LEFT JOIN users u ON c.client_id = u.id
        LEFT JOIN dependents d ON c.dependent_id = d.id
        LEFT JOIN services s ON c.service_id = s.id
        LEFT JOIN users prof ON c.professional_id = prof.id
        WHERE c.client_id = $1 OR c.dependent_id IN (
          SELECT id FROM dependents WHERE client_id = $1
        )
        ORDER BY c.date DESC
      `;
      params = [req.user.id];
    } else if (req.user.currentRole === 'professional') {
      query = `
        SELECT c.*, 
               COALESCE(pp.name, u.name, d.name) as client_name,
               CASE 
                 WHEN d.id IS NOT NULL THEN true 
                 ELSE false 
               END as is_dependent,
               s.name as service_name,
               prof.name as professional_name
        FROM consultations c
        LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
        LEFT JOIN users u ON c.client_id = u.id
        LEFT JOIN dependents d ON c.dependent_id = d.id
        LEFT JOIN services s ON c.service_id = s.id
        LEFT JOIN users prof ON c.professional_id = prof.id
        WHERE c.professional_id = $1
        ORDER BY c.date DESC
      `;
      params = [req.user.id];
    } else if (req.user.currentRole === 'admin') {
      query = `
        SELECT c.*, 
               COALESCE(pp.name, u.name, d.name) as client_name,
               CASE 
                 WHEN d.id IS NOT NULL THEN true 
                 ELSE false 
               END as is_dependent,
               s.name as service_name,
               prof.name as professional_name
        FROM consultations c
        LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
        LEFT JOIN users u ON c.client_id = u.id
        LEFT JOIN dependents d ON c.dependent_id = d.id
        LEFT JOIN services s ON c.service_id = s.id
        LEFT JOIN users prof ON c.professional_id = prof.id
        ORDER BY c.date DESC
      `;
      params = [];
    }

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching consultations:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create new consultation
app.post('/api/consultations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      client_id,
      dependent_id,
      private_patient_id,
      service_id,
      location_id,
      value,
      date,
      notes,
      appointment_date,
      appointment_time,
      create_appointment
    } = req.body;

    // Create consultation
    const consultationResult = await pool.query(
      `INSERT INTO consultations 
       (professional_id, client_id, dependent_id, private_patient_id, service_id, 
        location_id, date, value, notes, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'completed')
       RETURNING *`,
      [req.user.id, client_id, dependent_id, private_patient_id, service_id, 
       location_id, date, value, notes]
    );

    const consultation = consultationResult.rows[0];

    // Create appointment if requested
    let appointment = null;
    if (create_appointment && appointment_date && appointment_time) {
      const appointmentResult = await pool.query(
        `INSERT INTO appointments 
         (professional_id, client_id, dependent_id, private_patient_id, service_id, 
          appointment_date, appointment_time, location_id, notes, value, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'scheduled')
         RETURNING *`,
        [req.user.id, client_id, dependent_id, private_patient_id, service_id, 
         appointment_date, appointment_time, location_id, notes, value]
      );
      
      appointment = appointmentResult.rows[0];
    }

    res.status(201).json({ 
      consultation,
      appointment,
      message: 'Consulta registrada com sucesso'
    });
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// MEDICAL RECORDS ROUTES
// =============================================================================

// Get medical records for current professional
app.get('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT mr.*, 
              COALESCE(pp.name, c.name, d.name) as patient_name,
              COALESCE(pp.cpf, c.cpf, d.cpf) as patient_cpf
       FROM medical_records mr
       LEFT JOIN private_patients pp ON mr.private_patient_id = pp.id
       LEFT JOIN users c ON mr.client_id = c.id
       LEFT JOIN dependents d ON mr.dependent_id = d.id
       WHERE mr.professional_id = $1
       ORDER BY mr.created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical records:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create new medical record
app.post('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      private_patient_id,
      client_id,
      dependent_id,
      appointment_id,
      chief_complaint,
      history_present_illness,
      past_medical_history,
      medications,
      allergies,
      physical_examination,
      diagnosis,
      treatment_plan,
      notes,
      vital_signs
    } = req.body;

    const result = await pool.query(
      `INSERT INTO medical_records 
       (professional_id, private_patient_id, client_id, dependent_id, appointment_id,
        chief_complaint, history_present_illness, past_medical_history, medications,
        allergies, physical_examination, diagnosis, treatment_plan, notes, vital_signs)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
       RETURNING *`,
      [req.user.id, private_patient_id, client_id, dependent_id, appointment_id,
       chief_complaint, history_present_illness, past_medical_history, medications,
       allergies, physical_examination, diagnosis, treatment_plan, notes, vital_signs]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update medical record
app.put('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      chief_complaint,
      history_present_illness,
      past_medical_history,
      medications,
      allergies,
      physical_examination,
      diagnosis,
      treatment_plan,
      notes,
      vital_signs
    } = req.body;

    const result = await pool.query(
      `UPDATE medical_records 
       SET chief_complaint = $1, history_present_illness = $2, past_medical_history = $3,
           medications = $4, allergies = $5, physical_examination = $6, diagnosis = $7,
           treatment_plan = $8, notes = $9, vital_signs = $10, updated_at = CURRENT_TIMESTAMP
       WHERE id = $11 AND professional_id = $12
       RETURNING *`,
      [chief_complaint, history_present_illness, past_medical_history, medications,
       allergies, physical_examination, diagnosis, treatment_plan, notes, vital_signs, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete medical record
app.delete('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `DELETE FROM medical_records WHERE id = $1 AND professional_id = $2 RETURNING *`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    res.json({ message: 'Prontuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// MEDICAL DOCUMENTS ROUTES
// =============================================================================

// Get medical documents for current professional
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT md.*, 
              COALESCE(pp.name, c.name, d.name) as patient_name
       FROM medical_documents md
       LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
       LEFT JOIN users c ON md.client_id = c.id
       LEFT JOIN dependents d ON md.dependent_id = d.id
       WHERE md.professional_id = $1
       ORDER BY md.created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical documents:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create medical document
app.post('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { private_patient_id, client_id, dependent_id, document_type, title, template_data } = req.body;

    if (!document_type || !title) {
      return res.status(400).json({ message: 'Tipo de documento e título são obrigatórios' });
    }

    const documentUrl = `${process.env.API_URL || 'http://localhost:3001'}/documents/${Date.now()}_${title.replace(/\s+/g, '_')}.pdf`;

    const result = await pool.query(
      `INSERT INTO medical_documents 
       (professional_id, private_patient_id, client_id, dependent_id, document_type, title, document_url, template_data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [req.user.id, private_patient_id, client_id, dependent_id, document_type, title, documentUrl, JSON.stringify(template_data)]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating medical document:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// REPORTS ROUTES
// =============================================================================

// Get revenue report for admin
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    const totalRevenueResult = await pool.query(
      `SELECT COALESCE(SUM(value), 0) as total_revenue
       FROM consultations 
       WHERE date >= $1 AND date <= $2`,
      [start_date, end_date]
    );

    const totalRevenue = parseFloat(totalRevenueResult.rows[0].total_revenue) || 0;

    const professionalRevenueResult = await pool.query(
      `SELECT 
         p.name as professional_name,
         p.percentage as professional_percentage,
         COALESCE(SUM(c.value), 0) as revenue,
         COUNT(c.id) as consultation_count,
         COALESCE(SUM(c.value * (p.percentage / 100.0)), 0) as professional_payment,
         COALESCE(SUM(c.value * ((100 - p.percentage) / 100.0)), 0) as clinic_revenue
       FROM users p
       LEFT JOIN consultations c ON c.professional_id = p.id 
         AND c.date >= $1 AND c.date <= $2
       WHERE p.roles::jsonb ? 'professional'
       GROUP BY p.id, p.name, p.percentage
       ORDER BY revenue DESC`,
      [start_date, end_date]
    );

    const serviceRevenueResult = await pool.query(
      `SELECT 
         s.name as service_name,
         COALESCE(SUM(c.value), 0) as revenue,
         COUNT(c.id) as consultation_count
       FROM services s
       LEFT JOIN consultations c ON c.service_id = s.id 
         AND c.date >= $1 AND c.date <= $2
       GROUP BY s.id, s.name
       HAVING COUNT(c.id) > 0
       ORDER BY revenue DESC`,
      [start_date, end_date]
    );

    res.json({
      total_revenue: totalRevenue,
      revenue_by_professional: professionalRevenueResult.rows,
      revenue_by_service: serviceRevenueResult.rows,
    });
  } catch (error) {
    console.error('Error generating revenue report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get professional revenue report
app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    const professionalResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    if (professionalResult.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professionalPercentage = professionalResult.rows[0].percentage || 50;

    const consultationsResult = await pool.query(
      `SELECT 
         c.date,
         COALESCE(u.name, d.name, pp.name) as client_name,
         s.name as service_name,
         c.value as total_value,
         CASE 
           WHEN pp.id IS NOT NULL THEN c.value
           ELSE c.value * ((100 - $3) / 100.0)
         END as amount_to_pay
       FROM consultations c
       LEFT JOIN users u ON c.client_id = u.id
       LEFT JOIN dependents d ON c.dependent_id = d.id
       LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
       LEFT JOIN services s ON c.service_id = s.id
       WHERE c.professional_id = $1 
       AND c.date >= $2 AND c.date <= $4
       ORDER BY c.date DESC`,
      [req.user.id, start_date, professionalPercentage, end_date]
    );

    const consultations = consultationsResult.rows;
    const totalRevenue = consultations.reduce((sum, c) => sum + parseFloat(c.total_value), 0);
    const totalAmountToPay = consultations.reduce((sum, c) => sum + parseFloat(c.amount_to_pay), 0);

    res.json({
      summary: {
        professional_percentage: professionalPercentage,
        total_revenue: totalRevenue,
        consultation_count: consultations.length,
        amount_to_pay: totalAmountToPay,
      },
      consultations: consultations,
    });
  } catch (error) {
    console.error('Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get detailed professional report
app.get('/api/reports/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    const professionalId = req.user.id;
    
    console.log('🔄 Generating detailed professional report for:', professionalId);
    
    // Get professional percentage
    const professionalQuery = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [professionalId]
    );
    
    const professionalPercentage = professionalQuery.rows[0]?.percentage || 50;
    
    // Get convenio consultations (from consultations table)
    const convenioQuery = `
      SELECT 
        COUNT(*) as count,
        COALESCE(SUM(c.value), 0)::decimal as revenue
      FROM consultations c
      WHERE c.professional_id = $1
        AND c.date >= $2
        AND c.date <= $3
        AND (c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL)
    `;
    
    const convenioResult = await pool.query(convenioQuery, [
      professionalId,
      start_date,
      end_date
    ]);
    
    // Get private consultations (from appointments table)
    const privateQuery = `
      SELECT 
        COUNT(*) as count,
        COALESCE(SUM(a.value), 0)::decimal as revenue
      FROM appointments a
      WHERE a.professional_id = $1
        AND a.appointment_date >= $2
        AND a.appointment_date <= $3
        AND a.private_patient_id IS NOT NULL
    `;
    
    const privateResult = await pool.query(privateQuery, [
      professionalId,
      start_date,
      end_date
    ]);
    
    const convenioData = convenioResult.rows[0];
    const privateData = privateResult.rows[0];
    
    const convenioConsultations = parseInt(convenioData.count) || 0;
    const convenioRevenue = parseFloat(convenioData.revenue) || 0;
    const privateConsultations = parseInt(privateData.count) || 0;
    const privateRevenue = parseFloat(privateData.revenue) || 0;
    
    const totalRevenue = convenioRevenue + privateRevenue;
    const amountToPay = convenioRevenue * (100 - professionalPercentage) / 100.0;
    
    const summary = {
      total_consultations: convenioConsultations + privateConsultations,
      convenio_consultations: convenioConsultations,
      private_consultations: privateConsultations,
      total_revenue: totalRevenue,
      convenio_revenue: convenioRevenue,
      private_revenue: privateRevenue,
      professional_percentage: professionalPercentage,
      amount_to_pay: amountToPay
    };
    
    res.json({ summary });
  } catch (error) {
    console.error('❌ Error generating detailed professional report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get clients by city report
app.get('/api/reports/clients-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         city,
         state,
         COUNT(*) as client_count,
         COUNT(CASE WHEN subscription_status = 'active' THEN 1 END) as active_clients,
         COUNT(CASE WHEN subscription_status = 'pending' THEN 1 END) as pending_clients,
         COUNT(CASE WHEN subscription_status = 'expired' THEN 1 END) as expired_clients
       FROM users 
       WHERE roles::jsonb ? 'client' 
       AND city IS NOT NULL 
       AND city != ''
       GROUP BY city, state
       ORDER BY client_count DESC, city`
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error generating clients by city report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get professionals by city report
app.get('/api/reports/professionals-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         u.city,
         u.state,
         COUNT(*) as total_professionals,
         json_agg(
           json_build_object(
             'category_name', COALESCE(sc.name, 'Sem categoria'),
             'count', 1
           )
         ) as categories_raw
       FROM users u
       LEFT JOIN service_categories sc ON u.category_id = sc.id
       WHERE u.roles::jsonb ? 'professional' 
       AND u.city IS NOT NULL 
       AND u.city != ''
       GROUP BY u.city, u.state
       ORDER BY total_professionals DESC, u.city`
    );

    const processedData = result.rows.map(row => {
      const categoryMap = new Map();
      
      row.categories_raw.forEach((cat) => {
        const name = cat.category_name;
        if (categoryMap.has(name)) {
          categoryMap.set(name, categoryMap.get(name) + 1);
        } else {
          categoryMap.set(name, 1);
        }
      });

      const categories = Array.from(categoryMap.entries()).map(([name, count]) => ({
        category_name: name,
        count: count
      }));

      return {
        city: row.city,
        state: row.state,
        total_professionals: parseInt(row.total_professionals),
        categories: categories
      };
    });

    res.json(processedData);
  } catch (error) {
    console.error('Error generating professionals by city report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// ADMIN SCHEDULING ACCESS ROUTES
// =============================================================================

// Get professionals with scheduling access
app.get('/api/admin/professionals-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         u.id,
         u.name,
         u.email,
         u.phone,
         sc.name as category_name,
         COALESCE(pss.status = 'active' AND pss.expires_at > NOW(), false) as has_scheduling_access,
         pss.expires_at as access_expires_at,
         pss.granted_by as access_granted_by,
         pss.granted_at as access_granted_at,
         pss.status as subscription_status
       FROM users u
       LEFT JOIN service_categories sc ON u.category_id = sc.id
       LEFT JOIN professional_scheduling_subscriptions pss ON u.id = pss.professional_id
       WHERE u.roles::jsonb ? 'professional'
       ORDER BY u.name`
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Grant scheduling access
app.post('/api/admin/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;

    if (!professional_id || !expires_at) {
      return res.status(400).json({ message: 'ID do profissional e data de expiração são obrigatórios' });
    }

    const professionalCheck = await pool.query(
      `SELECT id FROM users WHERE id = $1 AND roles::jsonb ? 'professional'`,
      [professional_id]
    );

    if (professionalCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const result = await pool.query(
      `INSERT INTO professional_scheduling_subscriptions 
       (professional_id, status, expires_at, granted_by, granted_at, reason, is_admin_granted)
       VALUES ($1, 'active', $2, $3, CURRENT_TIMESTAMP, $4, true)
       ON CONFLICT (professional_id) 
       DO UPDATE SET 
         status = 'active',
         expires_at = $2,
         granted_by = $3,
         granted_at = CURRENT_TIMESTAMP,
         reason = $4,
         is_admin_granted = true,
         updated_at = CURRENT_TIMESTAMP
       RETURNING *`,
      [professional_id, expires_at, req.user.name, reason]
    );

    res.json({
      message: 'Acesso à agenda concedido com sucesso',
      subscription: result.rows[0]
    });
  } catch (error) {
    console.error('Error granting scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Revoke scheduling access
app.post('/api/admin/revoke-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id } = req.body;

    if (!professional_id) {
      return res.status(400).json({ message: 'ID do profissional é obrigatório' });
    }

    await pool.query(
      `UPDATE professional_scheduling_subscriptions 
       SET status = 'revoked', 
           revoked_by = $1,
           revoked_at = CURRENT_TIMESTAMP,
           updated_at = CURRENT_TIMESTAMP
       WHERE professional_id = $2`,
      [req.user.name, professional_id]
    );

    res.json({ message: 'Acesso à agenda revogado com sucesso' });
  } catch (error) {
    console.error('Error revoking scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// PAYMENT ROUTES
// =============================================================================

// Create subscription payment for clients
app.post('/api/create-subscription', authenticate, authorize(['client']), async (req, res) => {
  try {
    console.log('🔄 Creating subscription for client:', req.user.id);

    const existingSubscription = await pool.query(
      `SELECT * FROM client_subscriptions 
       WHERE client_id = $1 AND status = 'active' AND expires_at > NOW()`,
      [req.user.id]
    );

    if (existingSubscription.rows.length > 0) {
      return res.status(400).json({ 
        message: 'Você já possui uma assinatura ativa' 
      });
    }

    const dependentsResult = await pool.query(
      `SELECT COUNT(*) as count FROM dependents WHERE client_id = $1`,
      [req.user.id]
    );

    const dependentCount = parseInt(dependentsResult.rows[0].count) || 0;
    const basePrice = 250;
    const dependentPrice = 50;
    const totalAmount = basePrice + (dependentCount * dependentPrice);

    const externalReference = `subscription_${req.user.id}_${Date.now()}`;

    await pool.query(
      `INSERT INTO client_payments 
       (client_id, amount, status, external_reference, dependent_count)
       VALUES ($1, $2, 'pending', $3, $4)`,
      [req.user.id, totalAmount, externalReference, dependentCount]
    );

    res.json({
      preference_id: `mock_${externalReference}`,
      init_point: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/client/payment-success`,
      total_amount: totalAmount,
      dependent_count: dependentCount
    });
  } catch (error) {
    console.error('❌ Error creating subscription:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento da assinatura',
      error: error.message 
    });
  }
});

// Create professional payment
app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor inválido' });
    }

    console.log('🔄 Creating professional payment for:', req.user.id, 'Amount:', amount);

    const externalReference = `professional_${req.user.id}_${Date.now()}`;

    await pool.query(
      `INSERT INTO professional_payments 
       (professional_id, amount, status, external_reference)
       VALUES ($1, $2, 'pending', $3)`,
      [req.user.id, amount, externalReference]
    );

    res.json({
      preference_id: `mock_${externalReference}`,
      init_point: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/payment-success`,
    });
  } catch (error) {
    console.error('❌ Error creating professional payment:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento',
      error: error.message 
    });
  }
});

// =============================================================================
// IMAGE UPLOAD ROUTES
// =============================================================================

// Upload professional image
app.post('/api/upload-image', authenticate, authorize(['professional']), upload.single('image'), async (req, res) => {
  try {
    console.log('🔄 Processing image upload for user:', req.user.id);
    
    if (!req.file) {
      return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
    }

    let imageUrl;
    
    if (isCloudinaryConfigured && req.file.path) {
      imageUrl = req.file.path;
      console.log('✅ Image uploaded to Cloudinary:', imageUrl);
    } else {
      console.warn('⚠️ Cloudinary not configured, using fallback');
      return res.status(500).json({ message: 'Serviço de upload não configurado' });
    }

    const updateResult = await pool.query(
      'UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING photo_url',
      [imageUrl, req.user.id]
    );

    if (updateResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json({ 
      message: 'Imagem atualizada com sucesso',
      imageUrl: imageUrl
    });
  } catch (error) {
    console.error('❌ Error uploading image:', error);
    res.status(500).json({ 
      message: 'Erro ao fazer upload da imagem',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// =============================================================================
// HEALTH CHECK AND SYSTEM INFO
// =============================================================================

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    version: '1.0.0',
    services: {
      database: 'connected',
      cloudinary: isCloudinaryConfigured ? 'configured' : 'not configured'
    }
  });
});

// System info endpoint
app.get('/api/system-info', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const userStats = await pool.query(
      `SELECT 
         COUNT(*) as total_users,
         COUNT(CASE WHEN roles::jsonb ? 'client' THEN 1 END) as total_clients,
         COUNT(CASE WHEN roles::jsonb ? 'professional' THEN 1 END) as total_professionals,
         COUNT(CASE WHEN roles::jsonb ? 'admin' THEN 1 END) as total_admins
       FROM users`
    );

    const consultationStats = await pool.query(
      `SELECT 
         COUNT(*) as total_consultations,
         COUNT(CASE WHEN date >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as consultations_last_30_days,
         COALESCE(SUM(value), 0) as total_revenue
       FROM consultations`
    );

    res.json({
      system: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        node_version: process.version,
        environment: process.env.NODE_ENV || 'development'
      },
      database: {
        users: userStats.rows[0],
        consultations: consultationStats.rows[0]
      },
      services: {
        cloudinary: isCloudinaryConfigured
      }
    });
  } catch (error) {
    console.error('Error fetching system info:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Database connection test
app.get('/api/db-test', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as current_time, version() as postgres_version');
    res.json({
      status: 'connected',
      ...result.rows[0]
    });
  } catch (error) {
    console.error('Database connection error:', error);
    res.status(500).json({ 
      status: 'error',
      message: 'Falha na conexão com o banco de dados' 
    });
  }
});

// =============================================================================
// ERROR HANDLING
// =============================================================================

// 404 handler for API routes
app.use('/api/*', (req, res) => {
  console.warn(`🚫 API route not found: ${req.method} ${req.path}`);
  res.status(404).json({ 
    message: 'Endpoint não encontrado',
    path: req.path,
    method: req.method
  });
});

// Serve React app for all other routes
app.get('*', (req, res) => {
  try {
    const indexPath = path.join(__dirname, '../dist/index.html');
    res.sendFile(indexPath);
  } catch (error) {
    console.error('Error serving index.html:', error);
    res.status(500).send('Erro interno do servidor');
  }
});

// Global error handling middleware
app.use((err, req, res, next) => {
  console.error('🚨 Server error:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString()
  });

  if (err.name === 'ValidationError') {
    return res.status(400).json({ 
      message: 'Dados inválidos',
      details: err.message 
    });
  }

  if (err.name === 'UnauthorizedError' || err.name === 'JsonWebTokenError') {
    return res.status(401).json({ 
      message: 'Token inválido ou expirado' 
    });
  }

  if (err.code === '23505') {
    return res.status(400).json({ 
      message: 'Dados duplicados - registro já existe' 
    });
  }

  if (err.code === '23503') {
    return res.status(400).json({ 
      message: 'Referência inválida - dados relacionados não encontrados' 
    });
  }

  res.status(err.status || 500).json({ 
    message: err.message || 'Erro interno do servidor',
    error: process.env.NODE_ENV === 'development' ? {
      message: err.message,
      stack: err.stack
    } : undefined
  });
});

// =============================================================================
// GRACEFUL SHUTDOWN
// =============================================================================

const gracefulShutdown = (signal) => {
  console.log(`\n🛑 Received ${signal}. Starting graceful shutdown...`);
  
  pool.end(() => {
    console.log('📊 Database connections closed');
  });
  
  process.exit(0);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  console.error('🚨 Uncaught Exception:', err);
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('🚨 Unhandled Rejection at:', promise, 'reason:', reason);
  gracefulShutdown('unhandledRejection');
});

// =============================================================================
// SERVER STARTUP
// =============================================================================

const startServer = async () => {
  try {
    // Initialize database schema
    await initializeDatabase();
    
    // Test database connection
    await pool.query('SELECT NOW()');
    console.log('✅ Database connection established');
    
    // Start server
    app.listen(PORT, () => {
      console.log('\n🚀 ===== CONVÊNIO QUIRO FERREIRA SERVER =====');
      console.log(`📱 Frontend: http://localhost:5173`);
      console.log(`🔗 API: http://localhost:${PORT}/api`);
      console.log(`🏥 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`📊 Database: ${process.env.DATABASE_URL ? 'Connected' : 'Local'}`);
      console.log(`☁️ Cloudinary: ${isCloudinaryConfigured ? 'Configured' : 'Not configured'}`);
      console.log(`🔐 JWT Secret: ${process.env.JWT_SECRET ? 'Set' : 'Using default'}`);
      console.log('============================================\n');
      
      console.log('📋 Available API routes:');
      console.log('  🔐 /api/auth/* - Authentication');
      console.log('  👥 /api/users/* - User management');
      console.log('  🏥 /api/clients/* - Client operations');
      console.log('  👨‍⚕️ /api/professionals/* - Professional operations');
      console.log('  📅 /api/consultations/* - Consultation management');
      console.log('  🗓️ /api/scheduling/* - Appointment scheduling');
      console.log('  📋 /api/medical-records/* - Medical records');
      console.log('  👤 /api/private-patients/* - Private patients');
      console.log('  📍 /api/attendance-locations/* - Attendance locations');
      console.log('  📊 /api/reports/* - Reports and analytics');
      console.log('  🏗️ /api/services/* - Service management');
      console.log('  📂 /api/service-categories/* - Service categories');
      console.log('  👶 /api/dependents/* - Dependent management');
      console.log('  🖼️ /api/upload-image - Image upload');
      console.log('  ❤️ /api/health - Health check');
      console.log('');
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// Start the server
startServer();

export default app;