import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';
import createUpload from './middleware/upload.js';
import { generateDocumentPDF } from './utils/documentGenerator.js';
import { MercadoPagoConfig, Preference, Payment } from 'mercadopago';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Initialize MercadoPago
const client = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN,
  options: { timeout: 5000, idempotencyKey: 'abc' }
});

// CORS configuration for production
const corsOptions = {
  origin: [
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:5174',
    'http://localhost:4173',
    'https://cartaoquiroferreira.com.br',
    'https://www.cartaoquiroferreira.com.br'
  ],

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Database initialization and table creation
const initializeDatabase = async () => {
  try {
    console.log('🔄 Initializing database...');

    // Create tables
    await pool.query(`
      -- Users table
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) UNIQUE,
        email VARCHAR(255),
        phone VARCHAR(20),
        password_hash VARCHAR(255) NOT NULL,
        roles TEXT[] DEFAULT ARRAY['client'],
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry TIMESTAMP,
        birth_date DATE,
        address TEXT,
        address_number VARCHAR(20),
        address_complement VARCHAR(100),
        neighborhood VARCHAR(100),
        city VARCHAR(100),
        state VARCHAR(2),
        zip_code VARCHAR(8),
        photo_url TEXT,
        category_name VARCHAR(255),
        professional_percentage DECIMAL(5,2) DEFAULT 50.00,
        crm VARCHAR(50),
        has_scheduling_access BOOLEAN DEFAULT FALSE,
        access_expires_at TIMESTAMP,
        access_granted_by VARCHAR(255),
        access_granted_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Service categories table
      CREATE TABLE IF NOT EXISTS service_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Services table
      CREATE TABLE IF NOT EXISTS services (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        base_price DECIMAL(10,2) NOT NULL,
        category_id INTEGER REFERENCES service_categories(id),
        is_base_service BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Dependents table
      CREATE TABLE IF NOT EXISTS dependents (
        id SERIAL PRIMARY KEY,
        client_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) NOT NULL UNIQUE,
        birth_date DATE,
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry TIMESTAMP,
        billing_amount DECIMAL(10,2) DEFAULT 50.00,
        payment_reference VARCHAR(255),
        activated_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Private patients table
      CREATE TABLE IF NOT EXISTS private_patients (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11),
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Attendance locations table
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
        is_default BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Consultations table
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        private_patient_id INTEGER REFERENCES private_patients(id),
        professional_id INTEGER NOT NULL REFERENCES users(id),
        service_id INTEGER NOT NULL REFERENCES services(id),
        location_id INTEGER REFERENCES attendance_locations(id),
        value DECIMAL(10,2) NOT NULL,
        date TIMESTAMP NOT NULL,
        status VARCHAR(20) DEFAULT 'completed',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Medical records table
      CREATE TABLE IF NOT EXISTS medical_records (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id),
        private_patient_id INTEGER NOT NULL REFERENCES private_patients(id),
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Medical documents table
      CREATE TABLE IF NOT EXISTS medical_documents (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id),
        private_patient_id INTEGER REFERENCES private_patients(id),
        title VARCHAR(255) NOT NULL,
        document_type VARCHAR(50) NOT NULL,
        document_url TEXT NOT NULL,
        patient_name VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Client payments table
      CREATE TABLE IF NOT EXISTS client_payments (
        id SERIAL PRIMARY KEY,
        client_id INTEGER NOT NULL REFERENCES users(id),
        amount DECIMAL(10,2) NOT NULL,
        payment_status VARCHAR(20) DEFAULT 'pending',
        payment_method VARCHAR(50),
        external_reference VARCHAR(255),
        preference_id VARCHAR(255),
        payment_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Dependent payments table
      CREATE TABLE IF NOT EXISTS dependent_payments (
        id SERIAL PRIMARY KEY,
        dependent_id INTEGER NOT NULL REFERENCES dependents(id),
        amount DECIMAL(10,2) NOT NULL,
        payment_status VARCHAR(20) DEFAULT 'pending',
        payment_method VARCHAR(50),
        external_reference VARCHAR(255),
        preference_id VARCHAR(255),
        payment_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Professional payments table
      CREATE TABLE IF NOT EXISTS professional_payments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id),
        amount DECIMAL(10,2) NOT NULL,
        payment_status VARCHAR(20) DEFAULT 'pending',
        payment_method VARCHAR(50),
        external_reference VARCHAR(255),
        preference_id VARCHAR(255),
        payment_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Agenda payments table
      CREATE TABLE IF NOT EXISTS agenda_payments (
        id SERIAL PRIMARY KEY,
        client_id INTEGER NOT NULL REFERENCES users(id),
        consultation_id INTEGER REFERENCES consultations(id),
        amount DECIMAL(10,2) NOT NULL,
        payment_status VARCHAR(20) DEFAULT 'pending',
        payment_method VARCHAR(50),
        external_reference VARCHAR(255),
        preference_id VARCHAR(255),
        payment_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Audit logs table
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        action VARCHAR(100) NOT NULL,
        table_name VARCHAR(50),
        record_id INTEGER,
        old_values JSONB,
        new_values JSONB,
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Notifications table
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        title VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        type VARCHAR(50) DEFAULT 'info',
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- System settings table
      CREATE TABLE IF NOT EXISTS system_settings (
        id SERIAL PRIMARY KEY,
        key VARCHAR(100) UNIQUE NOT NULL,
        value TEXT,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create indexes for performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_users_cpf ON users(cpf);
      CREATE INDEX IF NOT EXISTS idx_users_roles ON users USING GIN(roles);
      CREATE INDEX IF NOT EXISTS idx_users_subscription_status ON users(subscription_status);
      CREATE INDEX IF NOT EXISTS idx_dependents_client_id ON dependents(client_id);
      CREATE INDEX IF NOT EXISTS idx_dependents_cpf ON dependents(cpf);
      CREATE INDEX IF NOT EXISTS idx_consultations_client_id ON consultations(client_id);
      CREATE INDEX IF NOT EXISTS idx_consultations_professional_id ON consultations(professional_id);
      CREATE INDEX IF NOT EXISTS idx_consultations_date ON consultations(date);
      CREATE INDEX IF NOT EXISTS idx_consultations_status ON consultations(status);
      CREATE INDEX IF NOT EXISTS idx_medical_records_professional_id ON medical_records(professional_id);
      CREATE INDEX IF NOT EXISTS idx_medical_records_patient_id ON medical_records(private_patient_id);
      CREATE INDEX IF NOT EXISTS idx_client_payments_client_id ON client_payments(client_id);
      CREATE INDEX IF NOT EXISTS idx_client_payments_status ON client_payments(payment_status);
      CREATE INDEX IF NOT EXISTS idx_dependent_payments_dependent_id ON dependent_payments(dependent_id);
      CREATE INDEX IF NOT EXISTS idx_dependent_payments_status ON dependent_payments(payment_status);
      CREATE INDEX IF NOT EXISTS idx_professional_payments_professional_id ON professional_payments(professional_id);
      CREATE INDEX IF NOT EXISTS idx_professional_payments_status ON professional_payments(payment_status);
      CREATE INDEX IF NOT EXISTS idx_agenda_payments_client_id ON agenda_payments(client_id);
      CREATE INDEX IF NOT EXISTS idx_agenda_payments_status ON agenda_payments(payment_status);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
      CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
      CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read);
    `);

    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Failed to create database tables:', error);
    throw error;
  }
};

// Utility function for safe JSON serialization
const safeJsonResponse = (res, data, statusCode = 200) => {
  try {
    const serializedData = JSON.parse(JSON.stringify(data));
    res.status(statusCode);
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(serializedData));
  } catch (error) {
    console.error('JSON serialization error:', error);
    res.status(500);
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify({ message: 'Internal server error' }));
  }
};

// Utility function to log audit actions
const logAuditAction = async (userId, action, tableName, recordId, oldValues, newValues, req) => {
  try {
    await pool.query(
      `INSERT INTO audit_logs (user_id, action, table_name, record_id, old_values, new_values, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        userId,
        action,
        tableName,
        recordId,
        oldValues ? JSON.stringify(oldValues) : null,
        newValues ? JSON.stringify(newValues) : null,
        req.ip,
        req.get('User-Agent')
      ]
    );
  } catch (error) {
    console.error('Error logging audit action:', error);
  }
};

// Health check endpoint
app.get('/health', (req, res) => {
  safeJsonResponse(res, { 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Version endpoint
app.get('/version', (req, res) => {
  safeJsonResponse(res, { 
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

// ==================== AUTH ROUTES ====================

// Login route
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return safeJsonResponse(res, { message: 'CPF e senha são obrigatórios' }, 400);
    }

    const cleanCpf = cpf.replace(/\D/g, '');
    if (!/^\d{11}$/.test(cleanCpf)) {
      return safeJsonResponse(res, { message: 'CPF deve conter 11 dígitos numéricos' }, 400);
    }

    const result = await pool.query(
      'SELECT id, name, cpf, email, phone, password_hash, roles, subscription_status, subscription_expiry FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Credenciais inválidas' }, 401);
    }

    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password_hash);

    if (!isValidPassword) {
      return safeJsonResponse(res, { message: 'Credenciais inválidas' }, 401);
    }

    await logAuditAction(user.id, 'LOGIN', 'users', user.id, null, null, req);

    const userData = {
      id: Number(user.id),
      name: String(user.name),
      cpf: String(user.cpf || ''),
      email: String(user.email || ''),
      phone: String(user.phone || ''),
      roles: Array.isArray(user.roles) ? user.roles : [],
      subscription_status: String(user.subscription_status || 'pending'),
      subscription_expiry: user.subscription_expiry
    };

    safeJsonResponse(res, { user: userData });
  } catch (error) {
    console.error('Login error:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Select role route
app.post('/api/auth/select-role', async (req, res) => {
  try {
    const { userId, role } = req.body;

    if (!userId || !role) {
      return safeJsonResponse(res, { message: 'ID do usuário e role são obrigatórios' }, 400);
    }

    const result = await pool.query(
      'SELECT id, name, cpf, email, phone, roles, subscription_status, subscription_expiry FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Usuário não encontrado' }, 404);
    }

    const user = result.rows[0];

    if (!user.roles.includes(role)) {
      return safeJsonResponse(res, { message: 'Role não autorizada para este usuário' }, 403);
    }

    const token = jwt.sign(
      { id: user.id, currentRole: role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    });

    await logAuditAction(user.id, 'ROLE_SELECTED', 'users', user.id, null, { role }, req);

    const userData = {
      id: Number(user.id),
      name: String(user.name),
      cpf: String(user.cpf || ''),
      email: String(user.email || ''),
      phone: String(user.phone || ''),
      roles: Array.isArray(user.roles) ? user.roles : [],
      currentRole: String(role),
      subscription_status: String(user.subscription_status || 'pending'),
      subscription_expiry: user.subscription_expiry
    };

    safeJsonResponse(res, { token, user: userData });
  } catch (error) {
    console.error('Role selection error:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Switch role route
app.post('/api/auth/switch-role', authenticate, async (req, res) => {
  try {
    const { role } = req.body;

    if (!role) {
      return safeJsonResponse(res, { message: 'Role é obrigatória' }, 400);
    }

    if (!req.user.roles.includes(role)) {
      return safeJsonResponse(res, { message: 'Role não autorizada para este usuário' }, 403);
    }

    const token = jwt.sign(
      { id: req.user.id, currentRole: role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    });

    await logAuditAction(req.user.id, 'ROLE_SWITCHED', 'users', req.user.id, { oldRole: req.user.currentRole }, { newRole: role }, req);

    const userData = {
      ...req.user,
      currentRole: String(role)
    };

    safeJsonResponse(res, { token, user: userData });
  } catch (error) {
    console.error('Role switch error:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Register route
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
      password
    } = req.body;

    if (!name || !password) {
      return safeJsonResponse(res, { message: 'Nome e senha são obrigatórios' }, 400);
    }

    if (password.length < 6) {
      return safeJsonResponse(res, { message: 'Senha deve ter pelo menos 6 caracteres' }, 400);
    }

    let cleanCpf = null;
    if (cpf) {
      cleanCpf = cpf.replace(/\D/g, '');
      if (!/^\d{11}$/.test(cleanCpf)) {
        return safeJsonResponse(res, { message: 'CPF deve conter 11 dígitos numéricos' }, 400);
      }

      const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cleanCpf]);
      if (existingUser.rows.length > 0) {
        return safeJsonResponse(res, { message: 'CPF já cadastrado' }, 409);
      }
    }

    if (email) {
      const existingEmail = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
      if (existingEmail.rows.length > 0) {
        return safeJsonResponse(res, { message: 'Email já cadastrado' }, 409);
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password_hash, roles
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) 
      RETURNING id, name, cpf, email, phone, roles, subscription_status`,
      [
        name.trim(),
        cleanCpf,
        email?.trim() || null,
        phone?.replace(/\D/g, '') || null,
        birth_date || null,
        address?.trim() || null,
        address_number?.trim() || null,
        address_complement?.trim() || null,
        neighborhood?.trim() || null,
        city?.trim() || null,
        state || null,
        hashedPassword,
        ['client']
      ]
    );

    const newUser = result.rows[0];

    await logAuditAction(newUser.id, 'USER_CREATED', 'users', newUser.id, null, { name, cpf: cleanCpf }, req);

    const userData = {
      id: Number(newUser.id),
      name: String(newUser.name),
      cpf: String(newUser.cpf || ''),
      email: String(newUser.email || ''),
      phone: String(newUser.phone || ''),
      roles: Array.isArray(newUser.roles) ? newUser.roles : ['client'],
      subscription_status: String(newUser.subscription_status || 'pending')
    };

    safeJsonResponse(res, { 
      message: 'Usuário criado com sucesso',
      user: userData
    }, 201);
  } catch (error) {
    console.error('Registration error:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Logout route
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  safeJsonResponse(res, { message: 'Logout realizado com sucesso' });
});

// ==================== USER ROUTES ====================

// Get all users (admin only)
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, cpf, email, phone, roles, subscription_status, 
             subscription_expiry, created_at, updated_at
      FROM users 
      ORDER BY created_at DESC
    `);

    const users = result.rows.map(user => ({
      id: Number(user.id),
      name: String(user.name),
      cpf: String(user.cpf || ''),
      email: String(user.email || ''),
      phone: String(user.phone || ''),
      roles: Array.isArray(user.roles) ? user.roles : [],
      subscription_status: String(user.subscription_status || 'pending'),
      subscription_expiry: user.subscription_expiry,
      created_at: String(user.created_at),
      updated_at: String(user.updated_at)
    }));

    safeJsonResponse(res, users);
  } catch (error) {
    console.error('Error fetching users:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Get user by ID
app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    if (req.user.currentRole !== 'admin' && req.user.id !== userId) {
      return safeJsonResponse(res, { message: 'Acesso não autorizado' }, 403);
    }

    const result = await pool.query(`
      SELECT id, name, cpf, email, phone, roles, subscription_status, 
             subscription_expiry, birth_date, address, address_number, 
             address_complement, neighborhood, city, state, zip_code,
             photo_url, category_name, professional_percentage, crm,
             has_scheduling_access, access_expires_at, created_at
      FROM users 
      WHERE id = $1
    `, [userId]);

    if (result.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Usuário não encontrado' }, 404);
    }

    const user = result.rows[0];
    const userData = {
      id: Number(user.id),
      name: String(user.name),
      cpf: String(user.cpf || ''),
      email: String(user.email || ''),
      phone: String(user.phone || ''),
      roles: Array.isArray(user.roles) ? user.roles : [],
      subscription_status: String(user.subscription_status || 'pending'),
      subscription_expiry: user.subscription_expiry,
      birth_date: user.birth_date,
      address: String(user.address || ''),
      address_number: String(user.address_number || ''),
      address_complement: String(user.address_complement || ''),
      neighborhood: String(user.neighborhood || ''),
      city: String(user.city || ''),
      state: String(user.state || ''),
      zip_code: String(user.zip_code || ''),
      photo_url: user.photo_url,
      category_name: String(user.category_name || ''),
      professional_percentage: Number(user.professional_percentage || 50),
      crm: String(user.crm || ''),
      has_scheduling_access: Boolean(user.has_scheduling_access),
      access_expires_at: user.access_expires_at,
      created_at: String(user.created_at)
    };

    safeJsonResponse(res, userData);
  } catch (error) {
    console.error('Error fetching user:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Get user subscription status
app.get('/api/users/:id/subscription-status', authenticate, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    if (req.user.currentRole !== 'admin' && req.user.id !== userId) {
      return safeJsonResponse(res, { message: 'Acesso não autorizado' }, 403);
    }

    const result = await pool.query(
      'SELECT subscription_status, subscription_expiry FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Usuário não encontrado' }, 404);
    }

    const user = result.rows[0];
    safeJsonResponse(res, {
      subscription_status: String(user.subscription_status || 'pending'),
      subscription_expiry: user.subscription_expiry
    });
  } catch (error) {
    console.error('Error fetching subscription status:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Create user (admin only)
app.post('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, cpf, email, phone, password, roles } = req.body;

    if (!name || !password || !roles || !Array.isArray(roles)) {
      return safeJsonResponse(res, { message: 'Nome, senha e roles são obrigatórios' }, 400);
    }

    if (password.length < 6) {
      return safeJsonResponse(res, { message: 'Senha deve ter pelo menos 6 caracteres' }, 400);
    }

    let cleanCpf = null;
    if (cpf) {
      cleanCpf = cpf.replace(/\D/g, '');
      if (!/^\d{11}$/.test(cleanCpf)) {
        return safeJsonResponse(res, { message: 'CPF deve conter 11 dígitos numéricos' }, 400);
      }

      const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cleanCpf]);
      if (existingUser.rows.length > 0) {
        return safeJsonResponse(res, { message: 'CPF já cadastrado' }, 409);
      }
    }

    if (email) {
      const existingEmail = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
      if (existingEmail.rows.length > 0) {
        return safeJsonResponse(res, { message: 'Email já cadastrado' }, 409);
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (name, cpf, email, phone, password_hash, roles) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, name, cpf, email, phone, roles, subscription_status, created_at`,
      [
        name.trim(),
        cleanCpf,
        email?.trim() || null,
        phone?.replace(/\D/g, '') || null,
        hashedPassword,
        roles
      ]
    );

    const newUser = result.rows[0];

    await logAuditAction(req.user.id, 'USER_CREATED', 'users', newUser.id, null, { name, cpf: cleanCpf, roles }, req);

    const userData = {
      id: Number(newUser.id),
      name: String(newUser.name),
      cpf: String(newUser.cpf || ''),
      email: String(newUser.email || ''),
      phone: String(newUser.phone || ''),
      roles: Array.isArray(newUser.roles) ? newUser.roles : [],
      subscription_status: String(newUser.subscription_status || 'pending'),
      created_at: String(newUser.created_at)
    };

    safeJsonResponse(res, userData, 201);
  } catch (error) {
    console.error('Error creating user:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Update user
app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { name, email, phone, roles, currentPassword, newPassword } = req.body;

    if (req.user.currentRole !== 'admin' && req.user.id !== userId) {
      return safeJsonResponse(res, { message: 'Acesso não autorizado' }, 403);
    }

    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Usuário não encontrado' }, 404);
    }

    const existingUser = userResult.rows[0];
    let updateFields = [];
    let updateValues = [];
    let paramCount = 1;

    if (name !== undefined) {
      updateFields.push(`name = $${paramCount}`);
      updateValues.push(name.trim());
      paramCount++;
    }

    if (email !== undefined) {
      if (email && email !== existingUser.email) {
        const emailCheck = await pool.query('SELECT id FROM users WHERE email = $1 AND id != $2', [email, userId]);
        if (emailCheck.rows.length > 0) {
          return safeJsonResponse(res, { message: 'Email já está em uso' }, 409);
        }
      }
      updateFields.push(`email = $${paramCount}`);
      updateValues.push(email?.trim() || null);
      paramCount++;
    }

    if (phone !== undefined) {
      updateFields.push(`phone = $${paramCount}`);
      updateValues.push(phone?.replace(/\D/g, '') || null);
      paramCount++;
    }

    if (roles !== undefined && req.user.currentRole === 'admin') {
      updateFields.push(`roles = $${paramCount}`);
      updateValues.push(roles);
      paramCount++;
    }

    if (newPassword) {
      if (!currentPassword && req.user.id === userId) {
        return safeJsonResponse(res, { message: 'Senha atual é obrigatória' }, 400);
      }

      if (req.user.id === userId) {
        const isValidPassword = await bcrypt.compare(currentPassword, existingUser.password_hash);
        if (!isValidPassword) {
          return safeJsonResponse(res, { message: 'Senha atual incorreta' }, 400);
        }
      }

      if (newPassword.length < 6) {
        return safeJsonResponse(res, { message: 'Nova senha deve ter pelo menos 6 caracteres' }, 400);
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      updateFields.push(`password_hash = $${paramCount}`);
      updateValues.push(hashedPassword);
      paramCount++;
    }

    if (updateFields.length === 0) {
      return safeJsonResponse(res, { message: 'Nenhum campo para atualizar' }, 400);
    }

    updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
    updateValues.push(userId);

    const query = `
      UPDATE users 
      SET ${updateFields.join(', ')} 
      WHERE id = $${paramCount} 
      RETURNING id, name, cpf, email, phone, roles, subscription_status, updated_at
    `;

    const result = await pool.query(query, updateValues);
    const updatedUser = result.rows[0];

    await logAuditAction(req.user.id, 'USER_UPDATED', 'users', userId, existingUser, req.body, req);

    const userData = {
      id: Number(updatedUser.id),
      name: String(updatedUser.name),
      cpf: String(updatedUser.cpf || ''),
      email: String(updatedUser.email || ''),
      phone: String(updatedUser.phone || ''),
      roles: Array.isArray(updatedUser.roles) ? updatedUser.roles : [],
      subscription_status: String(updatedUser.subscription_status || 'pending'),
      updated_at: String(updatedUser.updated_at)
    };

    safeJsonResponse(res, userData);
  } catch (error) {
    console.error('Error updating user:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Delete user (admin only)
app.delete('/api/users/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    if (req.user.id === userId) {
      return safeJsonResponse(res, { message: 'Não é possível excluir sua própria conta' }, 400);
    }

    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Usuário não encontrado' }, 404);
    }

    await pool.query('DELETE FROM users WHERE id = $1', [userId]);

    await logAuditAction(req.user.id, 'USER_DELETED', 'users', userId, userResult.rows[0], null, req);

    safeJsonResponse(res, { message: 'Usuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting user:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// ==================== SERVICE CATEGORIES ROUTES ====================

// Get all service categories
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, description, created_at 
      FROM service_categories 
      ORDER BY name
    `);

    const categories = result.rows.map(category => ({
      id: Number(category.id),
      name: String(category.name),
      description: String(category.description || ''),
      created_at: String(category.created_at)
    }));

    safeJsonResponse(res, categories);
  } catch (error) {
    console.error('Error fetching service categories:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Create service category (admin only)
app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return safeJsonResponse(res, { message: 'Nome é obrigatório' }, 400);
    }

    const existingCategory = await pool.query('SELECT id FROM service_categories WHERE name = $1', [name]);
    if (existingCategory.rows.length > 0) {
      return safeJsonResponse(res, { message: 'Categoria já existe' }, 409);
    }

    const result = await pool.query(
      'INSERT INTO service_categories (name, description) VALUES ($1, $2) RETURNING *',
      [name.trim(), description?.trim() || null]
    );

    const newCategory = result.rows[0];

    await logAuditAction(req.user.id, 'CATEGORY_CREATED', 'service_categories', newCategory.id, null, { name, description }, req);

    const categoryData = {
      id: Number(newCategory.id),
      name: String(newCategory.name),
      description: String(newCategory.description || ''),
      created_at: String(newCategory.created_at)
    };

    safeJsonResponse(res, categoryData, 201);
  } catch (error) {
    console.error('Error creating service category:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// ==================== SERVICES ROUTES ====================

// Get all services
app.get('/api/services', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.id, s.name, s.description, s.base_price, s.category_id, 
             s.is_base_service, sc.name as category_name
      FROM services s
      LEFT JOIN service_categories sc ON s.category_id = sc.id
      ORDER BY sc.name, s.name
    `);

    const services = result.rows.map(service => ({
      id: Number(service.id),
      name: String(service.name),
      description: String(service.description || ''),
      base_price: Number(service.base_price),
      category_id: service.category_id ? Number(service.category_id) : null,
      category_name: String(service.category_name || ''),
      is_base_service: Boolean(service.is_base_service)
    }));

    safeJsonResponse(res, services);
  } catch (error) {
    console.error('Error fetching services:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Create service (admin only)
app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !base_price) {
      return safeJsonResponse(res, { message: 'Nome e preço base são obrigatórios' }, 400);
    }

    if (isNaN(base_price) || base_price <= 0) {
      return safeJsonResponse(res, { message: 'Preço base deve ser um número positivo' }, 400);
    }

    const result = await pool.query(
      `INSERT INTO services (name, description, base_price, category_id, is_base_service) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [
        name.trim(),
        description?.trim() || null,
        Number(base_price),
        category_id || null,
        Boolean(is_base_service)
      ]
    );

    const newService = result.rows[0];

    await logAuditAction(req.user.id, 'SERVICE_CREATED', 'services', newService.id, null, req.body, req);

    const serviceData = {
      id: Number(newService.id),
      name: String(newService.name),
      description: String(newService.description || ''),
      base_price: Number(newService.base_price),
      category_id: newService.category_id ? Number(newService.category_id) : null,
      is_base_service: Boolean(newService.is_base_service)
    };

    safeJsonResponse(res, serviceData, 201);
  } catch (error) {
    console.error('Error creating service:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Update service (admin only)
app.put('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const serviceId = parseInt(req.params.id);
    const { name, description, base_price, category_id, is_base_service } = req.body;

    const existingService = await pool.query('SELECT * FROM services WHERE id = $1', [serviceId]);
    if (existingService.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Serviço não encontrado' }, 404);
    }

    const result = await pool.query(
      `UPDATE services 
       SET name = $1, description = $2, base_price = $3, category_id = $4, is_base_service = $5, updated_at = CURRENT_TIMESTAMP
       WHERE id = $6 
       RETURNING *`,
      [
        name?.trim() || existingService.rows[0].name,
        description?.trim() || existingService.rows[0].description,
        base_price ? Number(base_price) : existingService.rows[0].base_price,
        category_id || existingService.rows[0].category_id,
        is_base_service !== undefined ? Boolean(is_base_service) : existingService.rows[0].is_base_service,
        serviceId
      ]
    );

    const updatedService = result.rows[0];

    await logAuditAction(req.user.id, 'SERVICE_UPDATED', 'services', serviceId, existingService.rows[0], req.body, req);

    const serviceData = {
      id: Number(updatedService.id),
      name: String(updatedService.name),
      description: String(updatedService.description || ''),
      base_price: Number(updatedService.base_price),
      category_id: updatedService.category_id ? Number(updatedService.category_id) : null,
      is_base_service: Boolean(updatedService.is_base_service)
    };

    safeJsonResponse(res, serviceData);
  } catch (error) {
    console.error('Error updating service:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Delete service (admin only)
app.delete('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const serviceId = parseInt(req.params.id);

    const existingService = await pool.query('SELECT * FROM services WHERE id = $1', [serviceId]);
    if (existingService.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Serviço não encontrado' }, 404);
    }

    await pool.query('DELETE FROM services WHERE id = $1', [serviceId]);

    await logAuditAction(req.user.id, 'SERVICE_DELETED', 'services', serviceId, existingService.rows[0], null, req);

    safeJsonResponse(res, { message: 'Serviço excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting service:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// ==================== PROFESSIONALS ROUTES ====================

// Get all professionals
app.get('/api/professionals', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, email, phone, address, address_number, address_complement,
             neighborhood, city, state, category_name, photo_url, professional_percentage,
             has_scheduling_access, access_expires_at
      FROM users 
      WHERE 'professional' = ANY(roles)
      ORDER BY name
    `);

    const professionals = result.rows.map(prof => ({
      id: Number(prof.id),
      name: String(prof.name),
      email: String(prof.email || ''),
      phone: String(prof.phone || ''),
      address: String(prof.address || ''),
      address_number: String(prof.address_number || ''),
      address_complement: String(prof.address_complement || ''),
      neighborhood: String(prof.neighborhood || ''),
      city: String(prof.city || ''),
      state: String(prof.state || ''),
      category_name: String(prof.category_name || ''),
      photo_url: prof.photo_url,
      professional_percentage: Number(prof.professional_percentage || 50),
      has_scheduling_access: Boolean(prof.has_scheduling_access),
      access_expires_at: prof.access_expires_at
    }));

    safeJsonResponse(res, professionals);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Get professionals with scheduling access (admin only)
app.get('/api/admin/professionals-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, email, phone, category_name, has_scheduling_access,
             access_expires_at, access_granted_by, access_granted_at
      FROM users 
      WHERE 'professional' = ANY(roles)
      ORDER BY name
    `);

    const professionals = result.rows.map(prof => ({
      id: Number(prof.id),
      name: String(prof.name),
      email: String(prof.email || ''),
      phone: String(prof.phone || ''),
      category_name: String(prof.category_name || ''),
      has_scheduling_access: Boolean(prof.has_scheduling_access),
      access_expires_at: prof.access_expires_at,
      access_granted_by: String(prof.access_granted_by || ''),
      access_granted_at: prof.access_granted_at
    }));

    safeJsonResponse(res, professionals);
  } catch (error) {
    console.error('Error fetching professionals scheduling access:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Grant scheduling access (admin only)
app.post('/api/admin/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;

    if (!professional_id || !expires_at) {
      return safeJsonResponse(res, { message: 'ID do profissional e data de expiração são obrigatórios' }, 400);
    }

    const professionalResult = await pool.query(
      'SELECT name FROM users WHERE id = $1 AND $2 = ANY(roles)',
      [professional_id, 'professional']
    );

    if (professionalResult.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Profissional não encontrado' }, 404);
    }

    await pool.query(
      `UPDATE users 
       SET has_scheduling_access = TRUE, access_expires_at = $1, 
           access_granted_by = $2, access_granted_at = CURRENT_TIMESTAMP,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $3`,
      [expires_at, req.user.name, professional_id]
    );

    await logAuditAction(req.user.id, 'SCHEDULING_ACCESS_GRANTED', 'users', professional_id, null, { expires_at, reason }, req);

    safeJsonResponse(res, { message: 'Acesso à agenda concedido com sucesso' });
  } catch (error) {
    console.error('Error granting scheduling access:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Revoke scheduling access (admin only)
app.post('/api/admin/revoke-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id } = req.body;

    if (!professional_id) {
      return safeJsonResponse(res, { message: 'ID do profissional é obrigatório' }, 400);
    }

    const professionalResult = await pool.query(
      'SELECT name FROM users WHERE id = $1 AND $2 = ANY(roles)',
      [professional_id, 'professional']
    );

    if (professionalResult.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Profissional não encontrado' }, 404);
    }

    await pool.query(
      `UPDATE users 
       SET has_scheduling_access = FALSE, access_expires_at = NULL, 
           access_granted_by = NULL, access_granted_at = NULL,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $1`,
      [professional_id]
    );

    await logAuditAction(req.user.id, 'SCHEDULING_ACCESS_REVOKED', 'users', professional_id, null, null, req);

    safeJsonResponse(res, { message: 'Acesso à agenda revogado com sucesso' });
  } catch (error) {
    console.error('Error revoking scheduling access:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// ==================== CLIENTS ROUTES ====================

// Lookup client by CPF
app.get('/api/clients/lookup', authenticate, async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return safeJsonResponse(res, { message: 'CPF é obrigatório' }, 400);
    }

    const cleanCpf = cpf.replace(/\D/g, '');
    if (!/^\d{11}$/.test(cleanCpf)) {
      return safeJsonResponse(res, { message: 'CPF deve conter 11 dígitos numéricos' }, 400);
    }

    const result = await pool.query(`
      SELECT id, name, cpf, subscription_status, subscription_expiry
      FROM users 
      WHERE cpf = $1 AND 'client' = ANY(roles)
    `, [cleanCpf]);

    if (result.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Cliente não encontrado' }, 404);
    }

    const client = result.rows[0];
    const clientData = {
      id: Number(client.id),
      name: String(client.name),
      cpf: String(client.cpf),
      subscription_status: String(client.subscription_status || 'pending'),
      subscription_expiry: client.subscription_expiry
    };

    safeJsonResponse(res, clientData);
  } catch (error) {
    console.error('Error looking up client:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// ==================== DEPENDENTS ROUTES ====================

// Get dependents by client ID
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const clientId = parseInt(req.params.clientId);

    if (req.user.currentRole !== 'admin' && req.user.id !== clientId) {
      return safeJsonResponse(res, { message: 'Acesso não autorizado' }, 403);
    }

    const result = await pool.query(`
      SELECT d.*, u.name as client_name, u.subscription_status as client_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      WHERE d.client_id = $1
      ORDER BY d.name
    `, [clientId]);

    const dependents = result.rows.map(dependent => {
      const currentStatus = dependent.subscription_status || 'pending';
      
      return {
        id: Number(dependent.id),
        client_id: Number(dependent.client_id),
        name: String(dependent.name),
        cpf: String(dependent.cpf),
        birth_date: dependent.birth_date,
        subscription_status: String(dependent.subscription_status || 'pending'),
        subscription_expiry: dependent.subscription_expiry,
        billing_amount: Number(dependent.billing_amount || 50),
        payment_reference: String(dependent.payment_reference || ''),
        activated_at: dependent.activated_at,
        client_name: String(dependent.client_name),
        client_status: String(dependent.client_status || 'pending'),
        current_status: String(currentStatus),
        created_at: String(dependent.created_at),
        updated_at: String(dependent.updated_at)
      };
    });

    safeJsonResponse(res, dependents);
  } catch (error) {
    console.error('Error fetching dependents:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Get all dependents (admin only)
app.get('/api/admin/dependents', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT d.*, u.name as client_name, u.subscription_status as client_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      ORDER BY d.created_at DESC
    `);

    const dependents = result.rows.map(dependent => {
      const currentStatus = dependent.subscription_status || 'pending';
      
      return {
        id: Number(dependent.id),
        client_id: Number(dependent.client_id),
        name: String(dependent.name),
        cpf: String(dependent.cpf),
        birth_date: dependent.birth_date,
        subscription_status: String(dependent.subscription_status || 'pending'),
        subscription_expiry: dependent.subscription_expiry,
        billing_amount: Number(dependent.billing_amount || 50),
        payment_reference: String(dependent.payment_reference || ''),
        activated_at: dependent.activated_at,
        client_name: String(dependent.client_name),
        client_status: String(dependent.client_status || 'pending'),
        current_status: String(currentStatus),
        created_at: String(dependent.created_at),
        updated_at: String(dependent.updated_at)
      };
    });

    safeJsonResponse(res, dependents);
  } catch (error) {
    console.error('Error fetching all dependents:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Lookup dependent by CPF
app.get('/api/dependents/lookup', authenticate, async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return safeJsonResponse(res, { message: 'CPF é obrigatório' }, 400);
    }

    const cleanCpf = cpf.replace(/\D/g, '');
    if (!/^\d{11}$/.test(cleanCpf)) {
      return safeJsonResponse(res, { message: 'CPF deve conter 11 dígitos numéricos' }, 400);
    }

    const result = await pool.query(`
      SELECT d.*, u.name as client_name, u.subscription_status as client_subscription_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      WHERE d.cpf = $1
    `, [cleanCpf]);

    if (result.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Dependente não encontrado' }, 404);
    }

    const dependent = result.rows[0];
    const dependentData = {
      id: Number(dependent.id),
      client_id: Number(dependent.client_id),
      name: String(dependent.name),
      cpf: String(dependent.cpf),
      birth_date: dependent.birth_date,
      client_name: String(dependent.client_name),
      client_subscription_status: String(dependent.client_subscription_status || 'pending'),
      dependent_subscription_status: String(dependent.subscription_status || 'pending'),
      subscription_expiry: dependent.subscription_expiry
    };

    safeJsonResponse(res, dependentData);
  } catch (error) {
    console.error('Error looking up dependent:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Create dependent
app.post('/api/dependents', authenticate, async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    if (!client_id || !name || !cpf) {
      return safeJsonResponse(res, { message: 'ID do cliente, nome e CPF são obrigatórios' }, 400);
    }

    if (req.user.currentRole !== 'admin' && req.user.id !== client_id) {
      return safeJsonResponse(res, { message: 'Acesso não autorizado' }, 403);
    }

    const cleanCpf = cpf.replace(/\D/g, '');
    if (!/^\d{11}$/.test(cleanCpf)) {
      return safeJsonResponse(res, { message: 'CPF deve conter 11 dígitos numéricos' }, 400);
    }

    const existingDependent = await pool.query('SELECT id FROM dependents WHERE cpf = $1', [cleanCpf]);
    if (existingDependent.rows.length > 0) {
      return safeJsonResponse(res, { message: 'CPF já cadastrado como dependente' }, 409);
    }

    const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cleanCpf]);
    if (existingUser.rows.length > 0) {
      return safeJsonResponse(res, { message: 'CPF já cadastrado como usuário' }, 409);
    }

    const dependentCount = await pool.query('SELECT COUNT(*) FROM dependents WHERE client_id = $1', [client_id]);
    if (parseInt(dependentCount.rows[0].count) >= 10) {
      return safeJsonResponse(res, { message: 'Limite máximo de 10 dependentes atingido' }, 400);
    }

    const result = await pool.query(
      `INSERT INTO dependents (client_id, name, cpf, birth_date) 
       VALUES ($1, $2, $3, $4) 
       RETURNING *`,
      [client_id, name.trim(), cleanCpf, birth_date || null]
    );

    const newDependent = result.rows[0];

    await logAuditAction(req.user.id, 'DEPENDENT_CREATED', 'dependents', newDependent.id, null, req.body, req);

    const dependentData = {
      id: Number(newDependent.id),
      client_id: Number(newDependent.client_id),
      name: String(newDependent.name),
      cpf: String(newDependent.cpf),
      birth_date: newDependent.birth_date,
      subscription_status: String(newDependent.subscription_status || 'pending'),
      billing_amount: Number(newDependent.billing_amount || 50),
      created_at: String(newDependent.created_at)
    };

    safeJsonResponse(res, dependentData, 201);
  } catch (error) {
    console.error('Error creating dependent:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Update dependent
app.put('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const dependentId = parseInt(req.params.id);
    const { name, birth_date } = req.body;

    const existingDependent = await pool.query('SELECT * FROM dependents WHERE id = $1', [dependentId]);
    if (existingDependent.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Dependente não encontrado' }, 404);
    }

    if (req.user.currentRole !== 'admin' && req.user.id !== existingDependent.rows[0].client_id) {
      return safeJsonResponse(res, { message: 'Acesso não autorizado' }, 403);
    }

    const result = await pool.query(
      `UPDATE dependents 
       SET name = $1, birth_date = $2, updated_at = CURRENT_TIMESTAMP
       WHERE id = $3 
       RETURNING *`,
      [
        name?.trim() || existingDependent.rows[0].name,
        birth_date || existingDependent.rows[0].birth_date,
        dependentId
      ]
    );

    const updatedDependent = result.rows[0];

    await logAuditAction(req.user.id, 'DEPENDENT_UPDATED', 'dependents', dependentId, existingDependent.rows[0], req.body, req);

    const dependentData = {
      id: Number(updatedDependent.id),
      client_id: Number(updatedDependent.client_id),
      name: String(updatedDependent.name),
      cpf: String(updatedDependent.cpf),
      birth_date: updatedDependent.birth_date,
      subscription_status: String(updatedDependent.subscription_status || 'pending'),
      billing_amount: Number(updatedDependent.billing_amount || 50),
      updated_at: String(updatedDependent.updated_at)
    };

    safeJsonResponse(res, dependentData);
  } catch (error) {
    console.error('Error updating dependent:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Delete dependent
app.delete('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const dependentId = parseInt(req.params.id);

    const existingDependent = await pool.query('SELECT * FROM dependents WHERE id = $1', [dependentId]);
    if (existingDependent.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Dependente não encontrado' }, 404);
    }

    if (req.user.currentRole !== 'admin' && req.user.id !== existingDependent.rows[0].client_id) {
      return safeJsonResponse(res, { message: 'Acesso não autorizado' }, 403);
    }

    await pool.query('DELETE FROM dependents WHERE id = $1', [dependentId]);

    await logAuditAction(req.user.id, 'DEPENDENT_DELETED', 'dependents', dependentId, existingDependent.rows[0], null, req);

    safeJsonResponse(res, { message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting dependent:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Activate dependent (admin only)
app.post('/api/admin/dependents/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const dependentId = parseInt(req.params.id);

    const dependentResult = await pool.query('SELECT * FROM dependents WHERE id = $1', [dependentId]);
    if (dependentResult.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Dependente não encontrado' }, 404);
    }

    const dependent = dependentResult.rows[0];

    if (dependent.subscription_status === 'active') {
      return safeJsonResponse(res, { message: 'Dependente já está ativo' }, 400);
    }

    const expiryDate = new Date();
    expiryDate.setFullYear(expiryDate.getFullYear() + 1);

    await pool.query(
      `UPDATE dependents 
       SET subscription_status = 'active', subscription_expiry = $1, 
           activated_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2`,
      [expiryDate, dependentId]
    );

    await logAuditAction(req.user.id, 'DEPENDENT_ACTIVATED', 'dependents', dependentId, dependent, { subscription_status: 'active' }, req);

    safeJsonResponse(res, { message: 'Dependente ativado com sucesso' });
  } catch (error) {
    console.error('Error activating dependent:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// ==================== PRIVATE PATIENTS ROUTES ====================

// Get private patients for professional
app.get('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM private_patients 
      WHERE professional_id = $1 
      ORDER BY name
    `, [req.user.id]);

    const patients = result.rows.map(patient => ({
      id: Number(patient.id),
      professional_id: Number(patient.professional_id),
      name: String(patient.name),
      cpf: String(patient.cpf || ''),
      email: String(patient.email || ''),
      phone: String(patient.phone || ''),
      birth_date: patient.birth_date,
      address: String(patient.address || ''),
      address_number: String(patient.address_number || ''),
      address_complement: String(patient.address_complement || ''),
      neighborhood: String(patient.neighborhood || ''),
      city: String(patient.city || ''),
      state: String(patient.state || ''),
      zip_code: String(patient.zip_code || ''),
      created_at: String(patient.created_at),
      updated_at: String(patient.updated_at)
    }));

    safeJsonResponse(res, patients);
  } catch (error) {
    console.error('Error fetching private patients:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Create private patient
app.post('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    if (!name) {
      return safeJsonResponse(res, { message: 'Nome é obrigatório' }, 400);
    }

    let cleanCpf = null;
    if (cpf) {
      cleanCpf = cpf.replace(/\D/g, '');
      if (!/^\d{11}$/.test(cleanCpf)) {
        return safeJsonResponse(res, { message: 'CPF deve conter 11 dígitos numéricos' }, 400);
      }

      const existingPatient = await pool.query(
        'SELECT id FROM private_patients WHERE cpf = $1 AND professional_id = $2',
        [cleanCpf, req.user.id]
      );
      if (existingPatient.rows.length > 0) {
        return safeJsonResponse(res, { message: 'CPF já cadastrado' }, 409);
      }
    }

    const result = await pool.query(
      `INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date, address,
        address_number, address_complement, neighborhood, city, state, zip_code
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) 
      RETURNING *`,
      [
        req.user.id,
        name.trim(),
        cleanCpf,
        email?.trim() || null,
        phone?.replace(/\D/g, '') || null,
        birth_date || null,
        address?.trim() || null,
        address_number?.trim() || null,
        address_complement?.trim() || null,
        neighborhood?.trim() || null,
        city?.trim() || null,
        state || null,
        zip_code?.replace(/\D/g, '') || null
      ]
    );

    const newPatient = result.rows[0];

    await logAuditAction(req.user.id, 'PRIVATE_PATIENT_CREATED', 'private_patients', newPatient.id, null, req.body, req);

    const patientData = {
      id: Number(newPatient.id),
      professional_id: Number(newPatient.professional_id),
      name: String(newPatient.name),
      cpf: String(newPatient.cpf || ''),
      email: String(newPatient.email || ''),
      phone: String(newPatient.phone || ''),
      birth_date: newPatient.birth_date,
      address: String(newPatient.address || ''),
      address_number: String(newPatient.address_number || ''),
      address_complement: String(newPatient.address_complement || ''),
      neighborhood: String(newPatient.neighborhood || ''),
      city: String(newPatient.city || ''),
      state: String(newPatient.state || ''),
      zip_code: String(newPatient.zip_code || ''),
      created_at: String(newPatient.created_at)
    };

    safeJsonResponse(res, patientData, 201);
  } catch (error) {
    console.error('Error creating private patient:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Update private patient
app.put('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const patientId = parseInt(req.params.id);
    const {
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    const existingPatient = await pool.query(
      'SELECT * FROM private_patients WHERE id = $1 AND professional_id = $2',
      [patientId, req.user.id]
    );

    if (existingPatient.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Paciente não encontrado' }, 404);
    }

    const result = await pool.query(
      `UPDATE private_patients 
       SET name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
           address_number = $6, address_complement = $7, neighborhood = $8,
           city = $9, state = $10, zip_code = $11, updated_at = CURRENT_TIMESTAMP
       WHERE id = $12 AND professional_id = $13
       RETURNING *`,
      [
        name?.trim() || existingPatient.rows[0].name,
        email?.trim() || existingPatient.rows[0].email,
        phone?.replace(/\D/g, '') || existingPatient.rows[0].phone,
        birth_date || existingPatient.rows[0].birth_date,
        address?.trim() || existingPatient.rows[0].address,
        address_number?.trim() || existingPatient.rows[0].address_number,
        address_complement?.trim() || existingPatient.rows[0].address_complement,
        neighborhood?.trim() || existingPatient.rows[0].neighborhood,
        city?.trim() || existingPatient.rows[0].city,
        state || existingPatient.rows[0].state,
        zip_code?.replace(/\D/g, '') || existingPatient.rows[0].zip_code,
        patientId,
        req.user.id
      ]
    );

    const updatedPatient = result.rows[0];

    await logAuditAction(req.user.id, 'PRIVATE_PATIENT_UPDATED', 'private_patients', patientId, existingPatient.rows[0], req.body, req);

    const patientData = {
      id: Number(updatedPatient.id),
      professional_id: Number(updatedPatient.professional_id),
      name: String(updatedPatient.name),
      cpf: String(updatedPatient.cpf || ''),
      email: String(updatedPatient.email || ''),
      phone: String(updatedPatient.phone || ''),
      birth_date: updatedPatient.birth_date,
      address: String(updatedPatient.address || ''),
      address_number: String(updatedPatient.address_number || ''),
      address_complement: String(updatedPatient.address_complement || ''),
      neighborhood: String(updatedPatient.neighborhood || ''),
      city: String(updatedPatient.city || ''),
      state: String(updatedPatient.state || ''),
      zip_code: String(updatedPatient.zip_code || ''),
      updated_at: String(updatedPatient.updated_at)
    };

    safeJsonResponse(res, patientData);
  } catch (error) {
    console.error('Error updating private patient:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Delete private patient
app.delete('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const patientId = parseInt(req.params.id);

    const existingPatient = await pool.query(
      'SELECT * FROM private_patients WHERE id = $1 AND professional_id = $2',
      [patientId, req.user.id]
    );

    if (existingPatient.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Paciente não encontrado' }, 404);
    }

    await pool.query('DELETE FROM private_patients WHERE id = $1', [patientId]);

    await logAuditAction(req.user.id, 'PRIVATE_PATIENT_DELETED', 'private_patients', patientId, existingPatient.rows[0], null, req);

    safeJsonResponse(res, { message: 'Paciente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting private patient:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// ==================== ATTENDANCE LOCATIONS ROUTES ====================

// Get attendance locations for professional
app.get('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM attendance_locations 
      WHERE professional_id = $1 
      ORDER BY is_default DESC, name
    `, [req.user.id]);

    const locations = result.rows.map(location => ({
      id: Number(location.id),
      professional_id: Number(location.professional_id),
      name: String(location.name),
      address: String(location.address || ''),
      address_number: String(location.address_number || ''),
      address_complement: String(location.address_complement || ''),
      neighborhood: String(location.neighborhood || ''),
      city: String(location.city || ''),
      state: String(location.state || ''),
      zip_code: String(location.zip_code || ''),
      phone: String(location.phone || ''),
      is_default: Boolean(location.is_default),
      created_at: String(location.created_at)
    }));

    safeJsonResponse(res, locations);
  } catch (error) {
    console.error('Error fetching attendance locations:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Create attendance location
app.post('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name, address, address_number, address_complement, neighborhood,
      city, state, zip_code, phone, is_default
    } = req.body;

    if (!name) {
      return safeJsonResponse(res, { message: 'Nome é obrigatório' }, 400);
    }

    if (is_default) {
      await pool.query(
        'UPDATE attendance_locations SET is_default = FALSE WHERE professional_id = $1',
        [req.user.id]
      );
    }

    const result = await pool.query(
      `INSERT INTO attendance_locations (
        professional_id, name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) 
      RETURNING *`,
      [
        req.user.id,
        name.trim(),
        address?.trim() || null,
        address_number?.trim() || null,
        address_complement?.trim() || null,
        neighborhood?.trim() || null,
        city?.trim() || null,
        state || null,
        zip_code?.replace(/\D/g, '') || null,
        phone?.replace(/\D/g, '') || null,
        Boolean(is_default)
      ]
    );

    const newLocation = result.rows[0];

    await logAuditAction(req.user.id, 'LOCATION_CREATED', 'attendance_locations', newLocation.id, null, req.body, req);

    const locationData = {
      id: Number(newLocation.id),
      professional_id: Number(newLocation.professional_id),
      name: String(newLocation.name),
      address: String(newLocation.address || ''),
      address_number: String(newLocation.address_number || ''),
      address_complement: String(newLocation.address_complement || ''),
      neighborhood: String(newLocation.neighborhood || ''),
      city: String(newLocation.city || ''),
      state: String(newLocation.state || ''),
      zip_code: String(newLocation.zip_code || ''),
      phone: String(newLocation.phone || ''),
      is_default: Boolean(newLocation.is_default),
      created_at: String(newLocation.created_at)
    };

    safeJsonResponse(res, locationData, 201);
  } catch (error) {
    console.error('Error creating attendance location:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Update attendance location
app.put('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const locationId = parseInt(req.params.id);
    const {
      name, address, address_number, address_complement, neighborhood,
      city, state, zip_code, phone, is_default
    } = req.body;

    const existingLocation = await pool.query(
      'SELECT * FROM attendance_locations WHERE id = $1 AND professional_id = $2',
      [locationId, req.user.id]
    );

    if (existingLocation.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Local não encontrado' }, 404);
    }

    if (is_default) {
      await pool.query(
        'UPDATE attendance_locations SET is_default = FALSE WHERE professional_id = $1',
        [req.user.id]
      );
    }

    const result = await pool.query(
      `UPDATE attendance_locations 
       SET name = $1, address = $2, address_number = $3, address_complement = $4,
           neighborhood = $5, city = $6, state = $7, zip_code = $8, phone = $9,
           is_default = $10, updated_at = CURRENT_TIMESTAMP
       WHERE id = $11 AND professional_id = $12
       RETURNING *`,
      [
        name?.trim() || existingLocation.rows[0].name,
        address?.trim() || existingLocation.rows[0].address,
        address_number?.trim() || existingLocation.rows[0].address_number,
        address_complement?.trim() || existingLocation.rows[0].address_complement,
        neighborhood?.trim() || existingLocation.rows[0].neighborhood,
        city?.trim() || existingLocation.rows[0].city,
        state || existingLocation.rows[0].state,
        zip_code?.replace(/\D/g, '') || existingLocation.rows[0].zip_code,
        phone?.replace(/\D/g, '') || existingLocation.rows[0].phone,
        is_default !== undefined ? Boolean(is_default) : existingLocation.rows[0].is_default,
        locationId,
        req.user.id
      ]
    );

    const updatedLocation = result.rows[0];

    await logAuditAction(req.user.id, 'LOCATION_UPDATED', 'attendance_locations', locationId, existingLocation.rows[0], req.body, req);

    const locationData = {
      id: Number(updatedLocation.id),
      professional_id: Number(updatedLocation.professional_id),
      name: String(updatedLocation.name),
      address: String(updatedLocation.address || ''),
      address_number: String(updatedLocation.address_number || ''),
      address_complement: String(updatedLocation.address_complement || ''),
      neighborhood: String(updatedLocation.neighborhood || ''),
      city: String(updatedLocation.city || ''),
      state: String(updatedLocation.state || ''),
      zip_code: String(updatedLocation.zip_code || ''),
      phone: String(updatedLocation.phone || ''),
      is_default: Boolean(updatedLocation.is_default),
      updated_at: String(updatedLocation.updated_at)
    };

    safeJsonResponse(res, locationData);
  } catch (error) {
    console.error('Error updating attendance location:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Delete attendance location
app.delete('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const locationId = parseInt(req.params.id);

    const existingLocation = await pool.query(
      'SELECT * FROM attendance_locations WHERE id = $1 AND professional_id = $2',
      [locationId, req.user.id]
    );

    if (existingLocation.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Local não encontrado' }, 404);
    }

    await pool.query('DELETE FROM attendance_locations WHERE id = $1', [locationId]);

    await logAuditAction(req.user.id, 'LOCATION_DELETED', 'attendance_locations', locationId, existingLocation.rows[0], null, req);

    safeJsonResponse(res, { message: 'Local excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting attendance location:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// ==================== CONSULTATIONS ROUTES ====================

// Get all consultations (admin) or professional's consultations
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query = `
      SELECT c.*, s.name as service_name, u.name as professional_name,
             COALESCE(u2.name, pp.name, d.name) as client_name,
             CASE WHEN d.id IS NOT NULL THEN true ELSE false END as is_dependent
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      JOIN users u ON c.professional_id = u.id
      LEFT JOIN users u2 ON c.client_id = u2.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
    `;

    let queryParams = [];

    if (req.user.currentRole === 'professional') {
      query += ' WHERE c.professional_id = $1';
      queryParams.push(req.user.id);
    }

    query += ' ORDER BY c.date DESC';

    const result = await pool.query(query, queryParams);

    const consultations = result.rows.map(consultation => ({
      id: Number(consultation.id),
      client_id: consultation.client_id ? Number(consultation.client_id) : null,
      dependent_id: consultation.dependent_id ? Number(consultation.dependent_id) : null,
      private_patient_id: consultation.private_patient_id ? Number(consultation.private_patient_id) : null,
      professional_id: Number(consultation.professional_id),
      service_id: Number(consultation.service_id),
      location_id: consultation.location_id ? Number(consultation.location_id) : null,
      value: Number(consultation.value),
      date: String(consultation.date),
      status: String(consultation.status || 'completed'),
      notes: String(consultation.notes || ''),
      service_name: String(consultation.service_name),
      professional_name: String(consultation.professional_name),
      client_name: String(consultation.client_name || 'N/A'),
      is_dependent: Boolean(consultation.is_dependent),
      created_at: String(consultation.created_at),
      updated_at: String(consultation.updated_at)
    }));

    safeJsonResponse(res, consultations);
  } catch (error) {
    console.error('Error fetching consultations:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Get consultations for specific client
app.get('/api/consultations/client/:clientId', authenticate, async (req, res) => {
  try {
    const clientId = parseInt(req.params.clientId);

    if (req.user.currentRole !== 'admin' && req.user.id !== clientId) {
      return safeJsonResponse(res, { message: 'Acesso não autorizado' }, 403);
    }

    const result = await pool.query(`
      SELECT c.*, s.name as service_name, u.name as professional_name,
             COALESCE(u2.name, d.name) as client_name,
             CASE WHEN d.id IS NOT NULL THEN true ELSE false END as is_dependent
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      JOIN users u ON c.professional_id = u.id
      LEFT JOIN users u2 ON c.client_id = u2.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      WHERE c.client_id = $1 OR d.client_id = $1
      ORDER BY c.date DESC
    `, [clientId]);

    const consultations = result.rows.map(consultation => ({
      id: Number(consultation.id),
      client_id: consultation.client_id ? Number(consultation.client_id) : null,
      dependent_id: consultation.dependent_id ? Number(consultation.dependent_id) : null,
      professional_id: Number(consultation.professional_id),
      service_id: Number(consultation.service_id),
      value: Number(consultation.value),
      date: String(consultation.date),
      status: String(consultation.status || 'completed'),
      notes: String(consultation.notes || ''),
      service_name: String(consultation.service_name),
      professional_name: String(consultation.professional_name),
      client_name: String(consultation.client_name || 'N/A'),
      is_dependent: Boolean(consultation.is_dependent),
      created_at: String(consultation.created_at)
    }));

    safeJsonResponse(res, consultations);
  } catch (error) {
    console.error('Error fetching client consultations:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Create consultation
app.post('/api/consultations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      client_id, dependent_id, private_patient_id, service_id, location_id,
      value, date, status, notes
    } = req.body;

    if (!service_id || !value || !date) {
      return safeJsonResponse(res, { message: 'Serviço, valor e data são obrigatórios' }, 400);
    }

    if (!client_id && !dependent_id && !private_patient_id) {
      return safeJsonResponse(res, { message: 'É necessário especificar um cliente, dependente ou paciente particular' }, 400);
    }

    if (Number(value) <= 0) {
      return safeJsonResponse(res, { message: 'Valor deve ser maior que zero' }, 400);
    }

    const result = await pool.query(
      `INSERT INTO consultations (
        client_id, dependent_id, private_patient_id, professional_id, service_id,
        location_id, value, date, status, notes
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
      RETURNING *`,
      [
        client_id || null,
        dependent_id || null,
        private_patient_id || null,
        req.user.id,
        service_id,
        location_id || null,
        Number(value),
        new Date(date),
        status || 'completed',
        notes?.trim() || null
      ]
    );

    const newConsultation = result.rows[0];

    await logAuditAction(req.user.id, 'CONSULTATION_CREATED', 'consultations', newConsultation.id, null, req.body, req);

    const consultationData = {
      id: Number(newConsultation.id),
      client_id: newConsultation.client_id ? Number(newConsultation.client_id) : null,
      dependent_id: newConsultation.dependent_id ? Number(newConsultation.dependent_id) : null,
      private_patient_id: newConsultation.private_patient_id ? Number(newConsultation.private_patient_id) : null,
      professional_id: Number(newConsultation.professional_id),
      service_id: Number(newConsultation.service_id),
      location_id: newConsultation.location_id ? Number(newConsultation.location_id) : null,
      value: Number(newConsultation.value),
      date: String(newConsultation.date),
      status: String(newConsultation.status || 'completed'),
      notes: String(newConsultation.notes || ''),
      created_at: String(newConsultation.created_at)
    };

    safeJsonResponse(res, consultationData, 201);
  } catch (error) {
    console.error('Error creating consultation:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Update consultation status
app.put('/api/consultations/:id/status', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const consultationId = parseInt(req.params.id);
    const { status } = req.body;

    if (!status) {
      return safeJsonResponse(res, { message: 'Status é obrigatório' }, 400);
    }

    const validStatuses = ['scheduled', 'confirmed', 'completed', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return safeJsonResponse(res, { message: 'Status inválido' }, 400);
    }

    const existingConsultation = await pool.query(
      'SELECT * FROM consultations WHERE id = $1 AND professional_id = $2',
      [consultationId, req.user.id]
    );

    if (existingConsultation.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Consulta não encontrada' }, 404);
    }

    const result = await pool.query(
      'UPDATE consultations SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *',
      [status, consultationId]
    );

    const updatedConsultation = result.rows[0];

    await logAuditAction(req.user.id, 'CONSULTATION_STATUS_UPDATED', 'consultations', consultationId, existingConsultation.rows[0], { status }, req);

    const consultationData = {
      id: Number(updatedConsultation.id),
      status: String(updatedConsultation.status),
      updated_at: String(updatedConsultation.updated_at)
    };

    safeJsonResponse(res, consultationData);
  } catch (error) {
    console.error('Error updating consultation status:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// ==================== MEDICAL RECORDS ROUTES ====================

// Get medical records for professional
app.get('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT mr.*, pp.name as patient_name
      FROM medical_records mr
      JOIN private_patients pp ON mr.private_patient_id = pp.id
      WHERE mr.professional_id = $1
      ORDER BY mr.created_at DESC
    `, [req.user.id]);

    const records = result.rows.map(record => ({
      id: Number(record.id),
      professional_id: Number(record.professional_id),
      private_patient_id: Number(record.private_patient_id),
      patient_name: String(record.patient_name),
      chief_complaint: String(record.chief_complaint || ''),
      history_present_illness: String(record.history_present_illness || ''),
      past_medical_history: String(record.past_medical_history || ''),
      medications: String(record.medications || ''),
      allergies: String(record.allergies || ''),
      physical_examination: String(record.physical_examination || ''),
      diagnosis: String(record.diagnosis || ''),
      treatment_plan: String(record.treatment_plan || ''),
      notes: String(record.notes || ''),
      vital_signs: record.vital_signs || {},
      created_at: String(record.created_at),
      updated_at: String(record.updated_at)
    }));

    safeJsonResponse(res, records);
  } catch (error) {
    console.error('Error fetching medical records:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Create medical record
app.post('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      private_patient_id, chief_complaint, history_present_illness, past_medical_history,
      medications, allergies, physical_examination, diagnosis, treatment_plan, notes, vital_signs
    } = req.body;

    if (!private_patient_id) {
      return safeJsonResponse(res, { message: 'ID do paciente é obrigatório' }, 400);
    }

    const patientCheck = await pool.query(
      'SELECT id FROM private_patients WHERE id = $1 AND professional_id = $2',
      [private_patient_id, req.user.id]
    );

    if (patientCheck.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Paciente não encontrado' }, 404);
    }

    const result = await pool.query(
      `INSERT INTO medical_records (
        professional_id, private_patient_id, chief_complaint, history_present_illness,
        past_medical_history, medications, allergies, physical_examination,
        diagnosis, treatment_plan, notes, vital_signs
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) 
      RETURNING *`,
      [
        req.user.id,
        private_patient_id,
        chief_complaint?.trim() || null,
        history_present_illness?.trim() || null,
        past_medical_history?.trim() || null,
        medications?.trim() || null,
        allergies?.trim() || null,
        physical_examination?.trim() || null,
        diagnosis?.trim() || null,
        treatment_plan?.trim() || null,
        notes?.trim() || null,
        vital_signs ? JSON.stringify(vital_signs) : null
      ]
    );

    const newRecord = result.rows[0];

    await logAuditAction(req.user.id, 'MEDICAL_RECORD_CREATED', 'medical_records', newRecord.id, null, req.body, req);

    const recordData = {
      id: Number(newRecord.id),
      professional_id: Number(newRecord.professional_id),
      private_patient_id: Number(newRecord.private_patient_id),
      chief_complaint: String(newRecord.chief_complaint || ''),
      history_present_illness: String(newRecord.history_present_illness || ''),
      past_medical_history: String(newRecord.past_medical_history || ''),
      medications: String(newRecord.medications || ''),
      allergies: String(newRecord.allergies || ''),
      physical_examination: String(newRecord.physical_examination || ''),
      diagnosis: String(newRecord.diagnosis || ''),
      treatment_plan: String(newRecord.treatment_plan || ''),
      notes: String(newRecord.notes || ''),
      vital_signs: newRecord.vital_signs || {},
      created_at: String(newRecord.created_at)
    };

    safeJsonResponse(res, recordData, 201);
  } catch (error) {
    console.error('Error creating medical record:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Update medical record
app.put('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const recordId = parseInt(req.params.id);
    const {
      chief_complaint, history_present_illness, past_medical_history,
      medications, allergies, physical_examination, diagnosis, treatment_plan, notes, vital_signs
    } = req.body;

    const existingRecord = await pool.query(
      'SELECT * FROM medical_records WHERE id = $1 AND professional_id = $2',
      [recordId, req.user.id]
    );

    if (existingRecord.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Prontuário não encontrado' }, 404);
    }

    const result = await pool.query(
      `UPDATE medical_records 
       SET chief_complaint = $1, history_present_illness = $2, past_medical_history = $3,
           medications = $4, allergies = $5, physical_examination = $6, diagnosis = $7,
           treatment_plan = $8, notes = $9, vital_signs = $10, updated_at = CURRENT_TIMESTAMP
       WHERE id = $11 AND professional_id = $12
       RETURNING *`,
      [
        chief_complaint?.trim() || existingRecord.rows[0].chief_complaint,
        history_present_illness?.trim() || existingRecord.rows[0].history_present_illness,
        past_medical_history?.trim() || existingRecord.rows[0].past_medical_history,
        medications?.trim() || existingRecord.rows[0].medications,
        allergies?.trim() || existingRecord.rows[0].allergies,
        physical_examination?.trim() || existingRecord.rows[0].physical_examination,
        diagnosis?.trim() || existingRecord.rows[0].diagnosis,
        treatment_plan?.trim() || existingRecord.rows[0].treatment_plan,
        notes?.trim() || existingRecord.rows[0].notes,
        vital_signs ? JSON.stringify(vital_signs) : existingRecord.rows[0].vital_signs,
        recordId,
        req.user.id
      ]
    );

    const updatedRecord = result.rows[0];

    await logAuditAction(req.user.id, 'MEDICAL_RECORD_UPDATED', 'medical_records', recordId, existingRecord.rows[0], req.body, req);

    const recordData = {
      id: Number(updatedRecord.id),
      professional_id: Number(updatedRecord.professional_id),
      private_patient_id: Number(updatedRecord.private_patient_id),
      chief_complaint: String(updatedRecord.chief_complaint || ''),
      history_present_illness: String(updatedRecord.history_present_illness || ''),
      past_medical_history: String(updatedRecord.past_medical_history || ''),
      medications: String(updatedRecord.medications || ''),
      allergies: String(updatedRecord.allergies || ''),
      physical_examination: String(updatedRecord.physical_examination || ''),
      diagnosis: String(updatedRecord.diagnosis || ''),
      treatment_plan: String(updatedRecord.treatment_plan || ''),
      notes: String(updatedRecord.notes || ''),
      vital_signs: updatedRecord.vital_signs || {},
      updated_at: String(updatedRecord.updated_at)
    };

    safeJsonResponse(res, recordData);
  } catch (error) {
    console.error('Error updating medical record:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Delete medical record
app.delete('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const recordId = parseInt(req.params.id);

    const existingRecord = await pool.query(
      'SELECT * FROM medical_records WHERE id = $1 AND professional_id = $2',
      [recordId, req.user.id]
    );

    if (existingRecord.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Prontuário não encontrado' }, 404);
    }

    await pool.query('DELETE FROM medical_records WHERE id = $1', [recordId]);

    await logAuditAction(req.user.id, 'MEDICAL_RECORD_DELETED', 'medical_records', recordId, existingRecord.rows[0], null, req);

    safeJsonResponse(res, { message: 'Prontuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting medical record:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Generate medical record document
app.post('/api/medical-records/generate-document', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { record_id, template_data } = req.body;

    if (!record_id || !template_data) {
      return safeJsonResponse(res, { message: 'ID do prontuário e dados do template são obrigatórios' }, 400);
    }

    const recordCheck = await pool.query(
      'SELECT id FROM medical_records WHERE id = $1 AND professional_id = $2',
      [record_id, req.user.id]
    );

    if (recordCheck.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Prontuário não encontrado' }, 404);
    }

    const documentResult = await generateDocumentPDF('medical_record', template_data);

    safeJsonResponse(res, {
      message: 'Documento gerado com sucesso',
      documentUrl: documentResult.url
    });
  } catch (error) {
    console.error('Error generating medical record document:', error);
    safeJsonResponse(res, { message: 'Erro ao gerar documento' }, 500);
  }
});

// ==================== MEDICAL DOCUMENTS ROUTES ====================

// Get medical documents for professional
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM medical_documents 
      WHERE professional_id = $1 
      ORDER BY created_at DESC
    `, [req.user.id]);

    const documents = result.rows.map(doc => ({
      id: Number(doc.id),
      professional_id: Number(doc.professional_id),
      private_patient_id: doc.private_patient_id ? Number(doc.private_patient_id) : null,
      title: String(doc.title),
      document_type: String(doc.document_type),
      document_url: String(doc.document_url),
      patient_name: String(doc.patient_name),
      created_at: String(doc.created_at)
    }));

    safeJsonResponse(res, documents);
  } catch (error) {
    console.error('Error fetching medical documents:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Create medical document
app.post('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { title, document_type, private_patient_id, template_data } = req.body;

    if (!title || !document_type || !template_data) {
      return safeJsonResponse(res, { message: 'Título, tipo de documento e dados do template são obrigatórios' }, 400);
    }

    if (private_patient_id) {
      const patientCheck = await pool.query(
        'SELECT id FROM private_patients WHERE id = $1 AND professional_id = $2',
        [private_patient_id, req.user.id]
      );

      if (patientCheck.rows.length === 0) {
        return safeJsonResponse(res, { message: 'Paciente não encontrado' }, 404);
      }
    }

    const documentResult = await generateDocumentPDF(document_type, template_data);

    const result = await pool.query(
      `INSERT INTO medical_documents (
        professional_id, private_patient_id, title, document_type, document_url, patient_name
      ) VALUES ($1, $2, $3, $4, $5, $6) 
      RETURNING *`,
      [
        req.user.id,
        private_patient_id || null,
        title.trim(),
        document_type,
        documentResult.url,
        template_data.patientName || 'Paciente'
      ]
    );

    const newDocument = result.rows[0];

    await logAuditAction(req.user.id, 'MEDICAL_DOCUMENT_CREATED', 'medical_documents', newDocument.id, null, req.body, req);

    safeJsonResponse(res, {
      message: 'Documento criado com sucesso',
      title: newDocument.title,
      documentUrl: documentResult.url
    }, 201);
  } catch (error) {
    console.error('Error creating medical document:', error);
    safeJsonResponse(res, { message: 'Erro ao criar documento' }, 500);
  }
});

// ==================== REPORTS ROUTES ====================

// Revenue report (admin only)
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return safeJsonResponse(res, { message: 'Data inicial e final são obrigatórias' }, 400);
    }

    const revenueByProfessional = await pool.query(`
      SELECT 
        u.name as professional_name,
        u.professional_percentage,
        COUNT(c.id) as consultation_count,
        SUM(c.value) as revenue,
        SUM(c.value * (u.professional_percentage / 100)) as professional_payment,
        SUM(c.value * ((100 - u.professional_percentage) / 100)) as clinic_revenue
      FROM consultations c
      JOIN users u ON c.professional_id = u.id
      WHERE c.date >= $1 AND c.date <= $2
      GROUP BY u.id, u.name, u.professional_percentage
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    const revenueByService = await pool.query(`
      SELECT 
        s.name as service_name,
        COUNT(c.id) as consultation_count,
        SUM(c.value) as revenue
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      WHERE c.date >= $1 AND c.date <= $2
      GROUP BY s.id, s.name
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    const totalRevenue = await pool.query(`
      SELECT SUM(value) as total_revenue
      FROM consultations
      WHERE date >= $1 AND date <= $2
    `, [start_date, end_date]);

    const reportData = {
      total_revenue: Number(totalRevenue.rows[0]?.total_revenue || 0),
      revenue_by_professional: revenueByProfessional.rows.map(row => ({
        professional_name: String(row.professional_name),
        professional_percentage: Number(row.professional_percentage || 50),
        consultation_count: Number(row.consultation_count || 0),
        revenue: Number(row.revenue || 0),
        professional_payment: Number(row.professional_payment || 0),
        clinic_revenue: Number(row.clinic_revenue || 0)
      })),
      revenue_by_service: revenueByService.rows.map(row => ({
        service_name: String(row.service_name),
        consultation_count: Number(row.consultation_count || 0),
        revenue: Number(row.revenue || 0)
      }))
    };

    safeJsonResponse(res, reportData);
  } catch (error) {
    console.error('Error generating revenue report:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Professional revenue report
app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return safeJsonResponse(res, { message: 'Data inicial e final são obrigatórias' }, 400);
    }

    const professionalData = await pool.query(
      'SELECT professional_percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = Number(professionalData.rows[0]?.professional_percentage || 50);

    const consultations = await pool.query(`
      SELECT 
        c.date, c.value,
        COALESCE(u.name, pp.name, d.name) as client_name,
        s.name as service_name,
        CASE 
          WHEN c.private_patient_id IS NOT NULL THEN c.value
          ELSE c.value * ($1 / 100)
        END as professional_amount,
        CASE 
          WHEN c.private_patient_id IS NOT NULL THEN 0
          ELSE c.value * ((100 - $1) / 100)
        END as amount_to_pay
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      WHERE c.professional_id = $2 AND c.date >= $3 AND c.date <= $4
      ORDER BY c.date DESC
    `, [professionalPercentage, req.user.id, start_date, end_date]);

    const summary = await pool.query(`
      SELECT 
        COUNT(*) as consultation_count,
        SUM(c.value) as total_revenue,
        SUM(CASE 
          WHEN c.private_patient_id IS NOT NULL THEN 0
          ELSE c.value * ((100 - $1) / 100)
        END) as amount_to_pay
      FROM consultations c
      WHERE c.professional_id = $2 AND c.date >= $3 AND c.date <= $4
    `, [professionalPercentage, req.user.id, start_date, end_date]);

    const reportData = {
      summary: {
        professional_percentage: professionalPercentage,
        consultation_count: Number(summary.rows[0]?.consultation_count || 0),
        total_revenue: Number(summary.rows[0]?.total_revenue || 0),
        amount_to_pay: Number(summary.rows[0]?.amount_to_pay || 0)
      },
      consultations: consultations.rows.map(consultation => ({
        date: String(consultation.date),
        client_name: String(consultation.client_name || 'N/A'),
        service_name: String(consultation.service_name),
        total_value: Number(consultation.value),
        amount_to_pay: Number(consultation.amount_to_pay || 0)
      }))
    };

    safeJsonResponse(res, reportData);
  } catch (error) {
    console.error('Error generating professional revenue report:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Professional detailed report
app.get('/api/reports/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return safeJsonResponse(res, { message: 'Data inicial e final são obrigatórias' }, 400);
    }

    const professionalData = await pool.query(
      'SELECT professional_percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = Number(professionalData.rows[0]?.professional_percentage || 50);

    const summary = await pool.query(`
      SELECT 
        COUNT(*) as total_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        SUM(c.value) as total_revenue,
        SUM(CASE WHEN c.private_patient_id IS NULL THEN c.value ELSE 0 END) as convenio_revenue,
        SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END) as private_revenue,
        SUM(CASE 
          WHEN c.private_patient_id IS NOT NULL THEN 0
          ELSE c.value * ((100 - $1) / 100)
        END) as amount_to_pay
      FROM consultations c
      WHERE c.professional_id = $2 AND c.date >= $3 AND c.date <= $4
    `, [professionalPercentage, req.user.id, start_date, end_date]);

    const reportData = {
      summary: {
        total_consultations: Number(summary.rows[0]?.total_consultations || 0),
        convenio_consultations: Number(summary.rows[0]?.convenio_consultations || 0),
        private_consultations: Number(summary.rows[0]?.private_consultations || 0),
        total_revenue: Number(summary.rows[0]?.total_revenue || 0),
        convenio_revenue: Number(summary.rows[0]?.convenio_revenue || 0),
        private_revenue: Number(summary.rows[0]?.private_revenue || 0),
        professional_percentage: professionalPercentage,
        amount_to_pay: Number(summary.rows[0]?.amount_to_pay || 0)
      }
    };

    safeJsonResponse(res, reportData);
  } catch (error) {
    console.error('Error generating professional detailed report:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Clients by city report (admin only)
app.get('/api/reports/clients-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        city,
        state,
        COUNT(*) as client_count,
        COUNT(CASE WHEN subscription_status = 'active' THEN 1 END) as active_clients,
        COUNT(CASE WHEN subscription_status = 'pending' THEN 1 END) as pending_clients,
        COUNT(CASE WHEN subscription_status = 'expired' THEN 1 END) as expired_clients
      FROM users 
      WHERE 'client' = ANY(roles) AND city IS NOT NULL AND city != ''
      GROUP BY city, state
      ORDER BY client_count DESC
    `);

    const report = result.rows.map(row => ({
      city: String(row.city),
      state: String(row.state || ''),
      client_count: Number(row.client_count || 0),
      active_clients: Number(row.active_clients || 0),
      pending_clients: Number(row.pending_clients || 0),
      expired_clients: Number(row.expired_clients || 0)
    }));

    safeJsonResponse(res, report);
  } catch (error) {
    console.error('Error generating clients by city report:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Professionals by city report (admin only)
app.get('/api/reports/professionals-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        city,
        state,
        COUNT(*) as total_professionals,
        array_agg(DISTINCT category_name) as categories
      FROM users 
      WHERE 'professional' = ANY(roles) AND city IS NOT NULL AND city != ''
      GROUP BY city, state
      ORDER BY total_professionals DESC
    `);

    const report = result.rows.map(row => ({
      city: String(row.city),
      state: String(row.state || ''),
      total_professionals: Number(row.total_professionals || 0),
      categories: (row.categories || []).filter(cat => cat).map(cat => ({
        category_name: String(cat),
        count: 1
      }))
    }));

    safeJsonResponse(res, report);
  } catch (error) {
    console.error('Error generating professionals by city report:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// ==================== PAYMENT ROUTES (PRESERVED) ====================

// Create subscription payment
app.post('/api/create-subscription', authenticate, async (req, res) => {
  try {
    const { user_id } = req.body;

    if (!user_id) {
      return safeJsonResponse(res, { message: 'ID do usuário é obrigatório' }, 400);
    }

    if (req.user.currentRole !== 'admin' && req.user.id !== user_id) {
      return safeJsonResponse(res, { message: 'Acesso não autorizado' }, 403);
    }

    const userResult = await pool.query(
      'SELECT name, subscription_status FROM users WHERE id = $1',
      [user_id]
    );

    if (userResult.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Usuário não encontrado' }, 404);
    }

    const user = userResult.rows[0];

    if (user.subscription_status === 'active') {
      return safeJsonResponse(res, { message: 'Usuário já possui assinatura ativa' }, 400);
    }

    const externalReference = `client_${user_id}_${Date.now()}`;

    const preference = new Preference(client);
    const preferenceData = {
      items: [
        {
          id: 'subscription',
          title: 'Assinatura Cartão Quiro Ferreira',
          description: `Assinatura anual para ${user.name}`,
          quantity: 1,
          unit_price: 250.00,
          currency_id: 'BRL'
        }
      ],
      payer: {
        name: user.name,
        email: 'cliente@cartaoquiroferreira.com.br'
      },
      back_urls: {
        success: 'https://cartaoquiroferreira.com.br/client?payment=success&type=subscription',
        failure: 'https://cartaoquiroferreira.com.br/client?payment=failure&type=subscription',
        pending: 'https://cartaoquiroferreira.com.br/client?payment=pending&type=subscription'
      },
      auto_return: 'approved',
      external_reference: externalReference,
      notification_url: 'https://cartaoquiroferreira.com.br/api/webhook/mercadopago'
    };

    const response = await preference.create({ body: preferenceData });

    await pool.query(
      `INSERT INTO client_payments (client_id, amount, external_reference, preference_id) 
       VALUES ($1, $2, $3, $4)`,
      [user_id, 250.00, externalReference, response.id]
    );

    await logAuditAction(req.user.id, 'SUBSCRIPTION_PAYMENT_CREATED', 'client_payments', null, null, { user_id, amount: 250 }, req);

    safeJsonResponse(res, {
      preference_id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point
    });
  } catch (error) {
    console.error('Error creating subscription payment:', error);
    safeJsonResponse(res, { message: 'Erro ao criar pagamento' }, 500);
  }
});

// Create dependent payment
app.post('/api/dependents/:id/create-payment', authenticate, async (req, res) => {
  try {
    const dependentId = parseInt(req.params.id);

    const dependentResult = await pool.query(`
      SELECT d.*, u.name as client_name
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      WHERE d.id = $1
    `, [dependentId]);

    if (dependentResult.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Dependente não encontrado' }, 404);
    }

    const dependent = dependentResult.rows[0];

    if (req.user.currentRole !== 'admin' && req.user.id !== dependent.client_id) {
      return safeJsonResponse(res, { message: 'Acesso não autorizado' }, 403);
    }

    if (dependent.subscription_status === 'active') {
      return safeJsonResponse(res, { message: 'Dependente já possui assinatura ativa' }, 400);
    }

    const externalReference = `dependent_${dependentId}_${Date.now()}`;

    const preference = new Preference(client);
    const preferenceData = {
      items: [
        {
          id: 'dependent_subscription',
          title: 'Assinatura Dependente - Cartão Quiro Ferreira',
          description: `Assinatura anual para dependente ${dependent.name}`,
          quantity: 1,
          unit_price: Number(dependent.billing_amount || 50),
          currency_id: 'BRL'
        }
      ],
      payer: {
        name: dependent.client_name,
        email: 'cliente@cartaoquiroferreira.com.br'
      },
      back_urls: {
        success: 'https://cartaoquiroferreira.com.br/client?payment=success&type=dependent',
        failure: 'https://cartaoquiroferreira.com.br/client?payment=failure&type=dependent',
        pending: 'https://cartaoquiroferreira.com.br/client?payment=pending&type=dependent'
      },
      auto_return: 'approved',
      external_reference: externalReference,
      notification_url: 'https://cartaoquiroferreira.com.br/api/webhook/mercadopago'
    };

    const response = await preference.create({ body: preferenceData });

    await pool.query(
      `INSERT INTO dependent_payments (dependent_id, amount, external_reference, preference_id) 
       VALUES ($1, $2, $3, $4)`,
      [dependentId, Number(dependent.billing_amount || 50), externalReference, response.id]
    );

    await logAuditAction(req.user.id, 'DEPENDENT_PAYMENT_CREATED', 'dependent_payments', null, null, { dependent_id: dependentId }, req);

    safeJsonResponse(res, {
      preference_id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point
    });
  } catch (error) {
    console.error('Error creating dependent payment:', error);
    safeJsonResponse(res, { message: 'Erro ao criar pagamento' }, 500);
  }
});

// Create professional payment
app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || Number(amount) <= 0) {
      return safeJsonResponse(res, { message: 'Valor deve ser maior que zero' }, 400);
    }

    const externalReference = `professional_${req.user.id}_${Date.now()}`;

    const preference = new Preference(client);
    const preferenceData = {
      items: [
        {
          id: 'professional_payment',
          title: 'Repasse ao Convênio Quiro Ferreira',
          description: `Pagamento de repasse - ${req.user.name}`,
          quantity: 1,
          unit_price: Number(amount),
          currency_id: 'BRL'
        }
      ],
      payer: {
        name: req.user.name,
        email: 'profissional@cartaoquiroferreira.com.br'
      },
      back_urls: {
        success: 'https://cartaoquiroferreira.com.br/professional?payment=success&type=repasse',
        failure: 'https://cartaoquiroferreira.com.br/professional?payment=failure&type=repasse',
        pending: 'https://cartaoquiroferreira.com.br/professional?payment=pending&type=repasse'
      },
      auto_return: 'approved',
      external_reference: externalReference,
      notification_url: 'https://cartaoquiroferreira.com.br/api/webhook/mercadopago'
    };

    const response = await preference.create({ body: preferenceData });

    await pool.query(
      `INSERT INTO professional_payments (professional_id, amount, external_reference, preference_id) 
       VALUES ($1, $2, $3, $4)`,
      [req.user.id, Number(amount), externalReference, response.id]
    );

    await logAuditAction(req.user.id, 'PROFESSIONAL_PAYMENT_CREATED', 'professional_payments', null, null, { amount }, req);

    safeJsonResponse(res, {
      preference_id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point
    });
  } catch (error) {
    console.error('Error creating professional payment:', error);
    safeJsonResponse(res, { message: 'Erro ao criar pagamento' }, 500);
  }
});

// Create agenda payment
app.post('/api/agenda/create-payment', authenticate, async (req, res) => {
  try {
    const { consultation_id, amount } = req.body;

    if (!consultation_id || !amount || Number(amount) <= 0) {
      return safeJsonResponse(res, { message: 'ID da consulta e valor são obrigatórios' }, 400);
    }

    const consultationResult = await pool.query(
      'SELECT * FROM consultations WHERE id = $1',
      [consultation_id]
    );

    if (consultationResult.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Consulta não encontrada' }, 404);
    }

    const consultation = consultationResult.rows[0];

    if (req.user.currentRole !== 'admin' && req.user.id !== consultation.client_id) {
      return safeJsonResponse(res, { message: 'Acesso não autorizado' }, 403);
    }

    const externalReference = `agenda_${consultation_id}_${Date.now()}`;

    const preference = new Preference(client);
    const preferenceData = {
      items: [
        {
          id: 'agenda_payment',
          title: 'Pagamento de Consulta - Cartão Quiro Ferreira',
          description: `Pagamento de consulta agendada`,
          quantity: 1,
          unit_price: Number(amount),
          currency_id: 'BRL'
        }
      ],
      payer: {
        name: req.user.name,
        email: 'cliente@cartaoquiroferreira.com.br'
      },
      back_urls: {
        success: 'https://cartaoquiroferreira.com.br/client?payment=success&type=agenda',
        failure: 'https://cartaoquiroferreira.com.br/client?payment=failure&type=agenda',
        pending: 'https://cartaoquiroferreira.com.br/client?payment=pending&type=agenda'
      },
      auto_return: 'approved',
      external_reference: externalReference,
      notification_url: 'https://cartaoquiroferreira.com.br/api/webhook/mercadopago'
    };

    const response = await preference.create({ body: preferenceData });

    await pool.query(
      `INSERT INTO agenda_payments (client_id, consultation_id, amount, external_reference, preference_id) 
       VALUES ($1, $2, $3, $4, $5)`,
      [req.user.id, consultation_id, Number(amount), externalReference, response.id]
    );

    await logAuditAction(req.user.id, 'AGENDA_PAYMENT_CREATED', 'agenda_payments', null, null, { consultation_id, amount }, req);

    safeJsonResponse(res, {
      preference_id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point
    });
  } catch (error) {
    console.error('Error creating agenda payment:', error);
    safeJsonResponse(res, { message: 'Erro ao criar pagamento' }, 500);
  }
});

// MercadoPago webhook (PRESERVED)
app.post('/api/webhook/mercadopago', async (req, res) => {
  try {
    console.log('🔔 MercadoPago webhook received:', req.body);

    const { type, data } = req.body;

    if (type === 'payment') {
      const paymentId = data.id;
      console.log('💰 Processing payment:', paymentId);

      const payment = new Payment(client);
      const paymentData = await payment.get({ id: paymentId });

      console.log('📊 Payment data:', paymentData);

      const externalReference = paymentData.external_reference;
      const status = paymentData.status;

      if (!externalReference) {
        console.warn('⚠️ No external reference found');
        return safeJsonResponse(res, { message: 'OK' });
      }

      console.log('🔍 Processing external reference:', externalReference);

      let paymentStatus = 'pending';
      if (status === 'approved') {
        paymentStatus = 'approved';
      } else if (status === 'rejected' || status === 'cancelled') {
        paymentStatus = 'failed';
      }

      const tables = ['client_payments', 'dependent_payments', 'professional_payments', 'agenda_payments'];
      let paymentFound = false;

      for (const table of tables) {
        try {
          const checkResult = await pool.query(
            `SELECT * FROM ${table} WHERE external_reference = $1`,
            [externalReference]
          );

          if (checkResult.rows.length > 0) {
            const existingPayment = checkResult.rows[0];
            
            if (existingPayment.payment_status === paymentStatus) {
              console.log(`✅ Payment already processed in ${table}`);
              paymentFound = true;
              break;
            }

            await pool.query(
              `UPDATE ${table} 
               SET payment_status = $1, payment_id = $2, payment_method = $3, updated_at = CURRENT_TIMESTAMP
               WHERE external_reference = $4`,
              [paymentStatus, paymentId, paymentData.payment_method_id, externalReference]
            );

            console.log(`✅ Payment updated in ${table}:`, paymentStatus);

            if (paymentStatus === 'approved') {
              if (table === 'client_payments') {
                const clientId = existingPayment.client_id;
                const expiryDate = new Date();
                expiryDate.setFullYear(expiryDate.getFullYear() + 1);

                await pool.query(
                  'UPDATE users SET subscription_status = $1, subscription_expiry = $2 WHERE id = $3',
                  ['active', expiryDate, clientId]
                );

                console.log('✅ Client subscription activated');
              } else if (table === 'dependent_payments') {
                const dependentId = existingPayment.dependent_id;
                const expiryDate = new Date();
                expiryDate.setFullYear(expiryDate.getFullYear() + 1);

                await pool.query(
                  `UPDATE dependents 
                   SET subscription_status = $1, subscription_expiry = $2, activated_at = CURRENT_TIMESTAMP 
                   WHERE id = $3`,
                  ['active', expiryDate, dependentId]
                );

                console.log('✅ Dependent subscription activated');
              }
            }

            paymentFound = true;
            break;
          }
        } catch (error) {
          console.error(`❌ Error checking ${table}:`, error);
        }
      }

      if (!paymentFound) {
        console.warn('⚠️ Payment not found in any table:', externalReference);
      }
    }

    safeJsonResponse(res, { message: 'OK' });
  } catch (error) {
    console.error('❌ Webhook error:', error);
    safeJsonResponse(res, { message: 'OK' });
  }
});

// ==================== IMAGE UPLOAD ROUTE ====================

// Upload image
app.post('/api/upload-image', authenticate, async (req, res) => {
  try {
    const upload = createUpload();
    
    upload.single('image')(req, res, async (err) => {
      if (err) {
        console.error('Upload error:', err);
        return safeJsonResponse(res, { message: err.message || 'Erro no upload da imagem' }, 400);
      }

      if (!req.file) {
        return safeJsonResponse(res, { message: 'Nenhuma imagem foi enviada' }, 400);
      }

      const imageUrl = req.file.path;

      await pool.query(
        'UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
        [imageUrl, req.user.id]
      );

      await logAuditAction(req.user.id, 'PHOTO_UPLOADED', 'users', req.user.id, null, { photo_url: imageUrl }, req);

      safeJsonResponse(res, {
        message: 'Imagem enviada com sucesso',
        imageUrl: imageUrl
      });
    });
  } catch (error) {
    console.error('Error uploading image:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// ==================== NOTIFICATIONS ROUTES ====================

// Get notifications for user
app.get('/api/notifications', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM notifications 
      WHERE user_id = $1 
      ORDER BY created_at DESC 
      LIMIT 50
    `, [req.user.id]);

    const notifications = result.rows.map(notification => ({
      id: Number(notification.id),
      user_id: Number(notification.user_id),
      title: String(notification.title),
      message: String(notification.message),
      type: String(notification.type || 'info'),
      is_read: Boolean(notification.is_read),
      created_at: String(notification.created_at)
    }));

    safeJsonResponse(res, notifications);
  } catch (error) {
    console.error('Error fetching notifications:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Mark notification as read
app.put('/api/notifications/:id/read', authenticate, async (req, res) => {
  try {
    const notificationId = parseInt(req.params.id);

    const result = await pool.query(
      'UPDATE notifications SET is_read = TRUE WHERE id = $1 AND user_id = $2 RETURNING *',
      [notificationId, req.user.id]
    );

    if (result.rows.length === 0) {
      return safeJsonResponse(res, { message: 'Notificação não encontrada' }, 404);
    }

    safeJsonResponse(res, { message: 'Notificação marcada como lida' });
  } catch (error) {
    console.error('Error marking notification as read:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// ==================== SYSTEM SETTINGS ROUTES ====================

// Get system settings (admin only)
app.get('/api/system-settings', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM system_settings ORDER BY key');

    const settings = result.rows.map(setting => ({
      id: Number(setting.id),
      key: String(setting.key),
      value: String(setting.value || ''),
      description: String(setting.description || ''),
      created_at: String(setting.created_at),
      updated_at: String(setting.updated_at)
    }));

    safeJsonResponse(res, settings);
  } catch (error) {
    console.error('Error fetching system settings:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// Update system setting (admin only)
app.put('/api/system-settings/:key', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { key } = req.params;
    const { value, description } = req.body;

    const result = await pool.query(
      `INSERT INTO system_settings (key, value, description) 
       VALUES ($1, $2, $3) 
       ON CONFLICT (key) 
       DO UPDATE SET value = $2, description = $3, updated_at = CURRENT_TIMESTAMP
       RETURNING *`,
      [key, value || null, description || null]
    );

    const setting = result.rows[0];

    await logAuditAction(req.user.id, 'SYSTEM_SETTING_UPDATED', 'system_settings', setting.id, null, { key, value, description }, req);

    const settingData = {
      id: Number(setting.id),
      key: String(setting.key),
      value: String(setting.value || ''),
      description: String(setting.description || ''),
      updated_at: String(setting.updated_at)
    };

    safeJsonResponse(res, settingData);
  } catch (error) {
    console.error('Error updating system setting:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// ==================== AUDIT LOGS ROUTES ====================

// Get audit logs (admin only)
app.get('/api/audit-logs', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { limit = 100, offset = 0 } = req.query;

    const result = await pool.query(`
      SELECT al.*, u.name as user_name
      FROM audit_logs al
      LEFT JOIN users u ON al.user_id = u.id
      ORDER BY al.created_at DESC
      LIMIT $1 OFFSET $2
    `, [Number(limit), Number(offset)]);

    const logs = result.rows.map(log => ({
      id: Number(log.id),
      user_id: log.user_id ? Number(log.user_id) : null,
      user_name: String(log.user_name || 'Sistema'),
      action: String(log.action),
      table_name: String(log.table_name || ''),
      record_id: log.record_id ? Number(log.record_id) : null,
      old_values: log.old_values || {},
      new_values: log.new_values || {},
      ip_address: String(log.ip_address || ''),
      user_agent: String(log.user_agent || ''),
      created_at: String(log.created_at)
    }));

    safeJsonResponse(res, logs);
  } catch (error) {
    console.error('Error fetching audit logs:', error);
    safeJsonResponse(res, { message: 'Erro interno do servidor' }, 500);
  }
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use('*', (req, res) => {
  safeJsonResponse(res, { message: 'Rota não encontrada' }, 404);
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);
  
  if (res.headersSent) {
    return next(error);
  }
  
  safeJsonResponse(res, { 
    message: 'Erro interno do servidor',
    error: process.env.NODE_ENV === 'development' ? error.message : undefined
  }, 500);
});

// ==================== SERVER STARTUP ====================

const startServer = async () => {
  try {
    await initializeDatabase();
    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔗 CORS enabled for production domains`);
      console.log(`💳 MercadoPago SDK v2 initialized`);
      console.log(`📊 Database connected and tables created`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully');
  process.exit(0);
});

// Start the server
startServer();