import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';
import createUpload from './middleware/upload.js';
import { generateDocumentPDF } from './utils/documentGenerator.js';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// CORS configuration for production
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

// Global middlewares
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
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
        birth_date DATE,
        address TEXT,
        address_number VARCHAR(20),
        address_complement VARCHAR(100),
        neighborhood VARCHAR(100),
        city VARCHAR(100),
        state VARCHAR(2),
        password_hash VARCHAR(255) NOT NULL,
        roles TEXT[] DEFAULT ARRAY['client'],
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry TIMESTAMP,
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
        template_data JSONB,
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
        merchant_order_id VARCHAR(255),
        processed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        merchant_order_id VARCHAR(255),
        processed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        merchant_order_id VARCHAR(255),
        processed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Agenda payments table
      CREATE TABLE IF NOT EXISTS agenda_payments (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        consultation_id INTEGER REFERENCES consultations(id),
        amount DECIMAL(10,2) NOT NULL,
        payment_status VARCHAR(20) DEFAULT 'pending',
        payment_method VARCHAR(50),
        external_reference VARCHAR(255),
        preference_id VARCHAR(255),
        payment_id VARCHAR(255),
        merchant_order_id VARCHAR(255),
        processed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Audit logs table
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        action VARCHAR(100) NOT NULL,
        table_name VARCHAR(100),
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
        key VARCHAR(255) UNIQUE NOT NULL,
        value TEXT,
        description TEXT,
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

// Utility function to safely serialize data for JSON responses
const safeSerialize = (data) => {
  try {
    return JSON.parse(JSON.stringify(data));
  } catch (error) {
    console.error('Serialization error:', error);
    return data;
  }
};

// Utility function to send safe JSON responses
const sendSafeJSON = (res, data, statusCode = 200) => {
  try {
    const serializedData = safeSerialize(data);
    res.status(statusCode);
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(serializedData));
  } catch (error) {
    console.error('Response error:', error);
    res.status(500).send(JSON.stringify({ message: 'Internal server error' }));
  }
};

// Middleware to check subscription status
const checkSubscriptionStatus = async (req, res, next) => {
  try {
    if (!req.user || !req.user.id) {
      return res.status(401).json({ message: 'Usuário não autenticado' });
    }

    // Skip subscription check for admins
    if (req.user.currentRole === 'admin') {
      return next();
    }

    // Check user subscription status
    const result = await pool.query(
      'SELECT subscription_status, subscription_expiry FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];
    
    // Allow access for active subscriptions or pending for certain operations
    if (user.subscription_status === 'active' || 
        (user.subscription_status === 'pending' && req.method === 'GET')) {
      return next();
    }

    // For expired or invalid subscriptions
    return res.status(403).json({ 
      message: 'Acesso negado: assinatura inválida ou expirada',
      subscription_status: user.subscription_status 
    });
  } catch (error) {
    console.error('Subscription check error:', error);
    return res.status(500).json({ message: 'Erro interno do servidor' });
  }
};

// Health check endpoint
app.get('/health', (req, res) => {
  sendSafeJSON(res, { 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Version endpoint
app.get('/version', (req, res) => {
  sendSafeJSON(res, { 
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  });
});

// ==================== AUTH ROUTES ====================

// Login route
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return res.status(400).json({ message: 'CPF e senha são obrigatórios' });
    }

    // Find user by CPF
    const result = await pool.query(
      'SELECT id, name, cpf, password_hash, roles FROM users WHERE cpf = $1',
      [cpf.replace(/\D/g, '')]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const user = result.rows[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    // Check if user has multiple roles
    const roles = user.roles || ['client'];
    const needsRoleSelection = roles.length > 1;

    const userData = {
      id: user.id,
      name: user.name,
      roles: roles
    };

    sendSafeJSON(res, {
      user: userData,
      needsRoleSelection
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Select role route
app.post('/api/auth/select-role', async (req, res) => {
  try {
    const { userId, role } = req.body;

    if (!userId || !role) {
      return res.status(400).json({ message: 'ID do usuário e role são obrigatórios' });
    }

    // Verify user exists and has the requested role
    const result = await pool.query(
      'SELECT id, name, roles FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];
    const userRoles = user.roles || [];

    if (!userRoles.includes(role)) {
      return res.status(403).json({ message: 'Role não autorizada para este usuário' });
    }

    // Generate JWT token with selected role
    const token = jwt.sign(
      { 
        id: user.id, 
        currentRole: role 
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });

    const userData = {
      id: user.id,
      name: user.name,
      roles: userRoles,
      currentRole: role
    };

    sendSafeJSON(res, {
      token,
      user: userData
    });
  } catch (error) {
    console.error('Role selection error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Switch role route
app.post('/api/auth/switch-role', authenticate, async (req, res) => {
  try {
    const { role } = req.body;

    if (!role) {
      return res.status(400).json({ message: 'Role é obrigatória' });
    }

    // Verify user has the requested role
    const result = await pool.query(
      'SELECT id, name, roles FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];
    const userRoles = user.roles || [];

    if (!userRoles.includes(role)) {
      return res.status(403).json({ message: 'Role não autorizada para este usuário' });
    }

    // Generate new JWT token with new role
    const token = jwt.sign(
      { 
        id: user.id, 
        currentRole: role 
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });

    const userData = {
      id: user.id,
      name: user.name,
      roles: userRoles,
      currentRole: role
    };

    sendSafeJSON(res, {
      token,
      user: userData
    });
  } catch (error) {
    console.error('Role switch error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Register route (clients only)
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
      return res.status(400).json({ message: 'Nome e senha são obrigatórios' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Senha deve ter pelo menos 6 caracteres' });
    }

    // Check if CPF already exists (if provided)
    if (cpf) {
      const cleanCpf = cpf.replace(/\D/g, '');
      if (cleanCpf.length !== 11) {
        return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
      }

      const existingUser = await pool.query(
        'SELECT id FROM users WHERE cpf = $1',
        [cleanCpf]
      );

      if (existingUser.rows.length > 0) {
        return res.status(409).json({ message: 'CPF já cadastrado' });
      }
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);

    // Create user
    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password_hash, roles
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) 
      RETURNING id, name, roles`,
      [
        name.trim(),
        cpf ? cpf.replace(/\D/g, '') : null,
        email ? email.trim() : null,
        phone ? phone.replace(/\D/g, '') : null,
        birth_date || null,
        address ? address.trim() : null,
        address_number ? address_number.trim() : null,
        address_complement ? address_complement.trim() : null,
        neighborhood ? neighborhood.trim() : null,
        city ? city.trim() : null,
        state || null,
        passwordHash,
        ['client']
      ]
    );

    const newUser = result.rows[0];

    sendSafeJSON(res, {
      message: 'Usuário criado com sucesso',
      user: {
        id: newUser.id,
        name: newUser.name,
        roles: newUser.roles
      }
    }, 201);
  } catch (error) {
    console.error('Registration error:', error);
    if (error.code === '23505') {
      return res.status(409).json({ message: 'CPF já cadastrado' });
    }
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Logout route
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  sendSafeJSON(res, { message: 'Logout realizado com sucesso' });
});

// ==================== USER ROUTES ====================

// Get all users (admin only)
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, cpf, email, phone, roles, subscription_status, 
        subscription_expiry, created_at, photo_url, category_name,
        professional_percentage, crm, has_scheduling_access,
        access_expires_at, access_granted_by, access_granted_at
      FROM users 
      ORDER BY created_at DESC
    `);

    const users = result.rows.map(row => ({
      id: Number(row.id),
      name: String(row.name || ''),
      cpf: String(row.cpf || ''),
      email: String(row.email || ''),
      phone: String(row.phone || ''),
      roles: Array.isArray(row.roles) ? row.roles : [],
      subscription_status: String(row.subscription_status || 'pending'),
      subscription_expiry: row.subscription_expiry ? String(row.subscription_expiry) : null,
      created_at: String(row.created_at),
      photo_url: row.photo_url ? String(row.photo_url) : null,
      category_name: row.category_name ? String(row.category_name) : null,
      professional_percentage: row.professional_percentage ? Number(row.professional_percentage) : 50,
      crm: row.crm ? String(row.crm) : null,
      has_scheduling_access: Boolean(row.has_scheduling_access),
      access_expires_at: row.access_expires_at ? String(row.access_expires_at) : null,
      access_granted_by: row.access_granted_by ? String(row.access_granted_by) : null,
      access_granted_at: row.access_granted_at ? String(row.access_granted_at) : null
    }));

    sendSafeJSON(res, users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get user by ID
app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    // Users can only access their own data unless they're admin
    if (req.user.currentRole !== 'admin' && req.user.id !== userId) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(`
      SELECT 
        id, name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, roles, 
        subscription_status, subscription_expiry, created_at, photo_url,
        category_name, professional_percentage, crm, has_scheduling_access,
        access_expires_at, access_granted_by, access_granted_at
      FROM users 
      WHERE id = $1
    `, [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];
    const userData = {
      id: Number(user.id),
      name: String(user.name || ''),
      cpf: String(user.cpf || ''),
      email: String(user.email || ''),
      phone: String(user.phone || ''),
      birth_date: user.birth_date ? String(user.birth_date) : null,
      address: String(user.address || ''),
      address_number: String(user.address_number || ''),
      address_complement: String(user.address_complement || ''),
      neighborhood: String(user.neighborhood || ''),
      city: String(user.city || ''),
      state: String(user.state || ''),
      roles: Array.isArray(user.roles) ? user.roles : [],
      subscription_status: String(user.subscription_status || 'pending'),
      subscription_expiry: user.subscription_expiry ? String(user.subscription_expiry) : null,
      created_at: String(user.created_at),
      photo_url: user.photo_url ? String(user.photo_url) : null,
      category_name: user.category_name ? String(user.category_name) : null,
      professional_percentage: user.professional_percentage ? Number(user.professional_percentage) : 50,
      crm: user.crm ? String(user.crm) : null,
      has_scheduling_access: Boolean(user.has_scheduling_access),
      access_expires_at: user.access_expires_at ? String(user.access_expires_at) : null,
      access_granted_by: user.access_granted_by ? String(user.access_granted_by) : null,
      access_granted_at: user.access_granted_at ? String(user.access_granted_at) : null
    };

    sendSafeJSON(res, userData);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get user subscription status
app.get('/api/users/:id/subscription-status', authenticate, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    // Users can only access their own data unless they're admin
    if (req.user.currentRole !== 'admin' && req.user.id !== userId) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(
      'SELECT subscription_status, subscription_expiry FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];
    sendSafeJSON(res, {
      subscription_status: String(user.subscription_status || 'pending'),
      subscription_expiry: user.subscription_expiry ? String(user.subscription_expiry) : null
    });
  } catch (error) {
    console.error('Error fetching subscription status:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create user (admin only)
app.post('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, cpf, email, phone, password, roles } = req.body;

    if (!name || !password) {
      return res.status(400).json({ message: 'Nome e senha são obrigatórios' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Senha deve ter pelo menos 6 caracteres' });
    }

    // Validate roles
    const validRoles = ['client', 'professional', 'admin'];
    const userRoles = Array.isArray(roles) ? roles : ['client'];
    
    for (const role of userRoles) {
      if (!validRoles.includes(role)) {
        return res.status(400).json({ message: `Role inválida: ${role}` });
      }
    }

    // Check if CPF already exists (if provided)
    if (cpf) {
      const cleanCpf = cpf.replace(/\D/g, '');
      if (cleanCpf.length !== 11) {
        return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
      }

      const existingUser = await pool.query(
        'SELECT id FROM users WHERE cpf = $1',
        [cleanCpf]
      );

      if (existingUser.rows.length > 0) {
        return res.status(409).json({ message: 'CPF já cadastrado' });
      }
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);

    // Create user
    const result = await pool.query(
      `INSERT INTO users (name, cpf, email, phone, password_hash, roles) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, name, cpf, email, phone, roles, created_at`,
      [
        name.trim(),
        cpf ? cpf.replace(/\D/g, '') : null,
        email ? email.trim() : null,
        phone ? phone.replace(/\D/g, '') : null,
        passwordHash,
        userRoles
      ]
    );

    const newUser = result.rows[0];
    const userData = {
      id: Number(newUser.id),
      name: String(newUser.name),
      cpf: String(newUser.cpf || ''),
      email: String(newUser.email || ''),
      phone: String(newUser.phone || ''),
      roles: Array.isArray(newUser.roles) ? newUser.roles : [],
      created_at: String(newUser.created_at)
    };

    sendSafeJSON(res, userData, 201);
  } catch (error) {
    console.error('Error creating user:', error);
    if (error.code === '23505') {
      return res.status(409).json({ message: 'CPF já cadastrado' });
    }
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update user
app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { name, email, phone, roles, currentPassword, newPassword } = req.body;

    // Users can only update their own data unless they're admin
    if (req.user.currentRole !== 'admin' && req.user.id !== userId) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    // Get current user data
    const currentUser = await pool.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [userId]
    );

    if (currentUser.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    let updateFields = [];
    let updateValues = [];
    let paramCount = 1;

    // Update basic fields
    if (name !== undefined) {
      updateFields.push(`name = $${paramCount}`);
      updateValues.push(name.trim());
      paramCount++;
    }

    if (email !== undefined) {
      updateFields.push(`email = $${paramCount}`);
      updateValues.push(email ? email.trim() : null);
      paramCount++;
    }

    if (phone !== undefined) {
      updateFields.push(`phone = $${paramCount}`);
      updateValues.push(phone ? phone.replace(/\D/g, '') : null);
      paramCount++;
    }

    // Update roles (admin only)
    if (roles !== undefined && req.user.currentRole === 'admin') {
      const validRoles = ['client', 'professional', 'admin'];
      const userRoles = Array.isArray(roles) ? roles : ['client'];
      
      for (const role of userRoles) {
        if (!validRoles.includes(role)) {
          return res.status(400).json({ message: `Role inválida: ${role}` });
        }
      }

      updateFields.push(`roles = $${paramCount}`);
      updateValues.push(userRoles);
      paramCount++;
    }

    // Update password if provided
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: 'Senha atual é obrigatória para alterar a senha' });
      }

      // Verify current password
      const isValidPassword = await bcrypt.compare(currentPassword, currentUser.rows[0].password_hash);
      if (!isValidPassword) {
        return res.status(400).json({ message: 'Senha atual incorreta' });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({ message: 'Nova senha deve ter pelo menos 6 caracteres' });
      }

      const newPasswordHash = await bcrypt.hash(newPassword, 12);
      updateFields.push(`password_hash = $${paramCount}`);
      updateValues.push(newPasswordHash);
      paramCount++;
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ message: 'Nenhum campo para atualizar' });
    }

    // Add updated_at
    updateFields.push(`updated_at = CURRENT_TIMESTAMP`);

    // Add user ID for WHERE clause
    updateValues.push(userId);

    const query = `
      UPDATE users 
      SET ${updateFields.join(', ')} 
      WHERE id = $${paramCount}
      RETURNING id, name, cpf, email, phone, roles, subscription_status, created_at
    `;

    const result = await pool.query(query, updateValues);
    const updatedUser = result.rows[0];

    const userData = {
      id: Number(updatedUser.id),
      name: String(updatedUser.name),
      cpf: String(updatedUser.cpf || ''),
      email: String(updatedUser.email || ''),
      phone: String(updatedUser.phone || ''),
      roles: Array.isArray(updatedUser.roles) ? updatedUser.roles : [],
      subscription_status: String(updatedUser.subscription_status || 'pending'),
      created_at: String(updatedUser.created_at)
    };

    sendSafeJSON(res, userData);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete user (admin only)
app.delete('/api/users/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    // Prevent admin from deleting themselves
    if (req.user.id === userId) {
      return res.status(400).json({ message: 'Não é possível excluir sua própria conta' });
    }

    const result = await pool.query(
      'DELETE FROM users WHERE id = $1 RETURNING id',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    sendSafeJSON(res, { message: 'Usuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== CLIENT ROUTES ====================

// Client lookup by CPF
app.get('/api/clients/lookup', authenticate, authorize(['professional', 'admin']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');
    if (cleanCpf.length !== 11) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
    }

    const result = await pool.query(
      `SELECT id, name, cpf, subscription_status, subscription_expiry 
       FROM users 
       WHERE cpf = $1 AND 'client' = ANY(roles)`,
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    const client = result.rows[0];
    const clientData = {
      id: Number(client.id),
      name: String(client.name),
      cpf: String(client.cpf),
      subscription_status: String(client.subscription_status || 'pending'),
      subscription_expiry: client.subscription_expiry ? String(client.subscription_expiry) : null
    };

    sendSafeJSON(res, clientData);
  } catch (error) {
    console.error('Error looking up client:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== DEPENDENT ROUTES ====================

// Get dependents by client ID
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const clientId = parseInt(req.params.clientId);

    // Clients can only access their own dependents
    if (req.user.currentRole === 'client' && req.user.id !== clientId) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(`
      SELECT 
        d.id, d.name, d.cpf, d.birth_date, d.subscription_status,
        d.subscription_expiry, d.billing_amount, d.payment_reference,
        d.activated_at, d.created_at,
        u.subscription_status as client_subscription_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      WHERE d.client_id = $1
      ORDER BY d.created_at DESC
    `, [clientId]);

    const dependents = result.rows.map(row => {
      // Calculate current status based on client and dependent status
      let currentStatus = row.subscription_status;
      if (row.client_subscription_status !== 'active') {
        currentStatus = 'inactive'; // Dependent can't be active if client isn't
      }

      return {
        id: Number(row.id),
        name: String(row.name),
        cpf: String(row.cpf),
        birth_date: row.birth_date ? String(row.birth_date) : null,
        subscription_status: String(row.subscription_status || 'pending'),
        subscription_expiry: row.subscription_expiry ? String(row.subscription_expiry) : null,
        billing_amount: Number(row.billing_amount || 50),
        payment_reference: row.payment_reference ? String(row.payment_reference) : null,
        activated_at: row.activated_at ? String(row.activated_at) : null,
        created_at: String(row.created_at),
        current_status: String(currentStatus)
      };
    });

    sendSafeJSON(res, dependents);
  } catch (error) {
    console.error('Error fetching dependents:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Dependent lookup by CPF
app.get('/api/dependents/lookup', authenticate, authorize(['professional', 'admin']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');
    if (cleanCpf.length !== 11) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
    }

    const result = await pool.query(`
      SELECT 
        d.id, d.name, d.cpf, d.client_id, d.subscription_status as dependent_subscription_status,
        u.name as client_name, u.subscription_status as client_subscription_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      WHERE d.cpf = $1
    `, [cleanCpf]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    const dependent = result.rows[0];
    const dependentData = {
      id: Number(dependent.id),
      name: String(dependent.name),
      cpf: String(dependent.cpf),
      client_id: Number(dependent.client_id),
      client_name: String(dependent.client_name),
      dependent_subscription_status: String(dependent.dependent_subscription_status || 'pending'),
      client_subscription_status: String(dependent.client_subscription_status || 'pending')
    };

    sendSafeJSON(res, dependentData);
  } catch (error) {
    console.error('Error looking up dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create dependent
app.post('/api/dependents', authenticate, checkSubscriptionStatus, async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    if (!client_id || !name || !cpf) {
      return res.status(400).json({ message: 'ID do cliente, nome e CPF são obrigatórios' });
    }

    // Clients can only create dependents for themselves
    if (req.user.currentRole === 'client' && req.user.id !== client_id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');
    if (cleanCpf.length !== 11) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
    }

    // Check if CPF already exists
    const existingCpf = await pool.query(
      'SELECT id FROM users WHERE cpf = $1 UNION SELECT id FROM dependents WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingCpf.rows.length > 0) {
      return res.status(409).json({ message: 'CPF já cadastrado' });
    }

    // Check dependent limit (10 per client)
    const dependentCount = await pool.query(
      'SELECT COUNT(*) as count FROM dependents WHERE client_id = $1',
      [client_id]
    );

    if (Number(dependentCount.rows[0].count) >= 10) {
      return res.status(400).json({ message: 'Limite máximo de 10 dependentes atingido' });
    }

    // Create dependent
    const result = await pool.query(
      `INSERT INTO dependents (client_id, name, cpf, birth_date) 
       VALUES ($1, $2, $3, $4) 
       RETURNING id, name, cpf, birth_date, subscription_status, billing_amount, created_at`,
      [client_id, name.trim(), cleanCpf, birth_date || null]
    );

    const newDependent = result.rows[0];
    const dependentData = {
      id: Number(newDependent.id),
      name: String(newDependent.name),
      cpf: String(newDependent.cpf),
      birth_date: newDependent.birth_date ? String(newDependent.birth_date) : null,
      subscription_status: String(newDependent.subscription_status || 'pending'),
      billing_amount: Number(newDependent.billing_amount || 50),
      created_at: String(newDependent.created_at)
    };

    sendSafeJSON(res, dependentData, 201);
  } catch (error) {
    console.error('Error creating dependent:', error);
    if (error.code === '23505') {
      return res.status(409).json({ message: 'CPF já cadastrado' });
    }
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update dependent
app.put('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const dependentId = parseInt(req.params.id);
    const { name, birth_date } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    // Check if dependent exists and user has permission
    const dependentCheck = await pool.query(
      'SELECT client_id FROM dependents WHERE id = $1',
      [dependentId]
    );

    if (dependentCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    const clientId = dependentCheck.rows[0].client_id;

    // Clients can only update their own dependents
    if (req.user.currentRole === 'client' && req.user.id !== clientId) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(
      `UPDATE dependents 
       SET name = $1, birth_date = $2, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $3 
       RETURNING id, name, cpf, birth_date, subscription_status, billing_amount, created_at`,
      [name.trim(), birth_date || null, dependentId]
    );

    const updatedDependent = result.rows[0];
    const dependentData = {
      id: Number(updatedDependent.id),
      name: String(updatedDependent.name),
      cpf: String(updatedDependent.cpf),
      birth_date: updatedDependent.birth_date ? String(updatedDependent.birth_date) : null,
      subscription_status: String(updatedDependent.subscription_status || 'pending'),
      billing_amount: Number(updatedDependent.billing_amount || 50),
      created_at: String(updatedDependent.created_at)
    };

    sendSafeJSON(res, dependentData);
  } catch (error) {
    console.error('Error updating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete dependent
app.delete('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const dependentId = parseInt(req.params.id);

    // Check if dependent exists and user has permission
    const dependentCheck = await pool.query(
      'SELECT client_id FROM dependents WHERE id = $1',
      [dependentId]
    );

    if (dependentCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    const clientId = dependentCheck.rows[0].client_id;

    // Clients can only delete their own dependents
    if (req.user.currentRole === 'client' && req.user.id !== clientId) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    await pool.query('DELETE FROM dependents WHERE id = $1', [dependentId]);

    sendSafeJSON(res, { message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get all dependents (admin only)
app.get('/api/admin/dependents', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        d.id, d.name, d.cpf, d.birth_date, d.subscription_status,
        d.subscription_expiry, d.billing_amount, d.activated_at, d.created_at,
        u.name as client_name, u.subscription_status as client_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      ORDER BY d.created_at DESC
    `);

    const dependents = result.rows.map(row => {
      // Calculate current status
      let currentStatus = row.subscription_status;
      if (row.client_status !== 'active') {
        currentStatus = 'inactive';
      }

      return {
        id: Number(row.id),
        client_id: Number(row.client_id),
        name: String(row.name),
        cpf: String(row.cpf),
        birth_date: row.birth_date ? String(row.birth_date) : null,
        subscription_status: String(row.subscription_status || 'pending'),
        subscription_expiry: row.subscription_expiry ? String(row.subscription_expiry) : null,
        billing_amount: Number(row.billing_amount || 50),
        client_name: String(row.client_name),
        client_status: String(row.client_status || 'pending'),
        current_status: String(currentStatus),
        activated_at: row.activated_at ? String(row.activated_at) : null,
        created_at: String(row.created_at)
      };
    });

    sendSafeJSON(res, dependents);
  } catch (error) {
    console.error('Error fetching all dependents:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Activate dependent (admin only)
app.post('/api/admin/dependents/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const dependentId = parseInt(req.params.id);

    // Check if dependent exists
    const dependentCheck = await pool.query(
      'SELECT id, client_id, subscription_status FROM dependents WHERE id = $1',
      [dependentId]
    );

    if (dependentCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    const dependent = dependentCheck.rows[0];

    if (dependent.subscription_status === 'active') {
      return res.status(400).json({ message: 'Dependente já está ativo' });
    }

    // Check if client has active subscription
    const clientCheck = await pool.query(
      'SELECT subscription_status FROM users WHERE id = $1',
      [dependent.client_id]
    );

    if (clientCheck.rows.length === 0 || clientCheck.rows[0].subscription_status !== 'active') {
      return res.status(400).json({ message: 'Cliente titular deve ter assinatura ativa' });
    }

    // Activate dependent
    const expiryDate = new Date();
    expiryDate.setFullYear(expiryDate.getFullYear() + 1); // 1 year from now

    await pool.query(`
      UPDATE dependents 
      SET 
        subscription_status = 'active',
        subscription_expiry = $1,
        activated_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
    `, [expiryDate, dependentId]);

    sendSafeJSON(res, { message: 'Dependente ativado com sucesso' });
  } catch (error) {
    console.error('Error activating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== PROFESSIONAL ROUTES ====================

// Get all professionals
app.get('/api/professionals', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, email, phone, address, address_number, address_complement,
        neighborhood, city, state, category_name, photo_url, professional_percentage,
        crm, has_scheduling_access, access_expires_at
      FROM users 
      WHERE 'professional' = ANY(roles)
      ORDER BY name
    `);

    const professionals = result.rows.map(row => ({
      id: Number(row.id),
      name: String(row.name),
      email: String(row.email || ''),
      phone: String(row.phone || ''),
      roles: ['professional'],
      address: String(row.address || ''),
      address_number: String(row.address_number || ''),
      address_complement: String(row.address_complement || ''),
      neighborhood: String(row.neighborhood || ''),
      city: String(row.city || ''),
      state: String(row.state || ''),
      category_name: String(row.category_name || ''),
      photo_url: row.photo_url ? String(row.photo_url) : null,
      professional_percentage: Number(row.professional_percentage || 50),
      crm: row.crm ? String(row.crm) : null,
      has_scheduling_access: Boolean(row.has_scheduling_access),
      access_expires_at: row.access_expires_at ? String(row.access_expires_at) : null
    }));

    sendSafeJSON(res, professionals);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get professionals with scheduling access (admin only)
app.get('/api/admin/professionals-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, email, phone, category_name, has_scheduling_access,
        access_expires_at, access_granted_by, access_granted_at
      FROM users 
      WHERE 'professional' = ANY(roles)
      ORDER BY name
    `);

    const professionals = result.rows.map(row => ({
      id: Number(row.id),
      name: String(row.name),
      email: String(row.email || ''),
      phone: String(row.phone || ''),
      category_name: String(row.category_name || ''),
      has_scheduling_access: Boolean(row.has_scheduling_access),
      access_expires_at: row.access_expires_at ? String(row.access_expires_at) : null,
      access_granted_by: row.access_granted_by ? String(row.access_granted_by) : null,
      access_granted_at: row.access_granted_at ? String(row.access_granted_at) : null
    }));

    sendSafeJSON(res, professionals);
  } catch (error) {
    console.error('Error fetching professionals scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Grant scheduling access (admin only)
app.post('/api/admin/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;

    if (!professional_id || !expires_at) {
      return res.status(400).json({ message: 'ID do profissional e data de expiração são obrigatórios' });
    }

    // Verify professional exists
    const professionalCheck = await pool.query(
      "SELECT id FROM users WHERE id = $1 AND 'professional' = ANY(roles)",
      [professional_id]
    );

    if (professionalCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    // Grant access
    await pool.query(`
      UPDATE users 
      SET 
        has_scheduling_access = TRUE,
        access_expires_at = $1,
        access_granted_by = $2,
        access_granted_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $3
    `, [expires_at, req.user.name, professional_id]);

    sendSafeJSON(res, { message: 'Acesso à agenda concedido com sucesso' });
  } catch (error) {
    console.error('Error granting scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Revoke scheduling access (admin only)
app.post('/api/admin/revoke-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id } = req.body;

    if (!professional_id) {
      return res.status(400).json({ message: 'ID do profissional é obrigatório' });
    }

    await pool.query(`
      UPDATE users 
      SET 
        has_scheduling_access = FALSE,
        access_expires_at = NULL,
        access_granted_by = NULL,
        access_granted_at = NULL,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
    `, [professional_id]);

    sendSafeJSON(res, { message: 'Acesso à agenda revogado com sucesso' });
  } catch (error) {
    console.error('Error revoking scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== SERVICE ROUTES ====================

// Get all services
app.get('/api/services', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        s.id, s.name, s.description, s.base_price, s.category_id, s.is_base_service,
        sc.name as category_name
      FROM services s
      LEFT JOIN service_categories sc ON s.category_id = sc.id
      ORDER BY sc.name, s.name
    `);

    const services = result.rows.map(row => ({
      id: Number(row.id),
      name: String(row.name),
      description: String(row.description || ''),
      base_price: Number(row.base_price),
      category_id: row.category_id ? Number(row.category_id) : null,
      category_name: row.category_name ? String(row.category_name) : null,
      is_base_service: Boolean(row.is_base_service)
    }));

    sendSafeJSON(res, services);
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create service (admin only)
app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !description || base_price === undefined) {
      return res.status(400).json({ message: 'Nome, descrição e preço base são obrigatórios' });
    }

    if (Number(base_price) <= 0) {
      return res.status(400).json({ message: 'Preço base deve ser maior que zero' });
    }

    const result = await pool.query(
      `INSERT INTO services (name, description, base_price, category_id, is_base_service) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING id, name, description, base_price, category_id, is_base_service`,
      [
        name.trim(),
        description.trim(),
        Number(base_price),
        category_id ? Number(category_id) : null,
        Boolean(is_base_service)
      ]
    );

    const newService = result.rows[0];
    const serviceData = {
      id: Number(newService.id),
      name: String(newService.name),
      description: String(newService.description),
      base_price: Number(newService.base_price),
      category_id: newService.category_id ? Number(newService.category_id) : null,
      is_base_service: Boolean(newService.is_base_service)
    };

    sendSafeJSON(res, serviceData, 201);
  } catch (error) {
    console.error('Error creating service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update service (admin only)
app.put('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const serviceId = parseInt(req.params.id);
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !description || base_price === undefined) {
      return res.status(400).json({ message: 'Nome, descrição e preço base são obrigatórios' });
    }

    if (Number(base_price) <= 0) {
      return res.status(400).json({ message: 'Preço base deve ser maior que zero' });
    }

    const result = await pool.query(
      `UPDATE services 
       SET name = $1, description = $2, base_price = $3, category_id = $4, is_base_service = $5 
       WHERE id = $6 
       RETURNING id, name, description, base_price, category_id, is_base_service`,
      [
        name.trim(),
        description.trim(),
        Number(base_price),
        category_id ? Number(category_id) : null,
        Boolean(is_base_service),
        serviceId
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    const updatedService = result.rows[0];
    const serviceData = {
      id: Number(updatedService.id),
      name: String(updatedService.name),
      description: String(updatedService.description),
      base_price: Number(updatedService.base_price),
      category_id: updatedService.category_id ? Number(updatedService.category_id) : null,
      is_base_service: Boolean(updatedService.is_base_service)
    };

    sendSafeJSON(res, serviceData);
  } catch (error) {
    console.error('Error updating service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete service (admin only)
app.delete('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const serviceId = parseInt(req.params.id);

    // Check if service is being used in consultations
    const consultationCheck = await pool.query(
      'SELECT COUNT(*) as count FROM consultations WHERE service_id = $1',
      [serviceId]
    );

    if (Number(consultationCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir serviço que possui consultas registradas' 
      });
    }

    const result = await pool.query(
      'DELETE FROM services WHERE id = $1 RETURNING id',
      [serviceId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    sendSafeJSON(res, { message: 'Serviço excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== SERVICE CATEGORY ROUTES ====================

// Get all service categories
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, description, created_at
      FROM service_categories
      ORDER BY name
    `);

    const categories = result.rows.map(row => ({
      id: Number(row.id),
      name: String(row.name),
      description: String(row.description || ''),
      created_at: String(row.created_at)
    }));

    sendSafeJSON(res, categories);
  } catch (error) {
    console.error('Error fetching service categories:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create service category (admin only)
app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name || !description) {
      return res.status(400).json({ message: 'Nome e descrição são obrigatórios' });
    }

    const result = await pool.query(
      'INSERT INTO service_categories (name, description) VALUES ($1, $2) RETURNING id, name, description, created_at',
      [name.trim(), description.trim()]
    );

    const newCategory = result.rows[0];
    const categoryData = {
      id: Number(newCategory.id),
      name: String(newCategory.name),
      description: String(newCategory.description),
      created_at: String(newCategory.created_at)
    };

    sendSafeJSON(res, categoryData, 201);
  } catch (error) {
    console.error('Error creating service category:', error);
    if (error.code === '23505') {
      return res.status(409).json({ message: 'Categoria já existe' });
    }
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== CONSULTATION ROUTES ====================

// Get consultations
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query = `
      SELECT 
        c.id, c.value, c.date, c.status, c.notes, c.created_at,
        COALESCE(u.name, d.name, pp.name) as client_name,
        s.name as service_name,
        prof.name as professional_name,
        CASE WHEN c.dependent_id IS NOT NULL THEN true ELSE false END as is_dependent
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      JOIN services s ON c.service_id = s.id
      JOIN users prof ON c.professional_id = prof.id
    `;

    let queryParams = [];

    // Filter based on user role
    if (req.user.currentRole === 'professional') {
      query += ' WHERE c.professional_id = $1';
      queryParams.push(req.user.id);
    } else if (req.user.currentRole === 'client') {
      query += ' WHERE (c.client_id = $1 OR c.dependent_id IN (SELECT id FROM dependents WHERE client_id = $1))';
      queryParams.push(req.user.id);
    }

    query += ' ORDER BY c.date DESC';

    const result = await pool.query(query, queryParams);

    const consultations = result.rows.map(row => ({
      id: Number(row.id),
      value: Number(row.value),
      date: String(row.date),
      status: String(row.status || 'completed'),
      notes: String(row.notes || ''),
      client_name: String(row.client_name || ''),
      service_name: String(row.service_name || ''),
      professional_name: String(row.professional_name || ''),
      is_dependent: Boolean(row.is_dependent),
      created_at: String(row.created_at)
    }));

    sendSafeJSON(res, consultations);
  } catch (error) {
    console.error('Error fetching consultations:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get consultations by client ID
app.get('/api/consultations/client/:clientId', authenticate, async (req, res) => {
  try {
    const clientId = parseInt(req.params.clientId);

    // Clients can only access their own consultations
    if (req.user.currentRole === 'client' && req.user.id !== clientId) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(`
      SELECT 
        c.id, c.value, c.date, c.status, c.notes, c.created_at,
        COALESCE(u.name, d.name) as client_name,
        s.name as service_name,
        prof.name as professional_name,
        CASE WHEN c.dependent_id IS NOT NULL THEN true ELSE false END as is_dependent
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      JOIN services s ON c.service_id = s.id
      JOIN users prof ON c.professional_id = prof.id
      WHERE c.client_id = $1 OR c.dependent_id IN (
        SELECT id FROM dependents WHERE client_id = $1
      )
      ORDER BY c.date DESC
    `, [clientId]);

    const consultations = result.rows.map(row => ({
      id: Number(row.id),
      value: Number(row.value),
      date: String(row.date),
      status: String(row.status || 'completed'),
      notes: String(row.notes || ''),
      client_name: String(row.client_name || ''),
      service_name: String(row.service_name || ''),
      professional_name: String(row.professional_name || ''),
      is_dependent: Boolean(row.is_dependent),
      created_at: String(row.created_at)
    }));

    sendSafeJSON(res, consultations);
  } catch (error) {
    console.error('Error fetching client consultations:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create consultation
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
      status,
      notes
    } = req.body;

    if (!service_id || !value || !date) {
      return res.status(400).json({ message: 'Serviço, valor e data são obrigatórios' });
    }

    if (Number(value) <= 0) {
      return res.status(400).json({ message: 'Valor deve ser maior que zero' });
    }

    // Validate that exactly one patient type is provided
    const patientCount = [client_id, dependent_id, private_patient_id].filter(Boolean).length;
    if (patientCount !== 1) {
      return res.status(400).json({ message: 'Deve ser especificado exatamente um tipo de paciente' });
    }

    // Verify service exists
    const serviceCheck = await pool.query(
      'SELECT id FROM services WHERE id = $1',
      [service_id]
    );

    if (serviceCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    // Create consultation
    const result = await pool.query(
      `INSERT INTO consultations (
        client_id, dependent_id, private_patient_id, professional_id, 
        service_id, location_id, value, date, status, notes
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
      RETURNING id, value, date, status, notes, created_at`,
      [
        client_id || null,
        dependent_id || null,
        private_patient_id || null,
        req.user.id,
        Number(service_id),
        location_id ? Number(location_id) : null,
        Number(value),
        date,
        status || 'completed',
        notes || null
      ]
    );

    const newConsultation = result.rows[0];
    const consultationData = {
      id: Number(newConsultation.id),
      value: Number(newConsultation.value),
      date: String(newConsultation.date),
      status: String(newConsultation.status),
      notes: String(newConsultation.notes || ''),
      created_at: String(newConsultation.created_at)
    };

    sendSafeJSON(res, consultationData, 201);
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update consultation status
app.put('/api/consultations/:id/status', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const consultationId = parseInt(req.params.id);
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ message: 'Status é obrigatório' });
    }

    const validStatuses = ['scheduled', 'confirmed', 'completed', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Status inválido' });
    }

    // Check if consultation exists and belongs to the professional
    const consultationCheck = await pool.query(
      'SELECT professional_id FROM consultations WHERE id = $1',
      [consultationId]
    );

    if (consultationCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Consulta não encontrada' });
    }

    if (consultationCheck.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    // Update status
    const result = await pool.query(
      'UPDATE consultations SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING status',
      [status, consultationId]
    );

    sendSafeJSON(res, { 
      message: 'Status atualizado com sucesso',
      status: String(result.rows[0].status)
    });
  } catch (error) {
    console.error('Error updating consultation status:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== PRIVATE PATIENT ROUTES ====================

// Get private patients for professional
app.get('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, zip_code, created_at
      FROM private_patients 
      WHERE professional_id = $1
      ORDER BY name
    `, [req.user.id]);

    const patients = result.rows.map(row => ({
      id: Number(row.id),
      name: String(row.name),
      cpf: String(row.cpf || ''),
      email: String(row.email || ''),
      phone: String(row.phone || ''),
      birth_date: row.birth_date ? String(row.birth_date) : null,
      address: String(row.address || ''),
      address_number: String(row.address_number || ''),
      address_complement: String(row.address_complement || ''),
      neighborhood: String(row.neighborhood || ''),
      city: String(row.city || ''),
      state: String(row.state || ''),
      zip_code: String(row.zip_code || ''),
      created_at: String(row.created_at)
    }));

    sendSafeJSON(res, patients);
  } catch (error) {
    console.error('Error fetching private patients:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
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
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    // Check if CPF already exists (if provided)
    if (cpf) {
      const cleanCpf = cpf.replace(/\D/g, '');
      if (cleanCpf.length !== 11) {
        return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
      }

      const existingCpf = await pool.query(
        'SELECT id FROM users WHERE cpf = $1 UNION SELECT id FROM dependents WHERE cpf = $1 UNION SELECT id FROM private_patients WHERE cpf = $1',
        [cleanCpf]
      );

      if (existingCpf.rows.length > 0) {
        return res.status(409).json({ message: 'CPF já cadastrado' });
      }
    }

    const result = await pool.query(
      `INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date, address,
        address_number, address_complement, neighborhood, city, state, zip_code
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) 
      RETURNING id, name, cpf, email, phone, birth_date, created_at`,
      [
        req.user.id,
        name.trim(),
        cpf ? cpf.replace(/\D/g, '') : null,
        email ? email.trim() : null,
        phone ? phone.replace(/\D/g, '') : null,
        birth_date || null,
        address ? address.trim() : null,
        address_number ? address_number.trim() : null,
        address_complement ? address_complement.trim() : null,
        neighborhood ? neighborhood.trim() : null,
        city ? city.trim() : null,
        state || null,
        zip_code ? zip_code.replace(/\D/g, '') : null
      ]
    );

    const newPatient = result.rows[0];
    const patientData = {
      id: Number(newPatient.id),
      name: String(newPatient.name),
      cpf: String(newPatient.cpf || ''),
      email: String(newPatient.email || ''),
      phone: String(newPatient.phone || ''),
      birth_date: newPatient.birth_date ? String(newPatient.birth_date) : null,
      created_at: String(newPatient.created_at)
    };

    sendSafeJSON(res, patientData, 201);
  } catch (error) {
    console.error('Error creating private patient:', error);
    if (error.code === '23505') {
      return res.status(409).json({ message: 'CPF já cadastrado' });
    }
    res.status(500).json({ message: 'Erro interno do servidor' });
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

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    // Check if patient exists and belongs to the professional
    const patientCheck = await pool.query(
      'SELECT professional_id FROM private_patients WHERE id = $1',
      [patientId]
    );

    if (patientCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    if (patientCheck.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(
      `UPDATE private_patients 
       SET name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
           address_number = $6, address_complement = $7, neighborhood = $8,
           city = $9, state = $10, zip_code = $11, updated_at = CURRENT_TIMESTAMP
       WHERE id = $12 
       RETURNING id, name, cpf, email, phone, birth_date, created_at`,
      [
        name.trim(),
        email ? email.trim() : null,
        phone ? phone.replace(/\D/g, '') : null,
        birth_date || null,
        address ? address.trim() : null,
        address_number ? address_number.trim() : null,
        address_complement ? address_complement.trim() : null,
        neighborhood ? neighborhood.trim() : null,
        city ? city.trim() : null,
        state || null,
        zip_code ? zip_code.replace(/\D/g, '') : null,
        patientId
      ]
    );

    const updatedPatient = result.rows[0];
    const patientData = {
      id: Number(updatedPatient.id),
      name: String(updatedPatient.name),
      cpf: String(updatedPatient.cpf || ''),
      email: String(updatedPatient.email || ''),
      phone: String(updatedPatient.phone || ''),
      birth_date: updatedPatient.birth_date ? String(updatedPatient.birth_date) : null,
      created_at: String(updatedPatient.created_at)
    };

    sendSafeJSON(res, patientData);
  } catch (error) {
    console.error('Error updating private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete private patient
app.delete('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const patientId = parseInt(req.params.id);

    // Check if patient exists and belongs to the professional
    const patientCheck = await pool.query(
      'SELECT professional_id FROM private_patients WHERE id = $1',
      [patientId]
    );

    if (patientCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    if (patientCheck.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    // Check if patient has consultations
    const consultationCheck = await pool.query(
      'SELECT COUNT(*) as count FROM consultations WHERE private_patient_id = $1',
      [patientId]
    );

    if (Number(consultationCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir paciente que possui consultas registradas' 
      });
    }

    await pool.query('DELETE FROM private_patients WHERE id = $1', [patientId]);

    sendSafeJSON(res, { message: 'Paciente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== ATTENDANCE LOCATION ROUTES ====================

// Get attendance locations for professional
app.get('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default, created_at
      FROM attendance_locations 
      WHERE professional_id = $1
      ORDER BY is_default DESC, name
    `, [req.user.id]);

    const locations = result.rows.map(row => ({
      id: Number(row.id),
      name: String(row.name),
      address: String(row.address || ''),
      address_number: String(row.address_number || ''),
      address_complement: String(row.address_complement || ''),
      neighborhood: String(row.neighborhood || ''),
      city: String(row.city || ''),
      state: String(row.state || ''),
      zip_code: String(row.zip_code || ''),
      phone: String(row.phone || ''),
      is_default: Boolean(row.is_default),
      created_at: String(row.created_at)
    }));

    sendSafeJSON(res, locations);
  } catch (error) {
    console.error('Error fetching attendance locations:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create attendance location
app.post('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    // If setting as default, remove default from other locations
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
      RETURNING id, name, address, is_default, created_at`,
      [
        req.user.id,
        name.trim(),
        address ? address.trim() : null,
        address_number ? address_number.trim() : null,
        address_complement ? address_complement.trim() : null,
        neighborhood ? neighborhood.trim() : null,
        city ? city.trim() : null,
        state || null,
        zip_code ? zip_code.replace(/\D/g, '') : null,
        phone ? phone.replace(/\D/g, '') : null,
        Boolean(is_default)
      ]
    );

    const newLocation = result.rows[0];
    const locationData = {
      id: Number(newLocation.id),
      name: String(newLocation.name),
      address: String(newLocation.address || ''),
      is_default: Boolean(newLocation.is_default),
      created_at: String(newLocation.created_at)
    };

    sendSafeJSON(res, locationData, 201);
  } catch (error) {
    console.error('Error creating attendance location:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update attendance location
app.put('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const locationId = parseInt(req.params.id);
    const {
      name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    // Check if location exists and belongs to the professional
    const locationCheck = await pool.query(
      'SELECT professional_id FROM attendance_locations WHERE id = $1',
      [locationId]
    );

    if (locationCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Local não encontrado' });
    }

    if (locationCheck.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    // If setting as default, remove default from other locations
    if (is_default) {
      await pool.query(
        'UPDATE attendance_locations SET is_default = FALSE WHERE professional_id = $1 AND id != $2',
        [req.user.id, locationId]
      );
    }

    const result = await pool.query(
      `UPDATE attendance_locations 
       SET name = $1, address = $2, address_number = $3, address_complement = $4,
           neighborhood = $5, city = $6, state = $7, zip_code = $8, phone = $9, is_default = $10
       WHERE id = $11 
       RETURNING id, name, address, is_default`,
      [
        name.trim(),
        address ? address.trim() : null,
        address_number ? address_number.trim() : null,
        address_complement ? address_complement.trim() : null,
        neighborhood ? neighborhood.trim() : null,
        city ? city.trim() : null,
        state || null,
        zip_code ? zip_code.replace(/\D/g, '') : null,
        phone ? phone.replace(/\D/g, '') : null,
        Boolean(is_default),
        locationId
      ]
    );

    const updatedLocation = result.rows[0];
    const locationData = {
      id: Number(updatedLocation.id),
      name: String(updatedLocation.name),
      address: String(updatedLocation.address || ''),
      is_default: Boolean(updatedLocation.is_default)
    };

    sendSafeJSON(res, locationData);
  } catch (error) {
    console.error('Error updating attendance location:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete attendance location
app.delete('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const locationId = parseInt(req.params.id);

    // Check if location exists and belongs to the professional
    const locationCheck = await pool.query(
      'SELECT professional_id FROM attendance_locations WHERE id = $1',
      [locationId]
    );

    if (locationCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Local não encontrado' });
    }

    if (locationCheck.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    await pool.query('DELETE FROM attendance_locations WHERE id = $1', [locationId]);

    sendSafeJSON(res, { message: 'Local excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting attendance location:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== MEDICAL RECORD ROUTES ====================

// Get medical records for professional
app.get('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        mr.id, mr.chief_complaint, mr.history_present_illness, mr.past_medical_history,
        mr.medications, mr.allergies, mr.physical_examination, mr.diagnosis,
        mr.treatment_plan, mr.notes, mr.vital_signs, mr.created_at, mr.updated_at,
        pp.name as patient_name
      FROM medical_records mr
      JOIN private_patients pp ON mr.private_patient_id = pp.id
      WHERE mr.professional_id = $1
      ORDER BY mr.created_at DESC
    `, [req.user.id]);

    const records = result.rows.map(row => ({
      id: Number(row.id),
      patient_name: String(row.patient_name),
      chief_complaint: String(row.chief_complaint || ''),
      history_present_illness: String(row.history_present_illness || ''),
      past_medical_history: String(row.past_medical_history || ''),
      medications: String(row.medications || ''),
      allergies: String(row.allergies || ''),
      physical_examination: String(row.physical_examination || ''),
      diagnosis: String(row.diagnosis || ''),
      treatment_plan: String(row.treatment_plan || ''),
      notes: String(row.notes || ''),
      vital_signs: row.vital_signs || {},
      created_at: String(row.created_at),
      updated_at: String(row.updated_at)
    }));

    sendSafeJSON(res, records);
  } catch (error) {
    console.error('Error fetching medical records:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
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
      return res.status(400).json({ message: 'ID do paciente é obrigatório' });
    }

    // Verify patient exists and belongs to the professional
    const patientCheck = await pool.query(
      'SELECT id FROM private_patients WHERE id = $1 AND professional_id = $2',
      [private_patient_id, req.user.id]
    );

    if (patientCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    const result = await pool.query(
      `INSERT INTO medical_records (
        professional_id, private_patient_id, chief_complaint, history_present_illness,
        past_medical_history, medications, allergies, physical_examination,
        diagnosis, treatment_plan, notes, vital_signs
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) 
      RETURNING id, created_at`,
      [
        req.user.id,
        Number(private_patient_id),
        chief_complaint || null,
        history_present_illness || null,
        past_medical_history || null,
        medications || null,
        allergies || null,
        physical_examination || null,
        diagnosis || null,
        treatment_plan || null,
        notes || null,
        vital_signs ? JSON.stringify(vital_signs) : null
      ]
    );

    const newRecord = result.rows[0];
    const recordData = {
      id: Number(newRecord.id),
      created_at: String(newRecord.created_at)
    };

    sendSafeJSON(res, recordData, 201);
  } catch (error) {
    console.error('Error creating medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
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

    // Check if record exists and belongs to the professional
    const recordCheck = await pool.query(
      'SELECT professional_id FROM medical_records WHERE id = $1',
      [recordId]
    );

    if (recordCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    if (recordCheck.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(
      `UPDATE medical_records 
       SET chief_complaint = $1, history_present_illness = $2, past_medical_history = $3,
           medications = $4, allergies = $5, physical_examination = $6, diagnosis = $7,
           treatment_plan = $8, notes = $9, vital_signs = $10, updated_at = CURRENT_TIMESTAMP
       WHERE id = $11 
       RETURNING id, updated_at`,
      [
        chief_complaint || null,
        history_present_illness || null,
        past_medical_history || null,
        medications || null,
        allergies || null,
        physical_examination || null,
        diagnosis || null,
        treatment_plan || null,
        notes || null,
        vital_signs ? JSON.stringify(vital_signs) : null,
        recordId
      ]
    );

    const updatedRecord = result.rows[0];
    const recordData = {
      id: Number(updatedRecord.id),
      updated_at: String(updatedRecord.updated_at)
    };

    sendSafeJSON(res, recordData);
  } catch (error) {
    console.error('Error updating medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete medical record
app.delete('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const recordId = parseInt(req.params.id);

    // Check if record exists and belongs to the professional
    const recordCheck = await pool.query(
      'SELECT professional_id FROM medical_records WHERE id = $1',
      [recordId]
    );

    if (recordCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    if (recordCheck.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    await pool.query('DELETE FROM medical_records WHERE id = $1', [recordId]);

    sendSafeJSON(res, { message: 'Prontuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Generate medical record document
app.post('/api/medical-records/generate-document', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { record_id, template_data } = req.body;

    if (!record_id || !template_data) {
      return res.status(400).json({ message: 'ID do prontuário e dados do template são obrigatórios' });
    }

    // Verify record exists and belongs to the professional
    const recordCheck = await pool.query(
      'SELECT professional_id FROM medical_records WHERE id = $1',
      [record_id]
    );

    if (recordCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    if (recordCheck.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    // Generate document
    const documentResult = await generateDocumentPDF('medical_record', template_data);

    sendSafeJSON(res, {
      message: 'Documento gerado com sucesso',
      documentUrl: documentResult.url
    });
  } catch (error) {
    console.error('Error generating medical record document:', error);
    res.status(500).json({ message: 'Erro ao gerar documento' });
  }
});

// ==================== MEDICAL DOCUMENT ROUTES ====================

// Get medical documents for professional
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        md.id, md.title, md.document_type, md.document_url, md.created_at,
        pp.name as patient_name
      FROM medical_documents md
      LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
      WHERE md.professional_id = $1
      ORDER BY md.created_at DESC
    `, [req.user.id]);

    const documents = result.rows.map(row => ({
      id: Number(row.id),
      title: String(row.title),
      document_type: String(row.document_type),
      patient_name: String(row.patient_name || 'N/A'),
      document_url: String(row.document_url),
      created_at: String(row.created_at)
    }));

    sendSafeJSON(res, documents);
  } catch (error) {
    console.error('Error fetching medical documents:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create medical document
app.post('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { title, document_type, private_patient_id, template_data } = req.body;

    if (!title || !document_type || !template_data) {
      return res.status(400).json({ message: 'Título, tipo de documento e dados do template são obrigatórios' });
    }

    // Verify patient exists and belongs to the professional (if provided)
    if (private_patient_id) {
      const patientCheck = await pool.query(
        'SELECT id FROM private_patients WHERE id = $1 AND professional_id = $2',
        [private_patient_id, req.user.id]
      );

      if (patientCheck.rows.length === 0) {
        return res.status(404).json({ message: 'Paciente não encontrado' });
      }
    }

    // Generate document
    const documentResult = await generateDocumentPDF(document_type, template_data);

    // Save document record
    const result = await pool.query(
      `INSERT INTO medical_documents (
        professional_id, private_patient_id, title, document_type, document_url, template_data
      ) VALUES ($1, $2, $3, $4, $5, $6) 
      RETURNING id, title, document_url, created_at`,
      [
        req.user.id,
        private_patient_id || null,
        title.trim(),
        document_type,
        documentResult.url,
        JSON.stringify(template_data)
      ]
    );

    const newDocument = result.rows[0];
    const documentData = {
      id: Number(newDocument.id),
      title: String(newDocument.title),
      documentUrl: String(newDocument.document_url),
      created_at: String(newDocument.created_at)
    };

    sendSafeJSON(res, documentData, 201);
  } catch (error) {
    console.error('Error creating medical document:', error);
    res.status(500).json({ message: 'Erro ao criar documento' });
  }
});

// ==================== REPORT ROUTES ====================

// Revenue report (admin only)
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    // Get revenue by professional
    const professionalResult = await pool.query(`
      SELECT 
        prof.name as professional_name,
        prof.professional_percentage,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count,
        SUM(c.value * (prof.professional_percentage / 100)) as professional_payment,
        SUM(c.value * ((100 - prof.professional_percentage) / 100)) as clinic_revenue
      FROM consultations c
      JOIN users prof ON c.professional_id = prof.id
      WHERE c.date >= $1 AND c.date <= $2
      GROUP BY prof.id, prof.name, prof.professional_percentage
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    // Get revenue by service
    const serviceResult = await pool.query(`
      SELECT 
        s.name as service_name,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      WHERE c.date >= $1 AND c.date <= $2
      GROUP BY s.id, s.name
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    // Calculate total revenue
    const totalResult = await pool.query(`
      SELECT SUM(value) as total_revenue
      FROM consultations
      WHERE date >= $1 AND date <= $2
    `, [start_date, end_date]);

    const revenueByProfessional = professionalResult.rows.map(row => ({
      professional_name: String(row.professional_name),
      professional_percentage: Number(row.professional_percentage || 50),
      revenue: Number(row.revenue || 0),
      consultation_count: Number(row.consultation_count || 0),
      professional_payment: Number(row.professional_payment || 0),
      clinic_revenue: Number(row.clinic_revenue || 0)
    }));

    const revenueByService = serviceResult.rows.map(row => ({
      service_name: String(row.service_name),
      revenue: Number(row.revenue || 0),
      consultation_count: Number(row.consultation_count || 0)
    }));

    const reportData = {
      total_revenue: Number(totalResult.rows[0]?.total_revenue || 0),
      revenue_by_professional: revenueByProfessional,
      revenue_by_service: revenueByService
    };

    sendSafeJSON(res, reportData);
  } catch (error) {
    console.error('Error generating revenue report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Professional revenue report
app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    // Get professional percentage
    const professionalResult = await pool.query(
      'SELECT professional_percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = Number(professionalResult.rows[0]?.professional_percentage || 50);

    // Get consultations for the period
    const consultationsResult = await pool.query(`
      SELECT 
        c.date, c.value,
        COALESCE(u.name, d.name, pp.name) as client_name,
        s.name as service_name,
        CASE 
          WHEN c.private_patient_id IS NOT NULL THEN c.value
          ELSE c.value * ($3 / 100)
        END as amount_to_pay
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      JOIN services s ON c.service_id = s.id
      WHERE c.professional_id = $1 AND c.date >= $2 AND c.date <= $4
      ORDER BY c.date DESC
    `, [req.user.id, start_date, 100 - professionalPercentage, end_date]);

    // Calculate summary
    const totalRevenue = consultationsResult.rows.reduce((sum, row) => sum + Number(row.value), 0);
    const totalAmountToPay = consultationsResult.rows.reduce((sum, row) => sum + Number(row.amount_to_pay), 0);

    const consultations = consultationsResult.rows.map(row => ({
      date: String(row.date),
      client_name: String(row.client_name || ''),
      service_name: String(row.service_name || ''),
      total_value: Number(row.value),
      amount_to_pay: Number(row.amount_to_pay)
    }));

    const reportData = {
      summary: {
        professional_percentage: professionalPercentage,
        total_revenue: totalRevenue,
        consultation_count: consultationsResult.rows.length,
        amount_to_pay: totalAmountToPay
      },
      consultations: consultations
    };

    sendSafeJSON(res, reportData);
  } catch (error) {
    console.error('Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Professional detailed report
app.get('/api/reports/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    // Get professional percentage
    const professionalResult = await pool.query(
      'SELECT professional_percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = Number(professionalResult.rows[0]?.professional_percentage || 50);

    // Get detailed statistics
    const statsResult = await pool.query(`
      SELECT 
        COUNT(*) as total_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        SUM(c.value) as total_revenue,
        SUM(CASE WHEN c.private_patient_id IS NULL THEN c.value ELSE 0 END) as convenio_revenue,
        SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END) as private_revenue,
        SUM(CASE WHEN c.private_patient_id IS NULL THEN c.value * ((100 - $3) / 100) ELSE 0 END) as amount_to_pay
      FROM consultations c
      WHERE c.professional_id = $1 AND c.date >= $2 AND c.date <= $4
    `, [req.user.id, start_date, professionalPercentage, end_date]);

    const stats = statsResult.rows[0];

    const reportData = {
      summary: {
        total_consultations: Number(stats.total_consultations || 0),
        convenio_consultations: Number(stats.convenio_consultations || 0),
        private_consultations: Number(stats.private_consultations || 0),
        total_revenue: Number(stats.total_revenue || 0),
        convenio_revenue: Number(stats.convenio_revenue || 0),
        private_revenue: Number(stats.private_revenue || 0),
        professional_percentage: professionalPercentage,
        amount_to_pay: Number(stats.amount_to_pay || 0)
      }
    };

    sendSafeJSON(res, reportData);
  } catch (error) {
    console.error('Error generating professional detailed report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Clients by city report (admin only)
app.get('/api/reports/clients-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        city, state,
        COUNT(*) as client_count,
        COUNT(CASE WHEN subscription_status = 'active' THEN 1 END) as active_clients,
        COUNT(CASE WHEN subscription_status = 'pending' THEN 1 END) as pending_clients,
        COUNT(CASE WHEN subscription_status = 'expired' THEN 1 END) as expired_clients
      FROM users 
      WHERE 'client' = ANY(roles) AND city IS NOT NULL AND city != ''
      GROUP BY city, state
      ORDER BY client_count DESC, city
    `);

    const cityReport = result.rows.map(row => ({
      city: String(row.city),
      state: String(row.state || ''),
      client_count: Number(row.client_count),
      active_clients: Number(row.active_clients || 0),
      pending_clients: Number(row.pending_clients || 0),
      expired_clients: Number(row.expired_clients || 0)
    }));

    sendSafeJSON(res, cityReport);
  } catch (error) {
    console.error('Error generating clients by city report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Professionals by city report (admin only)
app.get('/api/reports/professionals-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        city, state,
        COUNT(*) as total_professionals,
        ARRAY_AGG(DISTINCT category_name) FILTER (WHERE category_name IS NOT NULL) as categories
      FROM users 
      WHERE 'professional' = ANY(roles) AND city IS NOT NULL AND city != ''
      GROUP BY city, state
      ORDER BY total_professionals DESC, city
    `);

    const cityReport = result.rows.map(row => {
      const categories = (row.categories || []).map(cat => ({
        category_name: String(cat),
        count: 1 // This would need a more complex query to get actual counts
      }));

      return {
        city: String(row.city),
        state: String(row.state || ''),
        total_professionals: Number(row.total_professionals),
        categories: categories
      };
    });

    sendSafeJSON(res, cityReport);
  } catch (error) {
    console.error('Error generating professionals by city report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== PAYMENT ROUTES (PRESERVED - DO NOT MODIFY) ====================

// Import MercadoPago SDK
import mercadopago from 'mercadopago';

// Configure MercadoPago
mercadopago.configure({
  access_token: process.env.MP_ACCESS_TOKEN
});

// Create subscription payment
app.post('/api/create-subscription', authenticate, async (req, res) => {
  try {
    const { user_id } = req.body;

    if (!user_id) {
      return res.status(400).json({ message: 'ID do usuário é obrigatório' });
    }

    // Verify user exists and is a client
    const userResult = await pool.query(
      "SELECT id, name, email, subscription_status FROM users WHERE id = $1 AND 'client' = ANY(roles)",
      [user_id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    const user = userResult.rows[0];

    // Check if user already has active subscription
    if (user.subscription_status === 'active') {
      return res.status(400).json({ message: 'Cliente já possui assinatura ativa' });
    }

    // Create payment record
    const paymentResult = await pool.query(
      `INSERT INTO client_payments (client_id, amount, payment_status, external_reference) 
       VALUES ($1, $2, 'pending', $3) 
       RETURNING id`,
      [user_id, 250.00, `client_${user_id}_${Date.now()}`]
    );

    const paymentId = paymentResult.rows[0].id;

    // Create MercadoPago preference
    const preference = {
      items: [
        {
          title: 'Assinatura Cartão Quiro Ferreira',
          quantity: 1,
          unit_price: 250.00,
          currency_id: 'BRL'
        }
      ],
      payer: {
        name: user.name,
        email: user.email || 'cliente@cartaoquiroferreira.com.br'
      },
      back_urls: {
        success: 'https://cartaoquiroferreira.com.br/client?payment=success&type=subscription',
        failure: 'https://cartaoquiroferreira.com.br/client?payment=failure&type=subscription',
        pending: 'https://cartaoquiroferreira.com.br/client?payment=pending&type=subscription'
      },
      auto_return: 'approved',
      external_reference: `client_${user_id}_${Date.now()}`,
      notification_url: 'https://cartaoquiroferreira.com.br/api/webhook/mercadopago'
    };

    const response = await mercadopago.preferences.create(preference);

    // Update payment record with preference ID
    await pool.query(
      'UPDATE client_payments SET preference_id = $1 WHERE id = $2',
      [response.body.id, paymentId]
    );

    sendSafeJSON(res, {
      init_point: response.body.init_point,
      preference_id: response.body.id
    });
  } catch (error) {
    console.error('Error creating subscription payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento' });
  }
});

// Create dependent payment
app.post('/api/dependents/:id/create-payment', authenticate, async (req, res) => {
  try {
    const dependentId = parseInt(req.params.id);

    // Get dependent and client info
    const dependentResult = await pool.query(`
      SELECT d.id, d.name, d.client_id, d.billing_amount, u.name as client_name, u.email as client_email
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      WHERE d.id = $1
    `, [dependentId]);

    if (dependentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    const dependent = dependentResult.rows[0];

    // Check if user has permission
    if (req.user.currentRole === 'client' && req.user.id !== dependent.client_id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    // Create payment record
    const paymentResult = await pool.query(
      `INSERT INTO dependent_payments (dependent_id, amount, payment_status, external_reference) 
       VALUES ($1, $2, 'pending', $3) 
       RETURNING id`,
      [dependentId, dependent.billing_amount, `dependent_${dependentId}_${Date.now()}`]
    );

    const paymentId = paymentResult.rows[0].id;

    // Create MercadoPago preference
    const preference = {
      items: [
        {
          title: `Ativação Dependente - ${dependent.name}`,
          quantity: 1,
          unit_price: Number(dependent.billing_amount),
          currency_id: 'BRL'
        }
      ],
      payer: {
        name: dependent.client_name,
        email: dependent.client_email || 'cliente@cartaoquiroferreira.com.br'
      },
      back_urls: {
        success: 'https://cartaoquiroferreira.com.br/client?payment=success&type=dependent',
        failure: 'https://cartaoquiroferreira.com.br/client?payment=failure&type=dependent',
        pending: 'https://cartaoquiroferreira.com.br/client?payment=pending&type=dependent'
      },
      auto_return: 'approved',
      external_reference: `dependent_${dependentId}_${Date.now()}`,
      notification_url: 'https://cartaoquiroferreira.com.br/api/webhook/mercadopago'
    };

    const response = await mercadopago.preferences.create(preference);

    // Update payment record with preference ID
    await pool.query(
      'UPDATE dependent_payments SET preference_id = $1 WHERE id = $2',
      [response.body.id, paymentId]
    );

    sendSafeJSON(res, {
      init_point: response.body.init_point,
      preference_id: response.body.id
    });
  } catch (error) {
    console.error('Error creating dependent payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento' });
  }
});

// Create professional payment
app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || Number(amount) <= 0) {
      return res.status(400).json({ message: 'Valor deve ser maior que zero' });
    }

    // Get professional info
    const professionalResult = await pool.query(
      'SELECT name, email FROM users WHERE id = $1',
      [req.user.id]
    );

    if (professionalResult.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professional = professionalResult.rows[0];

    // Create payment record
    const paymentResult = await pool.query(
      `INSERT INTO professional_payments (professional_id, amount, payment_status, external_reference) 
       VALUES ($1, $2, 'pending', $3) 
       RETURNING id`,
      [req.user.id, Number(amount), `professional_${req.user.id}_${Date.now()}`]
    );

    const paymentId = paymentResult.rows[0].id;

    // Create MercadoPago preference
    const preference = {
      items: [
        {
          title: 'Repasse ao Convênio Quiro Ferreira',
          quantity: 1,
          unit_price: Number(amount),
          currency_id: 'BRL'
        }
      ],
      payer: {
        name: professional.name,
        email: professional.email || 'profissional@cartaoquiroferreira.com.br'
      },
      back_urls: {
        success: 'https://cartaoquiroferreira.com.br/professional?payment=success&type=professional',
        failure: 'https://cartaoquiroferreira.com.br/professional?payment=failure&type=professional',
        pending: 'https://cartaoquiroferreira.com.br/professional?payment=pending&type=professional'
      },
      auto_return: 'approved',
      external_reference: `professional_${req.user.id}_${Date.now()}`,
      notification_url: 'https://cartaoquiroferreira.com.br/api/webhook/mercadopago'
    };

    const response = await mercadopago.preferences.create(preference);

    // Update payment record with preference ID
    await pool.query(
      'UPDATE professional_payments SET preference_id = $1 WHERE id = $2',
      [response.body.id, paymentId]
    );

    sendSafeJSON(res, {
      init_point: response.body.init_point,
      preference_id: response.body.id
    });
  } catch (error) {
    console.error('Error creating professional payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento' });
  }
});

// MercadoPago webhook
app.post('/api/webhook/mercadopago', async (req, res) => {
  try {
    console.log('🔔 MercadoPago webhook received:', req.body);

    const { type, data } = req.body;

    if (type === 'payment') {
      const paymentId = data.id;
      
      // Get payment details from MercadoPago
      const payment = await mercadopago.payment.findById(paymentId);
      console.log('💳 Payment details:', payment.body);

      const paymentData = payment.body;
      const externalReference = paymentData.external_reference;
      const status = paymentData.status;

      if (!externalReference) {
        console.warn('⚠️ No external reference found');
        return sendSafeJSON(res, { received: true });
      }

      // Determine payment type and process accordingly
      if (externalReference.startsWith('client_')) {
        await processClientPayment(paymentData, externalReference);
      } else if (externalReference.startsWith('dependent_')) {
        await processDependentPayment(paymentData, externalReference);
      } else if (externalReference.startsWith('professional_')) {
        await processProfessionalPayment(paymentData, externalReference);
      } else if (externalReference.startsWith('agenda_')) {
        await processAgendaPayment(paymentData, externalReference);
      }
    }

    sendSafeJSON(res, { received: true });
  } catch (error) {
    console.error('❌ Webhook error:', error);
    res.status(500).json({ message: 'Erro no webhook' });
  }
});

// Process client payment
async function processClientPayment(paymentData, externalReference) {
  try {
    const paymentStatus = paymentData.status === 'approved' ? 'approved' : 
                         paymentData.status === 'pending' ? 'pending' : 'failed';

    // Update payment record
    await pool.query(`
      UPDATE client_payments 
      SET payment_status = $1, payment_id = $2, processed_at = CURRENT_TIMESTAMP
      WHERE external_reference = $3
    `, [paymentStatus, paymentData.id.toString(), externalReference]);

    // If approved, activate client subscription
    if (paymentStatus === 'approved') {
      const clientId = externalReference.split('_')[1];
      const expiryDate = new Date();
      expiryDate.setFullYear(expiryDate.getFullYear() + 1);

      await pool.query(`
        UPDATE users 
        SET subscription_status = 'active', subscription_expiry = $1
        WHERE id = $2
      `, [expiryDate, clientId]);

      console.log('✅ Client subscription activated:', clientId);
    }
  } catch (error) {
    console.error('❌ Error processing client payment:', error);
  }
}

// Process dependent payment
async function processDependentPayment(paymentData, externalReference) {
  try {
    const paymentStatus = paymentData.status === 'approved' ? 'approved' : 
                         paymentData.status === 'pending' ? 'pending' : 'failed';

    // Update payment record
    await pool.query(`
      UPDATE dependent_payments 
      SET payment_status = $1, payment_id = $2, processed_at = CURRENT_TIMESTAMP
      WHERE external_reference = $3
    `, [paymentStatus, paymentData.id.toString(), externalReference]);

    // If approved, activate dependent
    if (paymentStatus === 'approved') {
      const dependentId = externalReference.split('_')[1];
      const expiryDate = new Date();
      expiryDate.setFullYear(expiryDate.getFullYear() + 1);

      await pool.query(`
        UPDATE dependents 
        SET subscription_status = 'active', subscription_expiry = $1, activated_at = CURRENT_TIMESTAMP
        WHERE id = $2
      `, [expiryDate, dependentId]);

      console.log('✅ Dependent activated:', dependentId);
    }
  } catch (error) {
    console.error('❌ Error processing dependent payment:', error);
  }
}

// Process professional payment
async function processProfessionalPayment(paymentData, externalReference) {
  try {
    const paymentStatus = paymentData.status === 'approved' ? 'approved' : 
                         paymentData.status === 'pending' ? 'pending' : 'failed';

    // Update payment record
    await pool.query(`
      UPDATE professional_payments 
      SET payment_status = $1, payment_id = $2, processed_at = CURRENT_TIMESTAMP
      WHERE external_reference = $3
    `, [paymentStatus, paymentData.id.toString(), externalReference]);

    console.log('✅ Professional payment processed:', externalReference);
  } catch (error) {
    console.error('❌ Error processing professional payment:', error);
  }
}

// Process agenda payment
async function processAgendaPayment(paymentData, externalReference) {
  try {
    const paymentStatus = paymentData.status === 'approved' ? 'approved' : 
                         paymentData.status === 'pending' ? 'pending' : 'failed';

    // Update payment record
    await pool.query(`
      UPDATE agenda_payments 
      SET payment_status = $1, payment_id = $2, processed_at = CURRENT_TIMESTAMP
      WHERE external_reference = $3
    `, [paymentStatus, paymentData.id.toString(), externalReference]);

    console.log('✅ Agenda payment processed:', externalReference);
  } catch (error) {
    console.error('❌ Error processing agenda payment:', error);
  }
}

// ==================== IMAGE UPLOAD ROUTE ====================

// Upload image route
app.post('/api/upload-image', authenticate, async (req, res) => {
  try {
    // Create upload middleware instance
    const upload = createUpload();
    
    // Use multer middleware
    upload.single('image')(req, res, async (err) => {
      if (err) {
        console.error('❌ Upload error:', err);
        return res.status(400).json({ 
          message: err.message || 'Erro no upload da imagem' 
        });
      }

      if (!req.file) {
        return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
      }

      try {
        console.log('✅ Image uploaded successfully:', req.file.path);

        // Update user photo URL
        await pool.query(
          'UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
          [req.file.path, req.user.id]
        );

        sendSafeJSON(res, {
          message: 'Imagem enviada com sucesso',
          imageUrl: req.file.path
        });
      } catch (dbError) {
        console.error('❌ Database error after upload:', dbError);
        res.status(500).json({ message: 'Erro ao salvar URL da imagem' });
      }
    });
  } catch (error) {
    console.error('❌ Upload route error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== ERROR HANDLING ====================

// Global error handler
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);
  
  if (res.headersSent) {
    return next(error);
  }
  
  res.status(500).json({ 
    message: 'Erro interno do servidor',
    error: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Rota não encontrada' });
});

// ==================== SERVER STARTUP ====================

const startServer = async () => {
  try {
    // Initialize database
    await initializeDatabase();
    
    // Start server
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`📊 Database: Connected`);
      console.log(`💳 MercadoPago: ${process.env.MP_ACCESS_TOKEN ? 'Configured' : 'Not configured'}`);
      console.log(`☁️ Cloudinary: ${process.env.CLOUDINARY_CLOUD_NAME ? 'Configured' : 'Not configured'}`);
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