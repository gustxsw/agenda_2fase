import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';
import createUpload from './middleware/upload.js';
import { generateDocumentPDF } from './utils/documentGenerator.js';
import { MercadoPagoConfig, Preference, Payment } from 'mercadopago';

// ES6 module compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// CORS configuration for production
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:3000',
      'https://cartaoquiroferreira.com.br',
      'https://www.cartaoquiroferreira.com.br',
      'https://convenioquiroferreira.onrender.com'
    ];
    
    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

// Serve static files from dist directory
app.use(express.static(path.join(process.cwd(), 'dist')));

// Initialize MercadoPago
let mercadoPagoClient = null;
try {
  if (process.env.MP_ACCESS_TOKEN) {
    mercadoPagoClient = new MercadoPagoConfig({
      accessToken: process.env.MP_ACCESS_TOKEN,
      options: {
        timeout: 5000,
        idempotencyKey: 'abc'
      }
    });
    console.log('✅ MercadoPago SDK v2 initialized successfully');
  } else {
    console.warn('⚠️ MercadoPago access token not found');
  }
} catch (error) {
  console.error('❌ Error initializing MercadoPago:', error);
}

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    mercadoPago: !!mercadoPagoClient
  });
});

// Database initialization
const initializeDatabase = async () => {
  try {
    console.log('🔄 Initializing database...');
    
    // Create users table
    await pool.query(`
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
        zip_code VARCHAR(8),
        password VARCHAR(255) NOT NULL,
        roles TEXT[] DEFAULT ARRAY['client'],
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry TIMESTAMP,
        percentage DECIMAL(5,2) DEFAULT 50.00,
        photo_url TEXT,
        has_scheduling_access BOOLEAN DEFAULT false,
        access_expires_at TIMESTAMP,
        access_granted_by INTEGER,
        access_granted_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create service_categories table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS service_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create services table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS services (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        base_price DECIMAL(10,2) NOT NULL,
        category_id INTEGER REFERENCES service_categories(id),
        is_base_service BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create dependents table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dependents (
        id SERIAL PRIMARY KEY,
        client_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) NOT NULL,
        birth_date DATE,
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry TIMESTAMP,
        billing_amount DECIMAL(10,2) DEFAULT 50.00,
        payment_reference VARCHAR(255),
        activated_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create attendance_locations table
    await pool.query(`
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create consultations table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        private_patient_id INTEGER,
        professional_id INTEGER NOT NULL REFERENCES users(id),
        service_id INTEGER NOT NULL REFERENCES services(id),
        location_id INTEGER REFERENCES attendance_locations(id),
        value DECIMAL(10,2) NOT NULL,
        date TIMESTAMP NOT NULL,
        status VARCHAR(20) DEFAULT 'completed',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create private_patients table
    await pool.query(`
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
      )
    `);

    // Create medical_records table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_records (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id) ON DELETE CASCADE,
        patient_name VARCHAR(255) NOT NULL,
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
      )
    `);

    // Create medical_documents table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_documents (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id),
        title VARCHAR(255) NOT NULL,
        document_type VARCHAR(50) NOT NULL,
        patient_name VARCHAR(255) NOT NULL,
        document_url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create payments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        payment_type VARCHAR(50) NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        mercadopago_payment_id VARCHAR(255),
        external_reference VARCHAR(255),
        payment_method VARCHAR(100),
        processed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create indexes for better performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_users_cpf ON users(cpf);
      CREATE INDEX IF NOT EXISTS idx_users_roles ON users USING GIN(roles);
      CREATE INDEX IF NOT EXISTS idx_dependents_client_id ON dependents(client_id);
      CREATE INDEX IF NOT EXISTS idx_dependents_cpf ON dependents(cpf);
      CREATE INDEX IF NOT EXISTS idx_consultations_client_id ON consultations(client_id);
      CREATE INDEX IF NOT EXISTS idx_consultations_professional_id ON consultations(professional_id);
      CREATE INDEX IF NOT EXISTS idx_consultations_date ON consultations(date);
      CREATE INDEX IF NOT EXISTS idx_private_patients_professional_id ON private_patients(professional_id);
      CREATE INDEX IF NOT EXISTS idx_medical_records_professional_id ON medical_records(professional_id);
      CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id);
    `);

    // Insert default service categories if they don't exist
    const categoryCheck = await pool.query('SELECT COUNT(*) FROM service_categories');
    if (parseInt(categoryCheck.rows[0].count) === 0) {
      await pool.query(`
        INSERT INTO service_categories (name, description) VALUES
        ('Fisioterapia', 'Serviços de fisioterapia e reabilitação'),
        ('Psicologia', 'Atendimento psicológico e terapêutico'),
        ('Nutrição', 'Consultas nutricionais e planejamento alimentar'),
        ('Medicina Geral', 'Consultas médicas gerais'),
        ('Odontologia', 'Serviços odontológicos'),
        ('Estética', 'Tratamentos estéticos e de beleza'),
        ('Educação Física', 'Personal trainer e atividades físicas'),
        ('Outros', 'Outros serviços de saúde e bem-estar')
      `);
    }

    // Insert default services if they don't exist
    const serviceCheck = await pool.query('SELECT COUNT(*) FROM services');
    if (parseInt(serviceCheck.rows[0].count) === 0) {
      await pool.query(`
        INSERT INTO services (name, description, base_price, category_id, is_base_service)
        SELECT 
          'Consulta ' || sc.name,
          'Consulta básica de ' || sc.name,
          CASE 
            WHEN sc.name = 'Fisioterapia' THEN 80.00
            WHEN sc.name = 'Psicologia' THEN 120.00
            WHEN sc.name = 'Nutrição' THEN 100.00
            WHEN sc.name = 'Medicina Geral' THEN 150.00
            WHEN sc.name = 'Odontologia' THEN 100.00
            WHEN sc.name = 'Estética' THEN 90.00
            WHEN sc.name = 'Educação Física' THEN 70.00
            ELSE 100.00
          END,
          sc.id,
          true
        FROM service_categories sc
      `);
    }

    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
    throw error;
  }
};

// Initialize database on startup
initializeDatabase().catch(console.error);

// ==========================================
// AUTHENTICATION ROUTES
// ==========================================

// Login route with enhanced security
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

    console.log('🔄 Login attempt for CPF:', cpf ? cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4') : 'undefined');

    if (!cpf || !password) {
      return res.status(400).json({ message: 'CPF e senha são obrigatórios' });
    }

    // Clean CPF
    const cleanCpf = cpf.replace(/\D/g, '');
    if (cleanCpf.length !== 11) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
    }

    // Find user by CPF
    const result = await pool.query(
      'SELECT id, name, cpf, password, roles, subscription_status, subscription_expiry FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      console.log('❌ User not found for CPF:', cleanCpf);
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const user = result.rows[0];
    console.log('✅ User found:', { id: user.id, name: user.name, roles: user.roles });

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      console.log('❌ Invalid password for user:', user.id);
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    // Check if user has multiple roles
    const userRoles = user.roles || ['client'];
    const needsRoleSelection = userRoles.length > 1;

    console.log('🎯 User roles:', userRoles);
    console.log('🎯 Needs role selection:', needsRoleSelection);

    // Return user data for role selection
    res.json({
      user: {
        id: user.id,
        name: user.name,
        roles: userRoles,
        subscription_status: user.subscription_status,
        subscription_expiry: user.subscription_expiry
      },
      needsRoleSelection
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Role selection route
app.post('/api/auth/select-role', async (req, res) => {
  try {
    const { userId, role } = req.body;

    console.log('🎯 Role selection:', { userId, role });

    if (!userId || !role) {
      return res.status(400).json({ message: 'User ID e role são obrigatórios' });
    }

    // Verify user exists and has the requested role
    const result = await pool.query(
      'SELECT id, name, cpf, roles, subscription_status, subscription_expiry FROM users WHERE id = $1',
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
        currentRole: role,
        roles: userRoles
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

    console.log('✅ Role selected successfully:', { userId, role });

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        roles: userRoles,
        currentRole: role,
        subscription_status: user.subscription_status,
        subscription_expiry: user.subscription_expiry
      }
    });
  } catch (error) {
    console.error('❌ Role selection error:', error);
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
    if (!req.user.roles.includes(role)) {
      return res.status(403).json({ message: 'Role não autorizada' });
    }

    // Generate new JWT token with new role
    const token = jwt.sign(
      { 
        id: req.user.id, 
        currentRole: role,
        roles: req.user.roles
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.json({
      token,
      user: {
        ...req.user,
        currentRole: role
      }
    });
  } catch (error) {
    console.error('❌ Role switch error:', error);
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

    console.log('🔄 Registration attempt for:', name);

    // Validate required fields
    if (!name || !password) {
      return res.status(400).json({ message: 'Nome e senha são obrigatórios' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Senha deve ter pelo menos 6 caracteres' });
    }

    // Validate and clean CPF if provided
    let cleanCpf = null;
    if (cpf) {
      cleanCpf = cpf.replace(/\D/g, '');
      if (cleanCpf.length !== 11) {
        return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
      }

      // Check if CPF already exists
      const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cleanCpf]);
      if (existingUser.rows.length > 0) {
        return res.status(409).json({ message: 'CPF já cadastrado' });
      }
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Clean phone if provided
    const cleanPhone = phone ? phone.replace(/\D/g, '') : null;

    // Insert user
    const insertResult = await pool.query(`
      INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password, roles
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING id, name, cpf, email, phone, roles, subscription_status, subscription_expiry
    `, [
      name.trim(),
      cleanCpf,
      email?.trim() || null,
      cleanPhone,
      birth_date || null,
      address?.trim() || null,
      address_number?.trim() || null,
      address_complement?.trim() || null,
      neighborhood?.trim() || null,
      city?.trim() || null,
      state || null,
      passwordHash,
      ['client']
    ]);

    const newUser = insertResult.rows[0];
    console.log('✅ User registered successfully:', { id: newUser.id, name: newUser.name });

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      user: {
        id: newUser.id,
        name: newUser.name,
        roles: newUser.roles,
        subscription_status: newUser.subscription_status,
        subscription_expiry: newUser.subscription_expiry
      }
    });
  } catch (error) {
    console.error('❌ Registration error:', error);
    if (error.code === '23505') { // Unique constraint violation
      res.status(409).json({ message: 'CPF já cadastrado' });
    } else {
      res.status(500).json({ message: 'Erro interno do servidor' });
    }
  }
});

// Logout route
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

// ==========================================
// USER MANAGEMENT ROUTES
// ==========================================

// Get all users (admin only)
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    console.log('🔄 Fetching all users for admin');

    const result = await pool.query(`
      SELECT 
        id, name, cpf, email, phone, roles, 
        subscription_status, subscription_expiry, created_at
      FROM users 
      ORDER BY created_at DESC
    `);

    console.log('✅ Users fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching users:', error);
    res.status(500).json({ message: 'Erro ao carregar usuários' });
  }
});

// Get specific user by ID
app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    
    console.log('🔄 Fetching user data for ID:', id);

    // Users can only access their own data unless they're admin
    if (req.user.currentRole !== 'admin' && req.user.id !== parseInt(id)) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(`
      SELECT 
        id, name, cpf, email, phone, roles, 
        subscription_status, subscription_expiry, photo_url,
        has_scheduling_access, access_expires_at, created_at
      FROM users 
      WHERE id = $1
    `, [id]);

    if (result.rows.length === 0) {
      console.log('❌ User not found for ID:', id);
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const userData = result.rows[0];
    console.log('✅ User data fetched:', { 
      id: userData.id, 
      name: userData.name, 
      subscription_status: userData.subscription_status 
    });

    res.json(userData);
  } catch (error) {
    console.error('❌ Error fetching user:', error);
    res.status(500).json({ message: 'Erro ao carregar dados do usuário' });
  }
});

// 🔥 ROTA ESPECÍFICA PARA VERIFICAÇÃO DE STATUS DE ASSINATURA
app.get('/api/users/:id/subscription-status', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    
    console.log('🔍 VERIFICAÇÃO DE STATUS: Checking subscription for user ID:', id);

    // Users can only check their own status unless they're admin
    if (req.user.currentRole !== 'admin' && req.user.id !== parseInt(id)) {
      console.log('🚫 ACESSO NEGADO: User trying to check other user status');
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(`
      SELECT subscription_status, subscription_expiry
      FROM users 
      WHERE id = $1
    `, [id]);

    if (result.rows.length === 0) {
      console.log('❌ USUÁRIO NÃO ENCONTRADO para ID:', id);
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const { subscription_status, subscription_expiry } = result.rows[0];
    
    console.log('✅ STATUS VERIFICADO:', { 
      user_id: id, 
      subscription_status, 
      subscription_expiry 
    });

    res.json({
      subscription_status,
      subscription_expiry
    });
  } catch (error) {
    console.error('❌ Error checking subscription status:', error);
    res.status(500).json({ message: 'Erro ao verificar status da assinatura' });
  }
});

// Create user (admin only)
app.post('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, cpf, email, phone, password, roles } = req.body;

    if (!name || !password || !roles || roles.length === 0) {
      return res.status(400).json({ message: 'Nome, senha e pelo menos uma role são obrigatórios' });
    }

    // Validate and clean CPF if provided
    let cleanCpf = null;
    if (cpf) {
      cleanCpf = cpf.replace(/\D/g, '');
      if (cleanCpf.length !== 11) {
        return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
      }

      // Check if CPF already exists
      const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cleanCpf]);
      if (existingUser.rows.length > 0) {
        return res.status(409).json({ message: 'CPF já cadastrado' });
      }
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);
    const cleanPhone = phone ? phone.replace(/\D/g, '') : null;

    const result = await pool.query(`
      INSERT INTO users (name, cpf, email, phone, password, roles)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, name, cpf, email, phone, roles, subscription_status, created_at
    `, [name, cleanCpf, email || null, cleanPhone, passwordHash, roles]);

    console.log('✅ User created by admin:', result.rows[0].id);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating user:', error);
    res.status(500).json({ message: 'Erro ao criar usuário' });
  }
});

// Update user
app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, phone, roles, currentPassword, newPassword } = req.body;

    // Users can only update their own data unless they're admin
    if (req.user.currentRole !== 'admin' && req.user.id !== parseInt(id)) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    // If changing password, verify current password
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: 'Senha atual é obrigatória para alterar senha' });
      }

      const userResult = await pool.query('SELECT password FROM users WHERE id = $1', [id]);
      if (userResult.rows.length === 0) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
      }

      const isValidPassword = await bcrypt.compare(currentPassword, userResult.rows[0].password);
      if (!isValidPassword) {
        return res.status(401).json({ message: 'Senha atual incorreta' });
      }
    }

    // Build update query dynamically
    const updates = [];
    const values = [];
    let paramCount = 1;

    if (name !== undefined) {
      updates.push(`name = $${paramCount}`);
      values.push(name);
      paramCount++;
    }

    if (email !== undefined) {
      updates.push(`email = $${paramCount}`);
      values.push(email || null);
      paramCount++;
    }

    if (phone !== undefined) {
      updates.push(`phone = $${paramCount}`);
      values.push(phone ? phone.replace(/\D/g, '') : null);
      paramCount++;
    }

    if (roles !== undefined && req.user.currentRole === 'admin') {
      updates.push(`roles = $${paramCount}`);
      values.push(roles);
      paramCount++;
    }

    if (newPassword) {
      const passwordHash = await bcrypt.hash(newPassword, 12);
      updates.push(`password = $${paramCount}`);
      values.push(passwordHash);
      paramCount++;
    }

    updates.push(`updated_at = CURRENT_TIMESTAMP`);
    values.push(id);

    const result = await pool.query(`
      UPDATE users 
      SET ${updates.join(', ')}
      WHERE id = $${paramCount}
      RETURNING id, name, cpf, email, phone, roles, subscription_status, subscription_expiry
    `, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    console.log('✅ User updated:', result.rows[0].id);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error updating user:', error);
    res.status(500).json({ message: 'Erro ao atualizar usuário' });
  }
});

// Delete user (admin only)
app.delete('/api/users/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    console.log('✅ User deleted:', id);
    res.json({ message: 'Usuário excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting user:', error);
    res.status(500).json({ message: 'Erro ao excluir usuário' });
  }
});

// ==========================================
// CLIENT LOOKUP ROUTES
// ==========================================

// Lookup client by CPF
app.get('/api/clients/lookup', authenticate, async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');
    
    const result = await pool.query(`
      SELECT id, name, cpf, subscription_status, subscription_expiry
      FROM users 
      WHERE cpf = $1 AND 'client' = ANY(roles)
    `, [cleanCpf]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error looking up client:', error);
    res.status(500).json({ message: 'Erro ao buscar cliente' });
  }
});

// ==========================================
// DEPENDENTS ROUTES
// ==========================================

// Get dependents for a client
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;

    // Users can only access their own dependents unless they're admin
    if (req.user.currentRole !== 'admin' && req.user.id !== parseInt(clientId)) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(`
      SELECT 
        id, name, cpf, birth_date, subscription_status, subscription_expiry,
        billing_amount, payment_reference, activated_at, created_at,
        subscription_status as current_status
      FROM dependents 
      WHERE client_id = $1 
      ORDER BY created_at DESC
    `, [clientId]);

    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching dependents:', error);
    res.status(500).json({ message: 'Erro ao carregar dependentes' });
  }
});

// Get all dependents (admin only)
app.get('/api/admin/dependents', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        d.id, d.client_id, d.name, d.cpf, d.birth_date,
        d.subscription_status, d.subscription_expiry, d.billing_amount,
        d.activated_at, d.created_at,
        u.name as client_name, u.subscription_status as client_status,
        d.subscription_status as current_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      ORDER BY d.created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching all dependents:', error);
    res.status(500).json({ message: 'Erro ao carregar dependentes' });
  }
});

// Lookup dependent by CPF
app.get('/api/dependents/lookup', authenticate, async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');
    
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

    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error looking up dependent:', error);
    res.status(500).json({ message: 'Erro ao buscar dependente' });
  }
});

// Create dependent
app.post('/api/dependents', authenticate, async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    // Validate access
    if (req.user.currentRole !== 'admin' && req.user.id !== client_id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    if (!name || !cpf) {
      return res.status(400).json({ message: 'Nome e CPF são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');
    if (cleanCpf.length !== 11) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
    }

    // Check if CPF already exists (in users or dependents)
    const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cleanCpf]);
    const existingDependent = await pool.query('SELECT id FROM dependents WHERE cpf = $1', [cleanCpf]);
    
    if (existingUser.rows.length > 0 || existingDependent.rows.length > 0) {
      return res.status(409).json({ message: 'CPF já cadastrado' });
    }

    // Check dependent limit (max 10 per client)
    const countResult = await pool.query('SELECT COUNT(*) FROM dependents WHERE client_id = $1', [client_id]);
    if (parseInt(countResult.rows[0].count) >= 10) {
      return res.status(400).json({ message: 'Limite máximo de 10 dependentes atingido' });
    }

    const result = await pool.query(`
      INSERT INTO dependents (client_id, name, cpf, birth_date)
      VALUES ($1, $2, $3, $4)
      RETURNING id, name, cpf, birth_date, subscription_status, billing_amount, created_at
    `, [client_id, name, cleanCpf, birth_date || null]);

    console.log('✅ Dependent created:', result.rows[0].id);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating dependent:', error);
    res.status(500).json({ message: 'Erro ao criar dependente' });
  }
});

// Update dependent
app.put('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    // Check if user owns this dependent
    const dependentResult = await pool.query('SELECT client_id FROM dependents WHERE id = $1', [id]);
    if (dependentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    if (req.user.currentRole !== 'admin' && req.user.id !== dependentResult.rows[0].client_id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(`
      UPDATE dependents 
      SET name = $1, birth_date = $2, updated_at = CURRENT_TIMESTAMP
      WHERE id = $3
      RETURNING id, name, cpf, birth_date, subscription_status, created_at
    `, [name, birth_date || null, id]);

    console.log('✅ Dependent updated:', id);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error updating dependent:', error);
    res.status(500).json({ message: 'Erro ao atualizar dependente' });
  }
});

// Delete dependent
app.delete('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if user owns this dependent
    const dependentResult = await pool.query('SELECT client_id FROM dependents WHERE id = $1', [id]);
    if (dependentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    if (req.user.currentRole !== 'admin' && req.user.id !== dependentResult.rows[0].client_id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    await pool.query('DELETE FROM dependents WHERE id = $1', [id]);

    console.log('✅ Dependent deleted:', id);
    res.json({ message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting dependent:', error);
    res.status(500).json({ message: 'Erro ao excluir dependente' });
  }
});

// Activate dependent (admin only)
app.post('/api/admin/dependents/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(`
      UPDATE dependents 
      SET 
        subscription_status = 'active',
        subscription_expiry = CURRENT_DATE + INTERVAL '1 year',
        activated_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING id, name, subscription_status, activated_at
    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    console.log('✅ Dependent activated:', id);
    res.json({ message: 'Dependente ativado com sucesso', dependent: result.rows[0] });
  } catch (error) {
    console.error('❌ Error activating dependent:', error);
    res.status(500).json({ message: 'Erro ao ativar dependente' });
  }
});

// ==========================================
// SERVICE CATEGORIES ROUTES
// ==========================================

// Get all service categories
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, description, created_at
      FROM service_categories 
      ORDER BY name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching service categories:', error);
    res.status(500).json({ message: 'Erro ao carregar categorias' });
  }
});

// Create service category (admin only)
app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    const result = await pool.query(`
      INSERT INTO service_categories (name, description)
      VALUES ($1, $2)
      RETURNING id, name, description, created_at
    `, [name, description || null]);

    console.log('✅ Service category created:', result.rows[0].id);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating service category:', error);
    res.status(500).json({ message: 'Erro ao criar categoria' });
  }
});

// ==========================================
// SERVICES ROUTES
// ==========================================

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

    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching services:', error);
    res.status(500).json({ message: 'Erro ao carregar serviços' });
  }
});

// Create service (admin only)
app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !base_price) {
      return res.status(400).json({ message: 'Nome e preço base são obrigatórios' });
    }

    if (base_price <= 0) {
      return res.status(400).json({ message: 'Preço base deve ser maior que zero' });
    }

    const result = await pool.query(`
      INSERT INTO services (name, description, base_price, category_id, is_base_service)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id, name, description, base_price, category_id, is_base_service
    `, [name, description || null, base_price, category_id || null, is_base_service || false]);

    console.log('✅ Service created:', result.rows[0].id);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating service:', error);
    res.status(500).json({ message: 'Erro ao criar serviço' });
  }
});

// Update service (admin only)
app.put('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !base_price) {
      return res.status(400).json({ message: 'Nome e preço base são obrigatórios' });
    }

    if (base_price <= 0) {
      return res.status(400).json({ message: 'Preço base deve ser maior que zero' });
    }

    const result = await pool.query(`
      UPDATE services 
      SET name = $1, description = $2, base_price = $3, category_id = $4, is_base_service = $5
      WHERE id = $6
      RETURNING id, name, description, base_price, category_id, is_base_service
    `, [name, description || null, base_price, category_id || null, is_base_service || false, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    console.log('✅ Service updated:', id);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error updating service:', error);
    res.status(500).json({ message: 'Erro ao atualizar serviço' });
  }
});

// Delete service (admin only)
app.delete('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query('DELETE FROM services WHERE id = $1 RETURNING id', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    console.log('✅ Service deleted:', id);
    res.json({ message: 'Serviço excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting service:', error);
    res.status(500).json({ message: 'Erro ao excluir serviço' });
  }
});

// ==========================================
// PROFESSIONALS ROUTES
// ==========================================

// Get all professionals
app.get('/api/professionals', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone, u.roles,
        u.address, u.address_number, u.address_complement,
        u.neighborhood, u.city, u.state, u.photo_url,
        COALESCE(sc.name, 'Sem categoria') as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id::INTEGER = sc.id
      WHERE 'professional' = ANY(u.roles)
      ORDER BY u.name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro ao carregar profissionais' });
  }
});

// Get professionals with scheduling access info (admin only)
app.get('/api/admin/professionals-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone,
        COALESCE(sc.name, 'Sem categoria') as category_name,
        u.has_scheduling_access, u.access_expires_at,
        granted_by.name as access_granted_by, u.access_granted_at
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id::INTEGER = sc.id
      LEFT JOIN users granted_by ON u.access_granted_by = granted_by.id
      WHERE 'professional' = ANY(u.roles)
      ORDER BY u.name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching professionals scheduling access:', error);
    res.status(500).json({ message: 'Erro ao carregar dados de acesso dos profissionais' });
  }
});

// Grant scheduling access (admin only)
app.post('/api/admin/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;

    if (!professional_id || !expires_at) {
      return res.status(400).json({ message: 'ID do profissional e data de expiração são obrigatórios' });
    }

    const result = await pool.query(`
      UPDATE users 
      SET 
        has_scheduling_access = true,
        access_expires_at = $1,
        access_granted_by = $2,
        access_granted_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $3 AND 'professional' = ANY(roles)
      RETURNING id, name, has_scheduling_access, access_expires_at
    `, [expires_at, req.user.id, professional_id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    console.log('✅ Scheduling access granted to professional:', professional_id);
    res.json({ message: 'Acesso à agenda concedido com sucesso', professional: result.rows[0] });
  } catch (error) {
    console.error('❌ Error granting scheduling access:', error);
    res.status(500).json({ message: 'Erro ao conceder acesso à agenda' });
  }
});

// Revoke scheduling access (admin only)
app.post('/api/admin/revoke-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id } = req.body;

    if (!professional_id) {
      return res.status(400).json({ message: 'ID do profissional é obrigatório' });
    }

    const result = await pool.query(`
      UPDATE users 
      SET 
        has_scheduling_access = false,
        access_expires_at = NULL,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $1 AND 'professional' = ANY(roles)
      RETURNING id, name, has_scheduling_access
    `, [professional_id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    console.log('✅ Scheduling access revoked from professional:', professional_id);
    res.json({ message: 'Acesso à agenda revogado com sucesso', professional: result.rows[0] });
  } catch (error) {
    console.error('❌ Error revoking scheduling access:', error);
    res.status(500).json({ message: 'Erro ao revogar acesso à agenda' });
  }
});

// ==========================================
// ATTENDANCE LOCATIONS ROUTES
// ==========================================

// Get attendance locations for professional
app.get('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, address, address_number, address_complement,
             neighborhood, city, state, zip_code, phone, is_default, created_at
      FROM attendance_locations 
      WHERE professional_id = $1 
      ORDER BY is_default DESC, name
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching attendance locations:', error);
    res.status(500).json({ message: 'Erro ao carregar locais de atendimento' });
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
        'UPDATE attendance_locations SET is_default = false WHERE professional_id = $1',
        [req.user.id]
      );
    }

    const result = await pool.query(`
      INSERT INTO attendance_locations (
        professional_id, name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING id, name, address, is_default, created_at
    `, [
      req.user.id, name, address || null, address_number || null,
      address_complement || null, neighborhood || null, city || null,
      state || null, zip_code ? zip_code.replace(/\D/g, '') : null,
      phone ? phone.replace(/\D/g, '') : null, is_default || false
    ]);

    console.log('✅ Attendance location created:', result.rows[0].id);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating attendance location:', error);
    res.status(500).json({ message: 'Erro ao criar local de atendimento' });
  }
});

// Update attendance location
app.put('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    } = req.body;

    // Verify ownership
    const ownershipCheck = await pool.query(
      'SELECT professional_id FROM attendance_locations WHERE id = $1',
      [id]
    );

    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Local não encontrado' });
    }

    if (ownershipCheck.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    // If setting as default, remove default from other locations
    if (is_default) {
      await pool.query(
        'UPDATE attendance_locations SET is_default = false WHERE professional_id = $1 AND id != $2',
        [req.user.id, id]
      );
    }

    const result = await pool.query(`
      UPDATE attendance_locations 
      SET name = $1, address = $2, address_number = $3, address_complement = $4,
          neighborhood = $5, city = $6, state = $7, zip_code = $8, phone = $9, is_default = $10
      WHERE id = $11
      RETURNING id, name, address, is_default
    `, [
      name, address || null, address_number || null, address_complement || null,
      neighborhood || null, city || null, state || null,
      zip_code ? zip_code.replace(/\D/g, '') : null,
      phone ? phone.replace(/\D/g, '') : null, is_default || false, id
    ]);

    console.log('✅ Attendance location updated:', id);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error updating attendance location:', error);
    res.status(500).json({ message: 'Erro ao atualizar local de atendimento' });
  }
});

// Delete attendance location
app.delete('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    // Verify ownership
    const ownershipCheck = await pool.query(
      'SELECT professional_id FROM attendance_locations WHERE id = $1',
      [id]
    );

    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Local não encontrado' });
    }

    if (ownershipCheck.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    await pool.query('DELETE FROM attendance_locations WHERE id = $1', [id]);

    console.log('✅ Attendance location deleted:', id);
    res.json({ message: 'Local excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting attendance location:', error);
    res.status(500).json({ message: 'Erro ao excluir local de atendimento' });
  }
});

// ==========================================
// PRIVATE PATIENTS ROUTES
// ==========================================

// Get private patients for professional
app.get('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, cpf, email, phone, birth_date, address, address_number,
             address_complement, neighborhood, city, state, zip_code, created_at
      FROM private_patients 
      WHERE professional_id = $1 
      ORDER BY name
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching private patients:', error);
    res.status(500).json({ message: 'Erro ao carregar pacientes particulares' });
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

    // Validate and clean CPF if provided
    let cleanCpf = null;
    if (cpf) {
      cleanCpf = cpf.replace(/\D/g, '');
      if (cleanCpf.length !== 11) {
        return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
      }

      // Check if CPF already exists
      const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cleanCpf]);
      const existingDependent = await pool.query('SELECT id FROM dependents WHERE cpf = $1', [cleanCpf]);
      const existingPatient = await pool.query('SELECT id FROM private_patients WHERE cpf = $1', [cleanCpf]);
      
      if (existingUser.rows.length > 0 || existingDependent.rows.length > 0 || existingPatient.rows.length > 0) {
        return res.status(409).json({ message: 'CPF já cadastrado' });
      }
    }

    const result = await pool.query(`
      INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date, address,
        address_number, address_complement, neighborhood, city, state, zip_code
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING id, name, cpf, email, phone, birth_date, created_at
    `, [
      req.user.id, name, cleanCpf, email || null, phone ? phone.replace(/\D/g, '') : null,
      birth_date || null, address || null, address_number || null,
      address_complement || null, neighborhood || null, city || null,
      state || null, zip_code ? zip_code.replace(/\D/g, '') : null
    ]);

    console.log('✅ Private patient created:', result.rows[0].id);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating private patient:', error);
    res.status(500).json({ message: 'Erro ao criar paciente particular' });
  }
});

// Update private patient
app.put('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    // Verify ownership
    const ownershipCheck = await pool.query(
      'SELECT professional_id FROM private_patients WHERE id = $1',
      [id]
    );

    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    if (ownershipCheck.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(`
      UPDATE private_patients 
      SET name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
          address_number = $6, address_complement = $7, neighborhood = $8,
          city = $9, state = $10, zip_code = $11, updated_at = CURRENT_TIMESTAMP
      WHERE id = $12
      RETURNING id, name, cpf, email, phone, birth_date, updated_at
    `, [
      name, email || null, phone ? phone.replace(/\D/g, '') : null,
      birth_date || null, address || null, address_number || null,
      address_complement || null, neighborhood || null, city || null,
      state || null, zip_code ? zip_code.replace(/\D/g, '') : null, id
    ]);

    console.log('✅ Private patient updated:', id);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error updating private patient:', error);
    res.status(500).json({ message: 'Erro ao atualizar paciente particular' });
  }
});

// Delete private patient
app.delete('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    // Verify ownership
    const ownershipCheck = await pool.query(
      'SELECT professional_id FROM private_patients WHERE id = $1',
      [id]
    );

    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    if (ownershipCheck.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    await pool.query('DELETE FROM private_patients WHERE id = $1', [id]);

    console.log('✅ Private patient deleted:', id);
    res.json({ message: 'Paciente excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting private patient:', error);
    res.status(500).json({ message: 'Erro ao excluir paciente particular' });
  }
});

// ==========================================
// CONSULTATIONS ROUTES
// ==========================================

// Get all consultations (admin and professional)
app.get('/api/consultations', authenticate, authorize(['admin', 'professional']), async (req, res) => {
  try {
    let query = `
      SELECT 
        c.id, c.value, c.date, c.status, c.notes,
        COALESCE(u.name, pp.name, d.name) as client_name,
        s.name as service_name,
        prof.name as professional_name,
        CASE 
          WHEN c.dependent_id IS NOT NULL THEN true 
          ELSE false 
        END as is_dependent
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      JOIN services s ON c.service_id = s.id
      JOIN users prof ON c.professional_id = prof.id
    `;

    const params = [];
    
    if (req.user.currentRole === 'professional') {
      query += ' WHERE c.professional_id = $1';
      params.push(req.user.id);
    }

    query += ' ORDER BY c.date DESC';

    const result = await pool.query(query, params);

    console.log('✅ Consultations fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching consultations:', error);
    res.status(500).json({ message: 'Erro ao carregar consultas' });
  }
});

// Get consultations for specific client
app.get('/api/consultations/client/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;

    // Users can only access their own consultations unless they're admin
    if (req.user.currentRole !== 'admin' && req.user.id !== parseInt(clientId)) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(`
      SELECT 
        c.id, c.value, c.date, c.status, c.notes,
        COALESCE(u.name, d.name) as client_name,
        s.name as service_name,
        prof.name as professional_name,
        CASE 
          WHEN c.dependent_id IS NOT NULL THEN true 
          ELSE false 
        END as is_dependent
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      JOIN services s ON c.service_id = s.id
      JOIN users prof ON c.professional_id = prof.id
      WHERE (c.client_id = $1 OR d.client_id = $1)
      ORDER BY c.date DESC
    `, [clientId]);

    console.log('✅ Client consultations fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching client consultations:', error);
    res.status(500).json({ message: 'Erro ao carregar consultas do cliente' });
  }
});

// Create consultation
app.post('/api/consultations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      client_id, dependent_id, private_patient_id, service_id, location_id,
      value, date, status, notes
    } = req.body;

    console.log('🔄 Creating consultation:', {
      client_id, dependent_id, private_patient_id, service_id, value, date
    });

    // Validate required fields
    if (!service_id || !value || !date) {
      return res.status(400).json({ message: 'Serviço, valor e data são obrigatórios' });
    }

    if (value <= 0) {
      return res.status(400).json({ message: 'Valor deve ser maior que zero' });
    }

    // Must have either client_id, dependent_id, or private_patient_id
    if (!client_id && !dependent_id && !private_patient_id) {
      return res.status(400).json({ message: 'É necessário especificar um cliente, dependente ou paciente particular' });
    }

    // Validate client subscription if it's a convenio consultation
    if (client_id || dependent_id) {
      let subscriptionCheck;
      
      if (dependent_id) {
        subscriptionCheck = await pool.query(`
          SELECT d.subscription_status, u.subscription_status as client_status
          FROM dependents d
          JOIN users u ON d.client_id = u.id
          WHERE d.id = $1
        `, [dependent_id]);
        
        if (subscriptionCheck.rows.length === 0) {
          return res.status(404).json({ message: 'Dependente não encontrado' });
        }
        
        if (subscriptionCheck.rows[0].subscription_status !== 'active') {
          return res.status(400).json({ message: 'Dependente não possui assinatura ativa' });
        }
      } else {
        subscriptionCheck = await pool.query(
          'SELECT subscription_status FROM users WHERE id = $1',
          [client_id]
        );
        
        const professionalPercentage = parseInt(professionalPercentageQuery.rows[0]?.professional_percentage) || 50;
          return res.status(404).json({ message: 'Cliente não encontrado' });
        const amountToPay = convenioRevenue * ((100 - professionalPercentage) / 100);
        
        if (subscriptionCheck.rows[0].subscription_status !== 'active') {
          return res.status(400).json({ message: 'Cliente não possui assinatura ativa' });
        }
      }
    }

    const result = await pool.query(`
      INSERT INTO consultations (
        client_id, dependent_id, private_patient_id, professional_id,
        service_id, location_id, value, date, status, notes
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING id, value, date, status, created_at
    `, [
      client_id || null, dependent_id || null, private_patient_id || null,
      req.user.id, service_id, location_id || null, value, date,
      status || 'completed', notes || null
    ]);

    console.log('✅ Consultation created:', result.rows[0].id);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating consultation:', error);
    res.status(500).json({ message: 'Erro ao criar consulta' });
  }
});

// Update consultation status
app.put('/api/consultations/:id/status', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ message: 'Status é obrigatório' });
    }

    const validStatuses = ['scheduled', 'confirmed', 'completed', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Status inválido' });
    }

    // Verify ownership
    const ownershipCheck = await pool.query(
      'SELECT professional_id FROM consultations WHERE id = $1',
      [id]
    );

    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Consulta não encontrada' });
    }

    if (ownershipCheck.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(`
      UPDATE consultations 
      SET status = $1
      WHERE id = $2
      RETURNING id, status
    `, [status, id]);

    console.log('✅ Consultation status updated:', { id, status });
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error updating consultation status:', error);
    res.status(500).json({ message: 'Erro ao atualizar status da consulta' });
  }
});

// ==========================================
// MEDICAL RECORDS ROUTES
// ==========================================

// Get medical records for professional
app.get('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        mr.id, mr.patient_name, mr.chief_complaint, mr.history_present_illness,
        mr.past_medical_history, mr.medications, mr.allergies, mr.physical_examination,
        mr.diagnosis, mr.treatment_plan, mr.notes, mr.vital_signs,
        mr.created_at, mr.updated_at
      FROM medical_records mr
      WHERE mr.professional_id = $1
      ORDER BY mr.created_at DESC
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching medical records:', error);
    res.status(500).json({ message: 'Erro ao carregar prontuários' });
  }
});

// Create medical record
app.post('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      private_patient_id, chief_complaint, history_present_illness,
      past_medical_history, medications, allergies, physical_examination,
      diagnosis, treatment_plan, notes, vital_signs
    } = req.body;

    if (!private_patient_id) {
      return res.status(400).json({ message: 'Paciente é obrigatório' });
    }

    // Get patient name
    const patientResult = await pool.query(
      'SELECT name FROM private_patients WHERE id = $1 AND professional_id = $2',
      [private_patient_id, req.user.id]
    );

    if (patientResult.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    const patientName = patientResult.rows[0].name;

    const result = await pool.query(`
      INSERT INTO medical_records (
        professional_id, private_patient_id, patient_name, chief_complaint,
        history_present_illness, past_medical_history, medications, allergies,
        physical_examination, diagnosis, treatment_plan, notes, vital_signs
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING id, patient_name, created_at
    `, [
      req.user.id, private_patient_id, patientName, chief_complaint || null,
      history_present_illness || null, past_medical_history || null,
      medications || null, allergies || null, physical_examination || null,
      diagnosis || null, treatment_plan || null, notes || null,
      vital_signs ? JSON.stringify(vital_signs) : null
    ]);

    console.log('✅ Medical record created:', result.rows[0].id);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating medical record:', error);
    res.status(500).json({ message: 'Erro ao criar prontuário' });
  }
});

// Update medical record
app.put('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      chief_complaint, history_present_illness, past_medical_history,
      medications, allergies, physical_examination, diagnosis,
      treatment_plan, notes, vital_signs
    } = req.body;

    // Verify ownership
    const ownershipCheck = await pool.query(
      'SELECT professional_id FROM medical_records WHERE id = $1',
      [id]
    );

    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    if (ownershipCheck.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(`
      UPDATE medical_records 
      SET chief_complaint = $1, history_present_illness = $2, past_medical_history = $3,
          medications = $4, allergies = $5, physical_examination = $6,
          diagnosis = $7, treatment_plan = $8, notes = $9, vital_signs = $10,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $11
      RETURNING id, patient_name, updated_at
    `, [
      chief_complaint || null, history_present_illness || null,
      past_medical_history || null, medications || null, allergies || null,
      physical_examination || null, diagnosis || null, treatment_plan || null,
      notes || null, vital_signs ? JSON.stringify(vital_signs) : null, id
    ]);

    console.log('✅ Medical record updated:', id);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error updating medical record:', error);
    res.status(500).json({ message: 'Erro ao atualizar prontuário' });
  }
});

// Delete medical record
app.delete('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    // Verify ownership
    const ownershipCheck = await pool.query(
      'SELECT professional_id FROM medical_records WHERE id = $1',
      [id]
    );

    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    if (ownershipCheck.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    await pool.query('DELETE FROM medical_records WHERE id = $1', [id]);

    console.log('✅ Medical record deleted:', id);
    res.json({ message: 'Prontuário excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting medical record:', error);
    res.status(500).json({ message: 'Erro ao excluir prontuário' });
  }
});

// Generate medical record document
app.post('/api/medical-records/generate-document', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { record_id, template_data } = req.body;

    if (!record_id || !template_data) {
      return res.status(400).json({ message: 'ID do prontuário e dados do template são obrigatórios' });
    }

    // Verify ownership
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

    console.log('✅ Medical record document generated');
    res.json({
      message: 'Documento gerado com sucesso',
      documentUrl: documentResult.url
    });
  } catch (error) {
    console.error('❌ Error generating medical record document:', error);
    res.status(500).json({ message: 'Erro ao gerar documento do prontuário' });
  }
});

// ==========================================
// MEDICAL DOCUMENTS ROUTES
// ==========================================

// Get medical documents for professional
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, title, document_type, patient_name, document_url, created_at
      FROM medical_documents 
      WHERE professional_id = $1 
      ORDER BY created_at DESC
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching medical documents:', error);
    res.status(500).json({ message: 'Erro ao carregar documentos médicos' });
  }
});

// Create medical document
app.post('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { title, document_type, private_patient_id, template_data } = req.body;

    if (!title || !document_type || !template_data) {
      return res.status(400).json({ message: 'Título, tipo de documento e dados são obrigatórios' });
    }

    // Get patient name
    let patientName = template_data.patientName;
    if (private_patient_id) {
      const patientResult = await pool.query(
        'SELECT name FROM private_patients WHERE id = $1 AND professional_id = $2',
        [private_patient_id, req.user.id]
      );

      if (patientResult.rows.length === 0) {
        return res.status(404).json({ message: 'Paciente não encontrado' });
      }

      patientName = patientResult.rows[0].name;
    }

    // Generate document
    const documentResult = await generateDocumentPDF(document_type, template_data);

    // Save document record
    const result = await pool.query(`
      INSERT INTO medical_documents (
        professional_id, private_patient_id, title, document_type, patient_name, document_url
      ) VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, title, document_type, patient_name, document_url, created_at
    `, [
      req.user.id, private_patient_id || null, title, document_type, patientName, documentResult.url
    ]);

    console.log('✅ Medical document created:', result.rows[0].id);
    res.status(201).json({
      ...result.rows[0],
      documentUrl: documentResult.url
    });
  } catch (error) {
    console.error('❌ Error creating medical document:', error);
    res.status(500).json({ message: 'Erro ao criar documento médico' });
  }
});

// ==========================================
// IMAGE UPLOAD ROUTES
// ==========================================

// Upload image route
app.post('/api/upload-image', authenticate, async (req, res) => {
  try {
    console.log('🔄 Image upload request received');

    // Create upload middleware instance
    const upload = createUpload();
    
    // Use multer middleware
    upload.single('image')(req, res, async (err) => {
      if (err) {
        console.error('❌ Multer error:', err);
        return res.status(400).json({ message: err.message });
      }

      if (!req.file) {
        return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
      }

      console.log('✅ Image uploaded to Cloudinary:', req.file.path);

      // Update user photo URL in database
      await pool.query(
        'UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
        [req.file.path, req.user.id]
      );

      console.log('✅ User photo URL updated in database');

      res.json({
        message: 'Imagem enviada com sucesso',
        imageUrl: req.file.path
      });
    });
  } catch (error) {
    console.error('❌ Error in image upload route:', error);
    res.status(500).json({ message: 'Erro ao fazer upload da imagem' });
  }
});

// ==========================================
// REPORTS ROUTES
// ==========================================

// Revenue report (admin only)
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    console.log('🔄 Generating revenue report:', { start_date, end_date });

    // Total revenue
    const totalResult = await pool.query(`
      SELECT COALESCE(SUM(value), 0) as total_revenue
      FROM consultations 
      WHERE date BETWEEN $1 AND $2
    `, [start_date, end_date]);

    // Revenue by professional
    const professionalResult = await pool.query(`
      SELECT 
        u.name as professional_name,
        COALESCE(u.percentage, 50) as professional_percentage,
        COALESCE(SUM(c.value), 0) as revenue,
        COUNT(c.id) as consultation_count,
        COALESCE(SUM(c.value * (COALESCE(u.percentage, 50) / 100)), 0) as professional_payment,
        COALESCE(SUM(c.value * ((100 - COALESCE(u.percentage, 50)) / 100)), 0) as clinic_revenue
      FROM users u
      LEFT JOIN consultations c ON u.id = c.professional_id 
        AND c.date BETWEEN $1 AND $2
      WHERE 'professional' = ANY(u.roles)
      GROUP BY u.id, u.name, u.percentage
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    // Revenue by service
    const serviceResult = await pool.query(`
      SELECT 
        s.name as service_name,
        COALESCE(SUM(c.value), 0) as revenue,
        COUNT(c.id) as consultation_count
      FROM services s
      LEFT JOIN consultations c ON s.id = c.service_id 
        AND c.date BETWEEN $1 AND $2
      GROUP BY s.id, s.name
      HAVING COUNT(c.id) > 0
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    const report = {
      total_revenue: parseFloat(totalResult.rows[0].total_revenue) || 0,
      revenue_by_professional: professionalResult.rows.map(row => ({
        professional_name: row.professional_name,
        professional_percentage: parseFloat(row.professional_percentage) || 50,
        revenue: parseFloat(row.revenue) || 0,
        consultation_count: parseInt(row.consultation_count) || 0,
        professional_payment: parseFloat(row.professional_payment) || 0,
        clinic_revenue: parseFloat(row.clinic_revenue) || 0
      })),
      revenue_by_service: serviceResult.rows.map(row => ({
        service_name: row.service_name,
        revenue: parseFloat(row.revenue) || 0,
        consultation_count: parseInt(row.consultation_count) || 0
      }))
    };

    console.log('✅ Revenue report generated');
    res.json(report);
  } catch (error) {
    console.error('❌ Error generating revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de receita' });
  }
});

// Professional revenue report
app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    console.log('🔄 Generating professional revenue report for user:', req.user.id);

    // Get professional percentage
    const userResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = userResult.rows[0]?.percentage || 50;

    // Get consultations summary
    const summaryResult = await pool.query(`
      SELECT 
        COALESCE(SUM(c.value), 0) as total_revenue,
        COUNT(c.id) as consultation_count,
        COALESCE(SUM(c.value * ((100 - $3) / 100)), 0) as amount_to_pay
      FROM consultations c
      WHERE c.professional_id = $1 AND c.date BETWEEN $2 AND $4
    `, [req.user.id, start_date, professionalPercentage, end_date]);

    // Get detailed consultations
    const consultationsResult = await pool.query(`
      SELECT 
        c.date, c.value as total_value,
        COALESCE(u.name, pp.name, d.name) as client_name,
        s.name as service_name,
        (c.value * ((100 - $3) / 100)) as amount_to_pay
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      JOIN services s ON c.service_id = s.id
      WHERE c.professional_id = $1 AND c.date BETWEEN $2 AND $4
      ORDER BY c.date DESC
    `, [req.user.id, start_date, professionalPercentage, end_date]);

    const summary = summaryResult.rows[0];

    const report = {
      summary: {
        professional_percentage: professionalPercentage,
        total_revenue: parseFloat(summary.total_revenue) || 0,
        consultation_count: parseInt(summary.consultation_count) || 0,
        amount_to_pay: parseFloat(summary.amount_to_pay) || 0
      },
      consultations: consultationsResult.rows.map(row => ({
        date: row.date,
        client_name: row.client_name,
        service_name: row.service_name,
        total_value: parseFloat(row.total_value) || 0,
        amount_to_pay: parseFloat(row.amount_to_pay) || 0
      }))
    };

    console.log('✅ Professional revenue report generated');
    res.json(report);
  } catch (error) {
    console.error('❌ Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de receita profissional' });
  }
});

// Professional detailed report
app.get('/api/reports/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    const professionalPercentage = 50; // Default percentage

    const result = await pool.query(`
      SELECT 
        COUNT(*) as total_consultations,
        COUNT(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        COALESCE(SUM(c.value), 0) as total_revenue,
        COALESCE(SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value ELSE 0 END), 0) as convenio_revenue,
        COALESCE(SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END), 0) as private_revenue,
        COALESCE(SUM(c.value * ((100 - $3) / 100)), 0) as amount_to_pay
      FROM consultations c
      WHERE c.professional_id = $1 AND c.date BETWEEN $2 AND $4
    `, [req.user.id, start_date, professionalPercentage, end_date]);

    const summary = result.rows[0];

    res.json({
      summary: {
        professional_percentage: professionalPercentage,
        total_consultations: parseInt(summary.total_consultations) || 0,
        convenio_consultations: parseInt(summary.convenio_consultations) || 0,
        private_consultations: parseInt(summary.private_consultations) || 0,
        total_revenue: parseFloat(summary.total_revenue) || 0,
        convenio_revenue: parseFloat(summary.convenio_revenue) || 0,
        private_revenue: parseFloat(summary.private_revenue) || 0,
        amount_to_pay: parseFloat(summary.amount_to_pay) || 0,
      },
    });
  } catch (error) {
    console.error('❌ Error generating detailed professional report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório detalhado' });
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

    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error generating clients by city report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de clientes por cidade' });
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
        json_agg(
          json_build_object(
            'category_name', COALESCE(sc.name, 'Sem categoria'),
            'count', 1
          )
        ) as categories
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id::INTEGER = sc.id
      WHERE 'professional' = ANY(u.roles) AND u.city IS NOT NULL AND u.city != ''
      GROUP BY u.city, u.state
      ORDER BY total_professionals DESC
    `);

    const processedResult = result.rows.map(row => ({
      ...row,
      categories: Object.values(
        row.categories.reduce((acc, cat) => {
          const key = cat.category_name;
          if (acc[key]) {
            acc[key].count += cat.count;
          } else {
            acc[key] = { ...cat };
          }
          return acc;
        }, {})
      ),
    }));

    res.json(processedResult);
  } catch (error) {
    console.error('❌ Error generating professionals by city report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de profissionais por cidade' });
  }
});

// ==========================================
// MERCADOPAGO PAYMENT ROUTES
// ==========================================

// 🔥 ROTA DE PAGAMENTO COM VERIFICAÇÃO TRIPLA DE SEGURANÇA
app.post('/api/create-subscription', authenticate, async (req, res) => {
  try {
    const { user_id } = req.body;

    console.log('💳 VERIFICAÇÃO DE PAGAMENTO: Iniciando para user_id:', user_id);

    if (!user_id) {
      return res.status(400).json({ message: 'User ID é obrigatório' });
    }

    // 🔥 VERIFICAÇÃO 1: Verificar se o usuário existe
    const userCheck = await pool.query(
      'SELECT id, name, subscription_status FROM users WHERE id = $1',
      [user_id]
    );

    if (userCheck.rows.length === 0) {
      console.log('❌ BLOQUEADO: Usuário não encontrado:', user_id);
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = userCheck.rows[0];
    console.log('🔍 VERIFICAÇÃO 1: Usuário encontrado:', { 
      id: user.id, 
      name: user.name, 
      status: user.subscription_status 
    });

    // 🔥 VERIFICAÇÃO 2: Bloquear se já estiver ativo
    if (user.subscription_status === 'active') {
      console.log('🚫 BLOQUEADO: Tentativa de pagamento para usuário ativo!');
      return res.status(400).json({ 
        message: 'Usuário já possui assinatura ativa. Pagamento não é necessário.',
        subscription_status: 'active'
      });
    }

    // 🔥 VERIFICAÇÃO 3: Verificar se MercadoPago está configurado
    if (!mercadoPagoClient) {
      console.log('❌ BLOQUEADO: MercadoPago não configurado');
      return res.status(500).json({ message: 'Sistema de pagamento não configurado' });
    }

    console.log('✅ VERIFICAÇÕES PASSARAM: Criando preferência de pagamento');

    const preference = new Preference(mercadoPagoClient);

    const preferenceData = {
      items: [
        {
          title: `Assinatura Convênio Quiro Ferreira - ${user.name}`,
          quantity: 1,
          unit_price: 250,
          currency_id: 'BRL',
        },
      ],
      payer: {
        email: 'cliente@quiroferreira.com.br',
      },
      back_urls: {
        success: `${req.protocol}://${req.get('host')}/client?payment=success&type=subscription`,
        failure: `${req.protocol}://${req.get('host')}/client?payment=failure&type=subscription`,
        pending: `${req.protocol}://${req.get('host')}/client?payment=pending&type=subscription`,
      },
      auto_return: 'approved',
      external_reference: `subscription_${user_id}`,
      notification_url: `${req.protocol}://${req.get('host')}/api/webhooks/mercadopago`,
    };

    const response = await preference.create({ body: preferenceData });

    console.log('✅ PAGAMENTO CRIADO: Preferência gerada com sucesso');

    res.json({
      id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point,
    });
  } catch (error) {
    console.error('❌ Error creating subscription payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento da assinatura' });
  }
});

// Create dependent payment
app.post('/api/dependents/:id/create-payment', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    if (!mercadoPagoClient) {
      return res.status(500).json({ message: 'MercadoPago não configurado' });
    }

    const dependentResult = await pool.query(
      'SELECT id, name, cpf, client_id, billing_amount FROM dependents WHERE id = $1',
      [id]
    );

    if (dependentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    const dependent = dependentResult.rows[0];

    if (req.user.currentRole !== 'admin' && req.user.id !== dependent.client_id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const preference = new Preference(mercadoPagoClient);

    const preferenceData = {
      items: [
        {
          title: `Ativação de Dependente - ${dependent.name}`,
          quantity: 1,
          unit_price: dependent.billing_amount || 50,
          currency_id: 'BRL',
        },
      ],
      payer: {
        email: 'cliente@quiroferreira.com.br',
      },
      back_urls: {
        success: `${req.protocol}://${req.get('host')}/client?payment=success&type=dependent`,
        failure: `${req.protocol}://${req.get('host')}/client?payment=failure&type=dependent`,
        pending: `${req.protocol}://${req.get('host')}/client?payment=pending&type=dependent`,
      },
      auto_return: 'approved',
      external_reference: `dependent_${id}`,
      notification_url: `${req.protocol}://${req.get('host')}/api/webhooks/mercadopago`,
    };

    const response = await preference.create({ body: preferenceData });

    console.log('✅ Dependent payment created:', id);
    res.json({
      id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point,
    });
  } catch (error) {
    console.error('❌ Error creating dependent payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento do dependente' });
  }
});

// Create professional payment
app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor deve ser maior que zero' });
    }

    if (!mercadoPagoClient) {
      return res.status(500).json({ message: 'MercadoPago não configurado' });
    }

    const preference = new Preference(mercadoPagoClient);

    const preferenceData = {
      items: [
        {
          title: `Repasse ao Convênio - ${req.user.name}`,
          quantity: 1,
          unit_price: parseFloat(amount),
          currency_id: 'BRL',
        },
      ],
      payer: {
        email: 'profissional@quiroferreira.com.br',
      },
      back_urls: {
        success: `${req.protocol}://${req.get('host')}/professional?payment=success`,
        failure: `${req.protocol}://${req.get('host')}/professional?payment=failure`,
        pending: `${req.protocol}://${req.get('host')}/professional?payment=pending`,
      },
      auto_return: 'approved',
      external_reference: `professional_payment_${req.user.id}_${Date.now()}`,
      notification_url: `${req.protocol}://${req.get('host')}/api/webhooks/mercadopago`,
    };

    const response = await preference.create({ body: preferenceData });

    console.log('✅ Professional payment created for amount:', amount);
    res.json({
      id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point,
    });
  } catch (error) {
    console.error('❌ Error creating professional payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento profissional' });
  }
});

// ==========================================
// MERCADOPAGO WEBHOOK
// ==========================================

// Webhook route for MercadoPago notifications
app.post('/api/webhooks/mercadopago', async (req, res) => {
  try {
    console.log('🔔 MercadoPago webhook received:', JSON.stringify(req.body, null, 2));

    const { type, data, action } = req.body;

    if (type === 'payment' && data?.id) {
      const paymentId = data.id;
      console.log('💳 Processing payment notification:', paymentId);

      try {
        // Get payment details from MercadoPago
        const payment = new Payment(mercadoPagoClient);
        const paymentData = await payment.get({ id: paymentId });

        console.log('💳 Payment data received:', {
          id: paymentData.id,
          status: paymentData.status,
          external_reference: paymentData.external_reference,
          transaction_amount: paymentData.transaction_amount
        });

        // Process payment based on external_reference
        if (paymentData.external_reference) {
          const reference = paymentData.external_reference;

          // Save payment record
          await pool.query(`
            INSERT INTO payments (
              payment_type, amount, status, mercadopago_payment_id, 
              external_reference, payment_method, processed_at
            ) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
            ON CONFLICT (mercadopago_payment_id) DO UPDATE SET
              status = EXCLUDED.status,
              processed_at = EXCLUDED.processed_at
          `, [
            reference.includes('subscription') ? 'subscription' : 
            reference.includes('dependent') ? 'dependent' : 'professional',
            paymentData.transaction_amount,
            paymentData.status,
            paymentData.id,
            reference,
            paymentData.payment_method_id || 'unknown'
          ]);

          if (paymentData.status === 'approved') {
            if (reference.startsWith('subscription_')) {
              // Activate user subscription
              const userId = reference.split('_')[1];
              await pool.query(`
                UPDATE users 
                SET subscription_status = 'active',
                    subscription_expiry = CURRENT_DATE + INTERVAL '1 year'
                WHERE id = $1
              `, [userId]);
              
              console.log('✅ User subscription activated:', userId);
              
            } else if (reference.startsWith('dependent_')) {
              // Activate dependent
              const dependentId = reference.split('_')[1];
              await pool.query(`
                UPDATE dependents 
                SET subscription_status = 'active',
                    subscription_expiry = CURRENT_DATE + INTERVAL '1 year',
                    activated_at = CURRENT_TIMESTAMP,
                    payment_reference = $1
                WHERE id = $2
              `, [reference, dependentId]);
              
              console.log('✅ Dependent activated:', dependentId);
              
            } else if (reference.startsWith('professional_payment_')) {
              // Record professional payment
              const parts = reference.split('_');
              const professionalId = parts[2];
              
              console.log('✅ Professional payment recorded:', professionalId);
            }
          }
        }

        console.log('✅ Payment webhook processed successfully');
      } catch (paymentError) {
        console.error('❌ Error processing payment details:', paymentError);
      }
    }

    res.status(200).json({ message: 'Webhook processed' });
  } catch (error) {
    console.error('❌ Error processing webhook:', error);
    res.status(500).json({ message: 'Erro ao processar webhook' });
  }
});

// ==========================================
// UTILITY ROUTES
// ==========================================

// Test database connection
app.get('/api/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as current_time');
    res.json({ 
      status: 'Database connected', 
      time: result.rows[0].current_time 
    });
  } catch (error) {
    console.error('❌ Database connection error:', error);
    res.status(500).json({ message: 'Database connection failed' });
  }
});

// Get system statistics (admin only)
app.get('/api/admin/statistics', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const stats = await Promise.all([
      pool.query("SELECT COUNT(*) as total FROM users WHERE 'client' = ANY(roles)"),
      pool.query("SELECT COUNT(*) as total FROM users WHERE 'professional' = ANY(roles)"),
      pool.query("SELECT COUNT(*) as total FROM dependents"),
      pool.query("SELECT COUNT(*) as total FROM consultations"),
      pool.query("SELECT COUNT(*) as total FROM consultations WHERE date >= CURRENT_DATE - INTERVAL '30 days'"),
      pool.query("SELECT COALESCE(SUM(value), 0) as total FROM consultations WHERE date >= CURRENT_DATE - INTERVAL '30 days'")
    ]);

    res.json({
      total_clients: parseInt(stats[0].rows[0].total),
      total_professionals: parseInt(stats[1].rows[0].total),
      total_dependents: parseInt(stats[2].rows[0].total),
      total_consultations: parseInt(stats[3].rows[0].total),
      consultations_last_30_days: parseInt(stats[4].rows[0].total),
      revenue_last_30_days: parseFloat(stats[5].rows[0].total)
    });
  } catch (error) {
    console.error('❌ Error fetching statistics:', error);
    res.status(500).json({ message: 'Erro ao carregar estatísticas' });
  }
});

// Backup database (admin only)
app.post('/api/admin/backup', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    
    // This is a simplified backup - in production you'd use pg_dump
    const tables = ['users', 'dependents', 'consultations', 'services', 'service_categories'];
    const backup = {};

    for (const table of tables) {
      const result = await pool.query(`SELECT * FROM ${table}`);
      backup[table] = result.rows;
    }

    res.json({
      message: 'Backup gerado com sucesso',
      timestamp,
      tables: Object.keys(backup),
      total_records: Object.values(backup).reduce((sum, records) => sum + records.length, 0)
    });
  } catch (error) {
    console.error('❌ Error creating backup:', error);
    res.status(500).json({ message: 'Erro ao criar backup' });
  }
});

// ==========================================
// ADVANCED SEARCH AND FILTERS
// ==========================================

// Advanced user search (admin only)
app.get('/api/admin/users/search', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { 
      query, role, status, city, state, 
      created_after, created_before, 
      limit = 50, offset = 0 
    } = req.query;

    let whereConditions = [];
    let params = [];
    let paramCount = 1;

    if (query) {
      whereConditions.push(`(name ILIKE $${paramCount} OR cpf LIKE $${paramCount + 1} OR email ILIKE $${paramCount + 2})`);
      params.push(`%${query}%`, `%${query.replace(/\D/g, '')}%`, `%${query}%`);
      paramCount += 3;
    }

    if (role) {
      whereConditions.push(`$${paramCount} = ANY(roles)`);
      params.push(role);
      paramCount++;
    }

    if (status) {
      whereConditions.push(`subscription_status = $${paramCount}`);
      params.push(status);
      paramCount++;
    }

    if (city) {
      whereConditions.push(`city ILIKE $${paramCount}`);
      params.push(`%${city}%`);
      paramCount++;
    }

    if (state) {
      whereConditions.push(`state = $${paramCount}`);
      params.push(state);
      paramCount++;
    }

    if (created_after) {
      whereConditions.push(`created_at >= $${paramCount}`);
      params.push(created_after);
      paramCount++;
    }

    if (created_before) {
      whereConditions.push(`created_at <= $${paramCount}`);
      params.push(created_before);
      paramCount++;
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

    const result = await pool.query(`
      SELECT 
        id, name, cpf, email, phone, roles, subscription_status, 
        subscription_expiry, city, state, created_at,
        COUNT(*) OVER() as total_count
      FROM users 
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT $${paramCount} OFFSET $${paramCount + 1}
    `, [...params, limit, offset]);

    res.json({
      users: result.rows,
      total: result.rows.length > 0 ? parseInt(result.rows[0].total_count) : 0,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
  } catch (error) {
    console.error('❌ Error in advanced user search:', error);
    res.status(500).json({ message: 'Erro na busca avançada de usuários' });
  }
});

// ==========================================
// BULK OPERATIONS (ADMIN ONLY)
// ==========================================

// Bulk update user status
app.post('/api/admin/users/bulk-update-status', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { user_ids, status, expiry_date } = req.body;

    if (!user_ids || !Array.isArray(user_ids) || user_ids.length === 0) {
      return res.status(400).json({ message: 'Lista de IDs de usuários é obrigatória' });
    }

    if (!status) {
      return res.status(400).json({ message: 'Status é obrigatório' });
    }

    const validStatuses = ['active', 'pending', 'expired'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Status inválido' });
    }

    let query = 'UPDATE users SET subscription_status = $1';
    let params = [status];
    let paramCount = 2;

    if (expiry_date && status === 'active') {
      query += `, subscription_expiry = $${paramCount}`;
      params.push(expiry_date);
      paramCount++;
    }

    query += `, updated_at = CURRENT_TIMESTAMP WHERE id = ANY($${paramCount}) RETURNING id, name, subscription_status`;
    params.push(user_ids);

    const result = await pool.query(query, params);

    console.log('✅ Bulk status update completed:', result.rows.length);
    res.json({
      message: `${result.rows.length} usuário(s) atualizado(s) com sucesso`,
      updated_users: result.rows
    });
  } catch (error) {
    console.error('❌ Error in bulk status update:', error);
    res.status(500).json({ message: 'Erro na atualização em lote' });
  }
});

// ==========================================
// DATA EXPORT ROUTES (ADMIN ONLY)
// ==========================================

// Export users data
app.get('/api/admin/export/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { format = 'json' } = req.query;

    const result = await pool.query(`
      SELECT 
        id, name, cpf, email, phone, roles, subscription_status,
        subscription_expiry, city, state, created_at
      FROM users 
      ORDER BY created_at DESC
    `);

    if (format === 'csv') {
      // Generate CSV
      const headers = ['ID', 'Nome', 'CPF', 'Email', 'Telefone', 'Funções', 'Status', 'Cidade', 'Estado', 'Data de Cadastro'];
      const csvData = [
        headers.join(','),
        ...result.rows.map(row => [
          row.id,
          `"${row.name}"`,
          row.cpf || '',
          row.email || '',
          row.phone || '',
          `"${(row.roles || []).join(', ')}"`,
          row.subscription_status || '',
          row.city || '',
          row.state || '',
          row.created_at ? new Date(row.created_at).toLocaleDateString('pt-BR') : ''
        ].join(','))
      ].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=usuarios_${new Date().toISOString().split('T')[0]}.csv`);
      res.send(csvData);
    } else {
      res.json(result.rows);
    }
  } catch (error) {
    console.error('❌ Error exporting users:', error);
    res.status(500).json({ message: 'Erro ao exportar usuários' });
  }
});

// Export consultations data
app.get('/api/admin/export/consultations', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date, format = 'json' } = req.query;

    let query = `
      SELECT 
        c.id, c.value, c.date, c.status,
        COALESCE(u.name, pp.name, d.name) as client_name,
        s.name as service_name,
        prof.name as professional_name,
        al.name as location_name
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      JOIN services s ON c.service_id = s.id
      JOIN users prof ON c.professional_id = prof.id
      LEFT JOIN attendance_locations al ON c.location_id = al.id
    `;

    const params = [];
    if (start_date && end_date) {
      query += ' WHERE c.date BETWEEN $1 AND $2';
      params.push(start_date, end_date);
    }

    query += ' ORDER BY c.date DESC';

    const result = await pool.query(query, params);

    if (format === 'csv') {
      const headers = ['ID', 'Cliente', 'Profissional', 'Serviço', 'Local', 'Valor', 'Data', 'Status'];
      const csvData = [
        headers.join(','),
        ...result.rows.map(row => [
          row.id,
          `"${row.client_name}"`,
          `"${row.professional_name}"`,
          `"${row.service_name}"`,
          `"${row.location_name || ''}"`,
          row.value,
          new Date(row.date).toLocaleString('pt-BR'),
          row.status || ''
        ].join(','))
      ].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=consultas_${new Date().toISOString().split('T')[0]}.csv`);
      res.send(csvData);
    } else {
      res.json(result.rows);
    }
  } catch (error) {
    console.error('❌ Error exporting consultations:', error);
    res.status(500).json({ message: 'Erro ao exportar consultas' });
  }
});

// ==========================================
// SYSTEM MAINTENANCE ROUTES
// ==========================================

// Clean expired sessions and tokens
app.post('/api/admin/cleanup', authenticate, authorize(['admin']), async (req, res) => {
  try {
    // Clean expired scheduling access
    const expiredAccessResult = await pool.query(`
      UPDATE users 
      SET has_scheduling_access = false, access_expires_at = NULL
      WHERE has_scheduling_access = true 
        AND access_expires_at IS NOT NULL 
        AND access_expires_at < CURRENT_TIMESTAMP
      RETURNING id, name
    `);

    // Clean old payment records (older than 1 year)
    const oldPaymentsResult = await pool.query(`
      DELETE FROM payments 
      WHERE created_at < CURRENT_DATE - INTERVAL '1 year'
      RETURNING id
    `);

    console.log('✅ System cleanup completed');
    res.json({
      message: 'Limpeza do sistema concluída',
      expired_access_revoked: expiredAccessResult.rows.length,
      old_payments_removed: oldPaymentsResult.rows.length
    });
  } catch (error) {
    console.error('❌ Error in system cleanup:', error);
    res.status(500).json({ message: 'Erro na limpeza do sistema' });
  }
});

// Update subscription expiry dates
app.post('/api/admin/update-expiry-dates', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { days_to_add = 365 } = req.body;

    const result = await pool.query(`
      UPDATE users 
      SET subscription_expiry = COALESCE(subscription_expiry, CURRENT_DATE) + INTERVAL '${days_to_add} days'
      WHERE subscription_status = 'active' AND subscription_expiry IS NULL
      RETURNING id, name, subscription_expiry
    `);

    console.log('✅ Subscription expiry dates updated:', result.rows.length);
    res.json({
      message: `${result.rows.length} data(s) de expiração atualizada(s)`,
      updated_users: result.rows
    });
  } catch (error) {
    console.error('❌ Error updating expiry dates:', error);
    res.status(500).json({ message: 'Erro ao atualizar datas de expiração' });
  }
});

// ==========================================
// NOTIFICATION SYSTEM
// ==========================================

// Get notifications for user
app.get('/api/notifications', authenticate, async (req, res) => {
  try {
    const notifications = [];

    // Check for expiring subscriptions (clients)
    if (req.user.currentRole === 'client') {
      const expiryCheck = await pool.query(`
        SELECT subscription_expiry 
        FROM users 
        WHERE id = $1 AND subscription_status = 'active'
      `, [req.user.id]);

      if (expiryCheck.rows.length > 0 && expiryCheck.rows[0].subscription_expiry) {
        const expiryDate = new Date(expiryCheck.rows[0].subscription_expiry);
        const daysUntilExpiry = Math.ceil((expiryDate.getTime() - new Date().getTime()) / (1000 * 60 * 60 * 24));

        if (daysUntilExpiry <= 30 && daysUntilExpiry > 0) {
          notifications.push({
            type: 'warning',
            title: 'Assinatura expirando',
            message: `Sua assinatura expira em ${daysUntilExpiry} dia(s)`,
            action_url: '/client'
          });
        }
      }
    }

    // Check for scheduling access expiry (professionals)
    if (req.user.currentRole === 'professional') {
      const accessCheck = await pool.query(`
        SELECT access_expires_at 
        FROM users 
        WHERE id = $1 AND has_scheduling_access = true
      `, [req.user.id]);

      if (accessCheck.rows.length > 0 && accessCheck.rows[0].access_expires_at) {
        const expiryDate = new Date(accessCheck.rows[0].access_expires_at);
        const daysUntilExpiry = Math.ceil((expiryDate.getTime() - new Date().getTime()) / (1000 * 60 * 60 * 24));

        if (daysUntilExpiry <= 7 && daysUntilExpiry > 0) {
          notifications.push({
            type: 'warning',
            title: 'Acesso à agenda expirando',
            message: `Seu acesso à agenda expira em ${daysUntilExpiry} dia(s)`,
            action_url: '/professional'
          });
        }
      }
    }

    res.json(notifications);
  } catch (error) {
    console.error('❌ Error fetching notifications:', error);
    res.status(500).json({ message: 'Erro ao carregar notificações' });
  }
});

// ==========================================
// AUDIT LOG SYSTEM
// ==========================================

// Log important actions
const logAction = async (userId, action, details = null) => {
  try {
    await pool.query(`
      INSERT INTO audit_logs (user_id, action, details, created_at)
      VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
    `, [userId, action, details ? JSON.stringify(details) : null]);
  } catch (error) {
    console.error('❌ Error logging action:', error);
  }
};

// Create audit_logs table if it doesn't exist
pool.query(`
  CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(255) NOT NULL,
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`).catch(console.error);

// Get audit logs (admin only)
app.get('/api/admin/audit-logs', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { limit = 100, offset = 0, user_id, action } = req.query;

    let whereConditions = [];
    let params = [];
    let paramCount = 1;

    if (user_id) {
      whereConditions.push(`user_id = $${paramCount}`);
      params.push(user_id);
      paramCount++;
    }

    if (action) {
      whereConditions.push(`action ILIKE $${paramCount}`);
      params.push(`%${action}%`);
      paramCount++;
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

    const result = await pool.query(`
      SELECT 
        al.id, al.action, al.details, al.created_at,
        u.name as user_name
      FROM audit_logs al
      LEFT JOIN users u ON al.user_id = u.id
      ${whereClause}
      ORDER BY al.created_at DESC
      LIMIT $${paramCount} OFFSET $${paramCount + 1}
    `, [...params, limit, offset]);

    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching audit logs:', error);
    res.status(500).json({ message: 'Erro ao carregar logs de auditoria' });
  }
});

// ==========================================
// ERROR HANDLING AND LOGGING
// ==========================================

// Global error handler
app.use((error, req, res, next) => {
  console.error('🚨 Unhandled error:', {
    message: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    user: req.user?.id || 'anonymous'
  });

  // Log error to database if possible
  if (req.user?.id) {
    logAction(req.user.id, 'ERROR', {
      message: error.message,
      url: req.url,
      method: req.method
    }).catch(console.error);
  }

  res.status(500).json({ 
    message: 'Erro interno do servidor',
    error_id: Date.now().toString(36)
  });
});

// 404 handler for API routes
app.use('/api/*', (req, res) => {
  console.log('❌ API route not found:', req.method, req.url);
  res.status(404).json({ message: 'Rota não encontrada' });
});

// ==========================================
// STATIC FILES AND SPA SUPPORT
// ==========================================

// Serve static files and handle SPA routing
app.get('*', (req, res) => {
  // Don't serve index.html for API routes
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ message: 'API route not found' });
  }
  
  res.sendFile(path.join(process.cwd(), 'dist', 'index.html'));
});

// ==========================================
// SERVER STARTUP
// ==========================================

// Graceful shutdown handling
process.on('SIGTERM', async () => {
  console.log('🔄 SIGTERM received, shutting down gracefully...');
  
  try {
    await pool.end();
    console.log('✅ Database connections closed');
  } catch (error) {
    console.error('❌ Error closing database connections:', error);
  }
  
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('🔄 SIGINT received, shutting down gracefully...');
  
  try {
    await pool.end();
    console.log('✅ Database connections closed');
  } catch (error) {
    console.error('❌ Error closing database connections:', error);
  }
  
  process.exit(0);
});

// Start server
app.listen(PORT, () => {
  console.log('🚀 ==========================================');
  console.log('🚀 CONVÊNIO QUIRO FERREIRA SERVER STARTED');
  console.log('🚀 ==========================================');
  console.log(`🌐 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`💳 MercadoPago: ${mercadoPagoClient ? '✅ Configured' : '❌ Not configured'}`);
  console.log(`🗄️  Database: ${process.env.DATABASE_URL ? '✅ Connected' : '❌ Not configured'}`);
  console.log('🚀 ==========================================');
});

export default app;