import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';
import createUpload from './middleware/upload.js';
import { generateDocumentPDF } from './utils/documentGenerator.js';
import { MercadoPagoConfig, Preference, Payment } from 'mercadopago';
import { v2 as cloudinary } from 'cloudinary';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// =============================================================================
// MERCADOPAGO CONFIGURATION
// =============================================================================

let mercadoPagoClient;
try {
  if (!process.env.MP_ACCESS_TOKEN) {
    console.warn('⚠️ MercadoPago access token not found in environment variables');
  } else {
    mercadoPagoClient = new MercadoPagoConfig({
      accessToken: process.env.MP_ACCESS_TOKEN,
      options: {
        timeout: 5000,
        idempotencyKey: 'abc'
      }
    });
    console.log('✅ MercadoPago client initialized successfully');
  }
} catch (error) {
  console.error('❌ Error initializing MercadoPago:', error);
}

// =============================================================================
// CLOUDINARY CONFIGURATION
// =============================================================================

try {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true
  });
  console.log('✅ Cloudinary configured successfully');
} catch (error) {
  console.error('❌ Error configuring Cloudinary:', error);
}

// =============================================================================
// MIDDLEWARE CONFIGURATION
// =============================================================================

// CORS configuration for production and development
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:3000',
      'http://localhost:3001',
      'https://www.cartaoquiroferreira.com.br',
      'https://cartaoquiroferreira.com.br'
    ];
    
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('❌ CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
  exposedHeaders: ['Set-Cookie']
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

// Serve static files from dist directory
app.use(express.static('dist'));

// =============================================================================
// DATABASE INITIALIZATION
// =============================================================================

const initializeDatabase = async () => {
  try {
    console.log('🔄 Initializing database...');
    
    // Create service_categories table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS service_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create users table with roles array
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) UNIQUE NOT NULL,
        email VARCHAR(255),
        phone VARCHAR(20),
        birth_date DATE,
        address TEXT,
        address_number VARCHAR(20),
        address_complement VARCHAR(100),
        neighborhood VARCHAR(100),
        city VARCHAR(100),
        state VARCHAR(2),
        password VARCHAR(255) NOT NULL,
        roles TEXT[] DEFAULT '{}',
        percentage DECIMAL(5,2) DEFAULT 50.00,
        category_id INTEGER REFERENCES service_categories(id),
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry DATE,
        photo_url TEXT,
        has_scheduling_access BOOLEAN DEFAULT FALSE,
        access_expires_at TIMESTAMP,
        access_granted_by VARCHAR(255),
        access_granted_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        is_base_service BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create dependents table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dependents (
        id SERIAL PRIMARY KEY,
        client_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) UNIQUE NOT NULL,
        birth_date DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create private_patients table (CPF optional)
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
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(professional_id, cpf) -- Only unique if CPF is provided
      )
    `);

    // Create consultations table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        private_patient_id INTEGER REFERENCES private_patients(id),
        professional_id INTEGER NOT NULL REFERENCES users(id),
        service_id INTEGER NOT NULL REFERENCES services(id),
        location_id INTEGER,
        value DECIMAL(10,2) NOT NULL,
        date TIMESTAMP NOT NULL,
        status VARCHAR(20) DEFAULT 'completed',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT check_patient_type CHECK (
          (client_id IS NOT NULL AND dependent_id IS NULL AND private_patient_id IS NULL) OR
          (client_id IS NULL AND dependent_id IS NOT NULL AND private_patient_id IS NULL) OR
          (client_id IS NULL AND dependent_id IS NULL AND private_patient_id IS NOT NULL)
        )
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
        is_default BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create medical_records table
    await pool.query(`
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
      )
    `);

    // Create medical_documents table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_documents (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id),
        private_patient_id INTEGER REFERENCES private_patients(id),
        title VARCHAR(255) NOT NULL,
        document_type VARCHAR(50) NOT NULL,
        document_url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create payments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        payment_type VARCHAR(50) NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        mp_preference_id VARCHAR(255),
        mp_payment_id VARCHAR(255),
        status VARCHAR(50) DEFAULT 'pending',
        payment_method VARCHAR(100),
        payment_date TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Insert default service categories
    await pool.query(`
      INSERT INTO service_categories (name, description) 
      VALUES 
        ('Fisioterapia', 'Serviços de fisioterapia e reabilitação'),
        ('Psicologia', 'Atendimento psicológico e terapêutico'),
        ('Nutrição', 'Consultas nutricionais e planejamento alimentar'),
        ('Medicina', 'Consultas médicas gerais e especializadas'),
        ('Odontologia', 'Tratamentos dentários e ortodônticos'),
        ('Estética', 'Procedimentos estéticos e de beleza')
      ON CONFLICT (name) DO NOTHING
    `);

    // Insert default services
    const categoryResult = await pool.query('SELECT id, name FROM service_categories');
    const categories = categoryResult.rows;

    for (const category of categories) {
      switch (category.name) {
        case 'Fisioterapia':
          await pool.query(`
            INSERT INTO services (name, description, base_price, category_id, is_base_service)
            VALUES 
              ('Consulta Fisioterapêutica', 'Avaliação e tratamento fisioterapêutico', 80.00, $1, true),
              ('Sessão de RPG', 'Reeducação Postural Global', 90.00, $1, false),
              ('Pilates Terapêutico', 'Sessão de pilates para reabilitação', 70.00, $1, false)
            ON CONFLICT DO NOTHING
          `, [category.id]);
          break;
        case 'Psicologia':
          await pool.query(`
            INSERT INTO services (name, description, base_price, category_id, is_base_service)
            VALUES 
              ('Consulta Psicológica', 'Sessão de psicoterapia individual', 120.00, $1, true),
              ('Terapia de Casal', 'Sessão de terapia para casais', 150.00, $1, false),
              ('Avaliação Psicológica', 'Avaliação psicológica completa', 200.00, $1, false)
            ON CONFLICT DO NOTHING
          `, [category.id]);
          break;
        case 'Nutrição':
          await pool.query(`
            INSERT INTO services (name, description, base_price, category_id, is_base_service)
            VALUES 
              ('Consulta Nutricional', 'Avaliação nutricional e plano alimentar', 100.00, $1, true),
              ('Acompanhamento Nutricional', 'Consulta de retorno nutricional', 80.00, $1, false),
              ('Bioimpedância', 'Exame de composição corporal', 50.00, $1, false)
            ON CONFLICT DO NOTHING
          `, [category.id]);
          break;
        case 'Medicina':
          await pool.query(`
            INSERT INTO services (name, description, base_price, category_id, is_base_service)
            VALUES 
              ('Consulta Médica', 'Consulta médica geral', 150.00, $1, true),
              ('Consulta Cardiológica', 'Consulta com cardiologista', 200.00, $1, false),
              ('Consulta Dermatológica', 'Consulta com dermatologista', 180.00, $1, false)
            ON CONFLICT DO NOTHING
          `, [category.id]);
          break;
        case 'Odontologia':
          await pool.query(`
            INSERT INTO services (name, description, base_price, category_id, is_base_service)
            VALUES 
              ('Consulta Odontológica', 'Consulta e avaliação dentária', 80.00, $1, true),
              ('Limpeza Dental', 'Profilaxia e limpeza dos dentes', 120.00, $1, false),
              ('Restauração', 'Restauração dentária', 150.00, $1, false)
            ON CONFLICT DO NOTHING
          `, [category.id]);
          break;
        case 'Estética':
          await pool.query(`
            INSERT INTO services (name, description, base_price, category_id, is_base_service)
            VALUES 
              ('Consulta Estética', 'Avaliação estética e planejamento', 100.00, $1, true),
              ('Limpeza de Pele', 'Limpeza facial profunda', 80.00, $1, false),
              ('Massagem Relaxante', 'Sessão de massagem terapêutica', 90.00, $1, false)
            ON CONFLICT DO NOTHING
          `, [category.id]);
          break;
      }
    }

    // Create admin user if not exists
    const adminExists = await pool.query(
      "SELECT id FROM users WHERE cpf = '00000000000'"
    );

    if (adminExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await pool.query(`
        INSERT INTO users (name, cpf, password, roles, subscription_status)
        VALUES ('Administrador', '00000000000', $1, ARRAY['admin'], 'active')
      `, [hashedPassword]);
      console.log('✅ Admin user created');
    }

    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
    throw error;
  }
};

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

const validateCpf = (cpf) => {
  if (!cpf) return false;
  const cleanCpf = cpf.replace(/\D/g, '');
  return cleanCpf.length === 11 && /^\d{11}$/.test(cleanCpf);
};

const formatCpf = (cpf) => {
  if (!cpf) return '';
  const cleanCpf = cpf.replace(/\D/g, '');
  return cleanCpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
};

const generateToken = (user, currentRole = null) => {
  const payload = {
    id: user.id,
    name: user.name,
    cpf: user.cpf,
    roles: user.roles,
    currentRole: currentRole || (user.roles && user.roles[0])
  };
  
  return jwt.sign(payload, process.env.JWT_SECRET || 'your-secret-key', {
    expiresIn: '24h'
  });
};

const getBaseUrl = (req) => {
  const protocol = req.get('x-forwarded-proto') || req.protocol;
  const host = req.get('host');
  return `${protocol}://${host}`;
};

// =============================================================================
// AUTHENTICATION ROUTES
// =============================================================================

// Login route
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

    console.log('🔄 Login attempt for CPF:', cpf);

    if (!cpf || !password) {
      return res.status(400).json({ message: 'CPF e senha são obrigatórios' });
    }

    // Clean CPF
    const cleanCpf = cpf.replace(/\D/g, '');

    if (!validateCpf(cleanCpf)) {
      return res.status(400).json({ message: 'CPF inválido' });
    }

    // Find user
    const result = await pool.query(
      'SELECT id, name, cpf, password, roles FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const user = result.rows[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    console.log('✅ Login successful for user:', user.name);
    console.log('🎯 User roles:', user.roles);

    // Return user data without token (will be generated after role selection)
    res.json({
      user: {
        id: user.id,
        name: user.name,
        cpf: user.cpf,
        roles: user.roles || []
      }
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
      return res.status(400).json({ message: 'ID do usuário e role são obrigatórios' });
    }

    // Get user
    const result = await pool.query(
      'SELECT id, name, cpf, roles FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];

    // Verify user has the requested role
    if (!user.roles || !user.roles.includes(role)) {
      return res.status(403).json({ message: 'Role não autorizada para este usuário' });
    }

    // Generate token with selected role
    const token = generateToken(user, role);

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });

    console.log('✅ Role selected successfully:', role);

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        cpf: user.cpf,
        roles: user.roles,
        currentRole: role
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
    const user = req.user;

    console.log('🔄 Role switch request:', { userId: user.id, newRole: role, currentRoles: user.roles });

    if (!role) {
      return res.status(400).json({ message: 'Role é obrigatória' });
    }

    // Verify user has the requested role
    if (!user.roles || !user.roles.includes(role)) {
      return res.status(403).json({ message: 'Role não autorizada para este usuário' });
    }

    // Generate new token with new role
    const token = generateToken(user, role);

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });

    console.log('✅ Role switched successfully to:', role);

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        cpf: user.cpf,
        roles: user.roles,
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
    if (!name || !cpf || !password) {
      return res.status(400).json({ message: 'Nome, CPF e senha são obrigatórios' });
    }

    // Clean and validate CPF
    const cleanCpf = cpf.replace(/\D/g, '');
    if (!validateCpf(cleanCpf)) {
      return res.status(400).json({ message: 'CPF inválido' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'Usuário já cadastrado com este CPF' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user with client role
    const result = await pool.query(`
      INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password, roles
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, ARRAY['client'])
      RETURNING id, name, cpf, roles
    `, [
      name, cleanCpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, hashedPassword
    ]);

    const newUser = result.rows[0];

    console.log('✅ User registered successfully:', newUser.name);

    res.status(201).json({
      user: newUser
    });
  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Logout route
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

// =============================================================================
// USER MANAGEMENT ROUTES
// =============================================================================

// Get all users (admin only)
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.cpf, u.email, u.phone, u.birth_date,
        u.address, u.address_number, u.address_complement,
        u.neighborhood, u.city, u.state, u.roles, u.percentage,
        u.category_id, u.subscription_status, u.subscription_expiry,
        u.created_at, sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      ORDER BY u.created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get single user
app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const user = req.user;

    // Users can only access their own data unless they're admin
    if (user.currentRole !== 'admin' && user.id !== parseInt(id)) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.cpf, u.email, u.phone, u.birth_date,
        u.address, u.address_number, u.address_complement,
        u.neighborhood, u.city, u.state, u.roles, u.percentage,
        u.category_id, u.subscription_status, u.subscription_expiry,
        u.photo_url, u.created_at, sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE u.id = $1
    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create user (admin only)
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

    // Validate required fields
    if (!name || !cpf || !password || !roles || roles.length === 0) {
      return res.status(400).json({ message: 'Nome, CPF, senha e pelo menos uma role são obrigatórios' });
    }

    // Clean and validate CPF
    const cleanCpf = cpf.replace(/\D/g, '');
    if (!validateCpf(cleanCpf)) {
      return res.status(400).json({ message: 'CPF inválido' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'Usuário já cadastrado com este CPF' });
    }

    // Validate professional fields
    if (roles.includes('professional')) {
      if (!category_id) {
        return res.status(400).json({ message: 'Categoria é obrigatória para profissionais' });
      }
      if (!percentage || !Number.isInteger(Number(percentage)) || percentage < 0 || percentage > 100) {
        return res.status(400).json({ message: 'Porcentagem deve ser um número inteiro entre 0 e 100' });
      }
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const result = await pool.query(`
      INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password, roles,
        percentage, category_id, subscription_status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
      RETURNING id, name, cpf, email, roles
    `, [
      name, cleanCpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, hashedPassword, roles,
      roles.includes('professional') ? percentage : null,
      roles.includes('professional') ? category_id : null,
      roles.includes('client') ? 'pending' : 'active'
    ]);

    const newUser = result.rows[0];

    console.log('✅ User created successfully:', newUser.name);

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      user: newUser
    });
  } catch (error) {
    console.error('❌ Error creating user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update user
app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const user = req.user;
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

    // Users can only update their own data unless they're admin
    if (user.currentRole !== 'admin' && user.id !== parseInt(id)) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    // Get current user data
    const currentUserResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );

    if (currentUserResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const currentUser = currentUserResult.rows[0];

    // Handle password change
    let passwordHash = currentUser.password;
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: 'Senha atual é obrigatória para alterar a senha' });
      }

      const isValidCurrentPassword = await bcrypt.compare(currentPassword, currentUser.password);
      if (!isValidCurrentPassword) {
        return res.status(400).json({ message: 'Senha atual incorreta' });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({ message: 'Nova senha deve ter pelo menos 6 caracteres' });
      }

      passwordHash = await bcrypt.hash(newPassword, 10);
    }

    // Validate professional fields if admin is updating roles
    if (user.currentRole === 'admin' && roles && roles.includes('professional')) {
      if (!category_id) {
        return res.status(400).json({ message: 'Categoria é obrigatória para profissionais' });
      }
      if (!percentage || !Number.isInteger(Number(percentage)) || percentage < 0 || percentage > 100) {
        return res.status(400).json({ message: 'Porcentagem deve ser um número inteiro entre 0 e 100' });
      }
    }

    // Update user
    const updateQuery = user.currentRole === 'admin' ? `
      UPDATE users SET
        name = $1, email = $2, phone = $3, birth_date = $4,
        address = $5, address_number = $6, address_complement = $7,
        neighborhood = $8, city = $9, state = $10, password = $11,
        roles = $12, percentage = $13, category_id = $14, updated_at = CURRENT_TIMESTAMP
      WHERE id = $15
      RETURNING id, name, cpf, email, roles
    ` : `
      UPDATE users SET
        name = $1, email = $2, phone = $3, birth_date = $4,
        address = $5, address_number = $6, address_complement = $7,
        neighborhood = $8, city = $9, state = $10, password = $11,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $12
      RETURNING id, name, cpf, email, roles
    `;

    const updateParams = user.currentRole === 'admin' ? [
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, passwordHash,
      roles, roles && roles.includes('professional') ? percentage : null,
      roles && roles.includes('professional') ? category_id : null, id
    ] : [
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, passwordHash, id
    ];

    const result = await pool.query(updateQuery, updateParams);

    console.log('✅ User updated successfully');

    res.json({
      message: 'Usuário atualizado com sucesso',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error updating user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete user (admin only)
app.delete('/api/users/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    // Check if user exists
    const userResult = await pool.query('SELECT name FROM users WHERE id = $1', [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    // Delete user (cascade will handle related records)
    await pool.query('DELETE FROM users WHERE id = $1', [id]);

    console.log('✅ User deleted successfully');

    res.json({ message: 'Usuário excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Activate client (admin only)
app.put('/api/users/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { expiry_date } = req.body;

    if (!expiry_date) {
      return res.status(400).json({ message: 'Data de expiração é obrigatória' });
    }

    // Validate that the user is a client
    const userResult = await pool.query(
      'SELECT name, roles FROM users WHERE id = $1',
      [id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = userResult.rows[0];
    if (!user.roles || !user.roles.includes('client')) {
      return res.status(400).json({ message: 'Apenas clientes podem ser ativados' });
    }

    // Update subscription status
    await pool.query(`
      UPDATE users 
      SET subscription_status = 'active', subscription_expiry = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
    `, [expiry_date, id]);

    console.log('✅ Client activated successfully:', user.name);

    res.json({ message: 'Cliente ativado com sucesso' });
  } catch (error) {
    console.error('❌ Error activating client:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// SERVICE CATEGORIES ROUTES
// =============================================================================

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
    console.error('Error fetching service categories:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create service category (admin only)
app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome da categoria é obrigatório' });
    }

    const result = await pool.query(`
      INSERT INTO service_categories (name, description)
      VALUES ($1, $2)
      RETURNING id, name, description, created_at
    `, [name, description]);

    console.log('✅ Service category created:', name);

    res.status(201).json({
      message: 'Categoria criada com sucesso',
      category: result.rows[0]
    });
  } catch (error) {
    if (error.code === '23505') { // Unique violation
      return res.status(409).json({ message: 'Já existe uma categoria com este nome' });
    }
    console.error('❌ Error creating service category:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// SERVICES ROUTES
// =============================================================================

// Get all services
app.get('/api/services', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        s.id, s.name, s.description, s.base_price, s.category_id,
        s.is_base_service, s.created_at, sc.name as category_name
      FROM services s
      LEFT JOIN service_categories sc ON s.category_id = sc.id
      ORDER BY sc.name, s.name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create service (admin only)
app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !description || !base_price) {
      return res.status(400).json({ message: 'Nome, descrição e preço base são obrigatórios' });
    }

    if (base_price <= 0) {
      return res.status(400).json({ message: 'Preço base deve ser maior que zero' });
    }

    const result = await pool.query(`
      INSERT INTO services (name, description, base_price, category_id, is_base_service)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id, name, description, base_price, category_id, is_base_service
    `, [name, description, base_price, category_id || null, is_base_service || false]);

    console.log('✅ Service created:', name);

    res.status(201).json({
      message: 'Serviço criado com sucesso',
      service: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error creating service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update service (admin only)
app.put('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !description || !base_price) {
      return res.status(400).json({ message: 'Nome, descrição e preço base são obrigatórios' });
    }

    if (base_price <= 0) {
      return res.status(400).json({ message: 'Preço base deve ser maior que zero' });
    }

    const result = await pool.query(`
      UPDATE services 
      SET name = $1, description = $2, base_price = $3, category_id = $4, 
          is_base_service = $5, updated_at = CURRENT_TIMESTAMP
      WHERE id = $6
      RETURNING id, name, description, base_price, category_id, is_base_service
    `, [name, description, base_price, category_id || null, is_base_service || false, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    console.log('✅ Service updated:', name);

    res.json({
      message: 'Serviço atualizado com sucesso',
      service: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error updating service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete service (admin only)
app.delete('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    // Check if service exists
    const serviceResult = await pool.query('SELECT name FROM services WHERE id = $1', [id]);
    if (serviceResult.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    // Check if service is being used in consultations
    const consultationResult = await pool.query(
      'SELECT COUNT(*) as count FROM consultations WHERE service_id = $1',
      [id]
    );

    if (parseInt(consultationResult.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir um serviço que possui consultas registradas' 
      });
    }

    // Delete service
    await pool.query('DELETE FROM services WHERE id = $1', [id]);

    console.log('✅ Service deleted successfully');

    res.json({ message: 'Serviço excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// CONSULTATIONS ROUTES
// =============================================================================

// Get consultations
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    const user = req.user;
    let query;
    let params;

    if (user.currentRole === 'admin') {
      // Admin can see all consultations
      query = `
        SELECT 
          c.id, c.value, c.date, c.status, c.notes,
          s.name as service_name,
          u.name as professional_name,
          COALESCE(u2.name, d.name, pp.name) as client_name,
          CASE 
            WHEN d.id IS NOT NULL THEN true 
            ELSE false 
          END as is_dependent,
          CASE 
            WHEN pp.id IS NOT NULL THEN 'private'
            ELSE 'convenio'
          END as patient_type
        FROM consultations c
        JOIN services s ON c.service_id = s.id
        JOIN users u ON c.professional_id = u.id
        LEFT JOIN users u2 ON c.client_id = u2.id
        LEFT JOIN dependents d ON c.dependent_id = d.id
        LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
        ORDER BY c.date DESC
      `;
      params = [];
    } else if (user.currentRole === 'professional') {
      // Professional can see their own consultations
      query = `
        SELECT 
          c.id, c.value, c.date, c.status, c.notes,
          s.name as service_name,
          u.name as professional_name,
          COALESCE(u2.name, d.name, pp.name) as client_name,
          CASE 
            WHEN d.id IS NOT NULL THEN true 
            ELSE false 
          END as is_dependent,
          CASE 
            WHEN pp.id IS NOT NULL THEN 'private'
            ELSE 'convenio'
          END as patient_type
        FROM consultations c
        JOIN services s ON c.service_id = s.id
        JOIN users u ON c.professional_id = u.id
        LEFT JOIN users u2 ON c.client_id = u2.id
        LEFT JOIN dependents d ON c.dependent_id = d.id
        LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
        WHERE c.professional_id = $1
        ORDER BY c.date DESC
      `;
      params = [user.id];
    } else if (user.currentRole === 'client') {
      // Client can see their own and dependents' consultations
      query = `
        SELECT 
          c.id, c.value, c.date, c.status, c.notes,
          s.name as service_name,
          u.name as professional_name,
          COALESCE(u2.name, d.name) as client_name,
          CASE 
            WHEN d.id IS NOT NULL THEN true 
            ELSE false 
          END as is_dependent
        FROM consultations c
        JOIN services s ON c.service_id = s.id
        JOIN users u ON c.professional_id = u.id
        LEFT JOIN users u2 ON c.client_id = u2.id
        LEFT JOIN dependents d ON c.dependent_id = d.id
        WHERE c.client_id = $1 OR c.dependent_id IN (
          SELECT id FROM dependents WHERE client_id = $1
        )
        ORDER BY c.date DESC
      `;
      params = [user.id];
    } else {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching consultations:', error);
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

    const professional_id = req.user.id;

    // Validate required fields
    if (!service_id || !value || !date) {
      return res.status(400).json({ message: 'Serviço, valor e data são obrigatórios' });
    }

    // Validate patient type (exactly one must be provided)
    const patientCount = [client_id, dependent_id, private_patient_id].filter(Boolean).length;
    if (patientCount !== 1) {
      return res.status(400).json({ message: 'Exatamente um tipo de paciente deve ser especificado' });
    }

    // Validate value
    if (value <= 0) {
      return res.status(400).json({ message: 'Valor deve ser maior que zero' });
    }

    // If it's a convenio patient, validate subscription status
    if (client_id || dependent_id) {
      let subscriptionQuery;
      let subscriptionParams;

      if (client_id) {
        subscriptionQuery = 'SELECT subscription_status FROM users WHERE id = $1';
        subscriptionParams = [client_id];
      } else {
        subscriptionQuery = `
          SELECT u.subscription_status 
          FROM users u 
          JOIN dependents d ON u.id = d.client_id 
          WHERE d.id = $1
        `;
        subscriptionParams = [dependent_id];
      }

      const subscriptionResult = await pool.query(subscriptionQuery, subscriptionParams);
      
      if (subscriptionResult.rows.length === 0) {
        return res.status(404).json({ message: 'Cliente não encontrado' });
      }

      if (subscriptionResult.rows[0].subscription_status !== 'active') {
        return res.status(400).json({ message: 'Cliente não possui assinatura ativa' });
      }
    }

    // Create consultation
    const result = await pool.query(`
      INSERT INTO consultations (
        client_id, dependent_id, private_patient_id, professional_id,
        service_id, location_id, value, date, status, notes
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING id, date, status
    `, [
      client_id || null,
      dependent_id || null,
      private_patient_id || null,
      professional_id,
      service_id,
      location_id || null,
      value,
      date,
      status || 'completed',
      notes || null
    ]);

    const consultation = result.rows[0];

    console.log('✅ Consultation created successfully:', consultation.id);

    res.status(201).json({
      message: 'Consulta registrada com sucesso',
      consultation: consultation
    });
  } catch (error) {
    console.error('❌ Error creating consultation:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update consultation status
app.put('/api/consultations/:id/status', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const professional_id = req.user.id;

    if (!status) {
      return res.status(400).json({ message: 'Status é obrigatório' });
    }

    const validStatuses = ['scheduled', 'confirmed', 'completed', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Status inválido' });
    }

    // Check if consultation exists and belongs to the professional
    const consultationResult = await pool.query(
      'SELECT id FROM consultations WHERE id = $1 AND professional_id = $2',
      [id, professional_id]
    );

    if (consultationResult.rows.length === 0) {
      return res.status(404).json({ message: 'Consulta não encontrada' });
    }

    // Update status
    await pool.query(`
      UPDATE consultations 
      SET status = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
    `, [status, id]);

    console.log('✅ Consultation status updated:', { id, status });

    res.json({ message: 'Status da consulta atualizado com sucesso' });
  } catch (error) {
    console.error('❌ Error updating consultation status:', error);
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
    const user = req.user;

    // Clients can only see their own dependents, admins can see all
    if (user.currentRole === 'client' && user.id !== parseInt(clientId)) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    const result = await pool.query(`
      SELECT id, name, cpf, birth_date, created_at
      FROM dependents
      WHERE client_id = $1
      ORDER BY name
    `, [clientId]);

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

    const cleanCpf = cpf.replace(/\D/g, '');
    if (!validateCpf(cleanCpf)) {
      return res.status(400).json({ message: 'CPF inválido' });
    }

    const result = await pool.query(`
      SELECT 
        d.id, d.name, d.cpf, d.birth_date, d.client_id,
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
    console.error('Error looking up dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create dependent
app.post('/api/dependents', authenticate, authorize(['client', 'admin']), async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;
    const user = req.user;

    // Validate required fields
    if (!client_id || !name || !cpf) {
      return res.status(400).json({ message: 'ID do cliente, nome e CPF são obrigatórios' });
    }

    // Clients can only create dependents for themselves
    if (user.currentRole === 'client' && user.id !== parseInt(client_id)) {
      return res.status(403).json({ message: 'Você só pode adicionar dependentes para sua própria conta' });
    }

    // Clean and validate CPF
    const cleanCpf = cpf.replace(/\D/g, '');
    if (!validateCpf(cleanCpf)) {
      return res.status(400).json({ message: 'CPF inválido' });
    }

    // Check if CPF already exists
    const existingCpf = await pool.query(
      'SELECT id FROM users WHERE cpf = $1 UNION SELECT id FROM dependents WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingCpf.rows.length > 0) {
      return res.status(409).json({ message: 'CPF já cadastrado no sistema' });
    }

    // Check dependent limit (max 10 per client)
    const dependentCount = await pool.query(
      'SELECT COUNT(*) as count FROM dependents WHERE client_id = $1',
      [client_id]
    );

    if (parseInt(dependentCount.rows[0].count) >= 10) {
      return res.status(400).json({ message: 'Limite máximo de 10 dependentes por cliente' });
    }

    // Create dependent
    const result = await pool.query(`
      INSERT INTO dependents (client_id, name, cpf, birth_date)
      VALUES ($1, $2, $3, $4)
      RETURNING id, name, cpf, birth_date, created_at
    `, [client_id, name, cleanCpf, birth_date || null]);

    console.log('✅ Dependent created successfully:', name);

    res.status(201).json({
      message: 'Dependente criado com sucesso',
      dependent: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error creating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update dependent
app.put('/api/dependents/:id', authenticate, authorize(['client', 'admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;
    const user = req.user;

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    // Get dependent to check ownership
    const dependentResult = await pool.query(
      'SELECT client_id FROM dependents WHERE id = $1',
      [id]
    );

    if (dependentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    // Clients can only update their own dependents
    if (user.currentRole === 'client' && user.id !== dependentResult.rows[0].client_id) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    // Update dependent
    const result = await pool.query(`
      UPDATE dependents 
      SET name = $1, birth_date = $2, updated_at = CURRENT_TIMESTAMP
      WHERE id = $3
      RETURNING id, name, cpf, birth_date
    `, [name, birth_date || null, id]);

    console.log('✅ Dependent updated successfully');

    res.json({
      message: 'Dependente atualizado com sucesso',
      dependent: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error updating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete dependent
app.delete('/api/dependents/:id', authenticate, authorize(['client', 'admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const user = req.user;

    // Get dependent to check ownership
    const dependentResult = await pool.query(
      'SELECT client_id, name FROM dependents WHERE id = $1',
      [id]
    );

    if (dependentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    // Clients can only delete their own dependents
    if (user.currentRole === 'client' && user.id !== dependentResult.rows[0].client_id) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    // Check if dependent has consultations
    const consultationResult = await pool.query(
      'SELECT COUNT(*) as count FROM consultations WHERE dependent_id = $1',
      [id]
    );

    if (parseInt(consultationResult.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir um dependente que possui consultas registradas' 
      });
    }

    // Delete dependent
    await pool.query('DELETE FROM dependents WHERE id = $1', [id]);

    console.log('✅ Dependent deleted successfully');

    res.json({ message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// PRIVATE PATIENTS ROUTES
// =============================================================================

// Get private patients for a professional
app.get('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const professional_id = req.user.id;

    const result = await pool.query(`
      SELECT id, name, cpf, email, phone, birth_date, address, address_number,
             address_complement, neighborhood, city, state, zip_code, created_at
      FROM private_patients
      WHERE professional_id = $1
      ORDER BY name
    `, [professional_id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching private patients:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create private patient (FIXED: only name required)
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

    const professional_id = req.user.id;

    // Validate required fields - ONLY NAME IS REQUIRED
    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    // Clean CPF if provided
    let cleanCpf = null;
    if (cpf && cpf.trim()) {
      cleanCpf = cpf.replace(/\D/g, '');
      if (!validateCpf(cleanCpf)) {
        return res.status(400).json({ message: 'CPF inválido' });
      }

      // Check if CPF already exists for this professional
      const existingPatient = await pool.query(
        'SELECT id FROM private_patients WHERE professional_id = $1 AND cpf = $2',
        [professional_id, cleanCpf]
      );

      if (existingPatient.rows.length > 0) {
        return res.status(409).json({ message: 'Já existe um paciente com este CPF' });
      }
    }

    // Create private patient
    const result = await pool.query(`
      INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date,
        address, address_number, address_complement, neighborhood,
        city, state, zip_code
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING id, name, cpf, email, phone, created_at
    `, [
      professional_id, name, cleanCpf, email || null, phone || null,
      birth_date || null, address || null, address_number || null,
      address_complement || null, neighborhood || null, city || null,
      state || null, zip_code || null
    ]);

    console.log('✅ Private patient created successfully:', name);

    res.status(201).json({
      message: 'Paciente criado com sucesso',
      patient: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error creating private patient:', error);
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

    const professional_id = req.user.id;

    // Validate required fields
    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    // Check if patient exists and belongs to the professional
    const patientResult = await pool.query(
      'SELECT id FROM private_patients WHERE id = $1 AND professional_id = $2',
      [id, professional_id]
    );

    if (patientResult.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    // Update patient
    const result = await pool.query(`
      UPDATE private_patients SET
        name = $1, email = $2, phone = $3, birth_date = $4,
        address = $5, address_number = $6, address_complement = $7,
        neighborhood = $8, city = $9, state = $10, zip_code = $11,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $12
      RETURNING id, name, cpf, email, phone
    `, [
      name, email || null, phone || null, birth_date || null,
      address || null, address_number || null, address_complement || null,
      neighborhood || null, city || null, state || null, zip_code || null, id
    ]);

    console.log('✅ Private patient updated successfully');

    res.json({
      message: 'Paciente atualizado com sucesso',
      patient: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error updating private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete private patient
app.delete('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const professional_id = req.user.id;

    // Check if patient exists and belongs to the professional
    const patientResult = await pool.query(
      'SELECT name FROM private_patients WHERE id = $1 AND professional_id = $2',
      [id, professional_id]
    );

    if (patientResult.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    // Check if patient has consultations
    const consultationResult = await pool.query(
      'SELECT COUNT(*) as count FROM consultations WHERE private_patient_id = $1',
      [id]
    );

    if (parseInt(consultationResult.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir um paciente que possui consultas registradas' 
      });
    }

    // Delete patient
    await pool.query('DELETE FROM private_patients WHERE id = $1', [id]);

    console.log('✅ Private patient deleted successfully');

    res.json({ message: 'Paciente excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// CLIENT LOOKUP ROUTES
// =============================================================================

// Lookup client by CPF
app.get('/api/clients/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');
    if (!validateCpf(cleanCpf)) {
      return res.status(400).json({ message: 'CPF inválido' });
    }

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
    console.error('Error looking up client:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// PROFESSIONALS ROUTES
// =============================================================================

// Get all professionals (for clients)
app.get('/api/professionals', authenticate, authorize(['client', 'admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone, u.address, u.address_number,
        u.address_complement, u.neighborhood, u.city, u.state, u.photo_url,
        sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE 'professional' = ANY(u.roles)
      ORDER BY u.name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get professionals with scheduling access info (admin only)
app.get('/api/admin/professionals-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone, u.has_scheduling_access,
        u.access_expires_at, u.access_granted_by, u.access_granted_at,
        sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE 'professional' = ANY(u.roles)
      ORDER BY u.name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Grant scheduling access (admin only)
app.post('/api/admin/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;
    const admin = req.user;

    if (!professional_id || !expires_at) {
      return res.status(400).json({ message: 'ID do profissional e data de expiração são obrigatórios' });
    }

    // Validate that the user is a professional
    const professionalResult = await pool.query(
      'SELECT name, roles FROM users WHERE id = $1',
      [professional_id]
    );

    if (professionalResult.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professional = professionalResult.rows[0];
    if (!professional.roles || !professional.roles.includes('professional')) {
      return res.status(400).json({ message: 'Usuário não é um profissional' });
    }

    // Grant access
    await pool.query(`
      UPDATE users 
      SET has_scheduling_access = true, access_expires_at = $1, 
          access_granted_by = $2, access_granted_at = CURRENT_TIMESTAMP,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $3
    `, [expires_at, admin.name, professional_id]);

    console.log('✅ Scheduling access granted to:', professional.name);

    res.json({ message: 'Acesso à agenda concedido com sucesso' });
  } catch (error) {
    console.error('❌ Error granting scheduling access:', error);
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

    // Revoke access
    await pool.query(`
      UPDATE users 
      SET has_scheduling_access = false, access_expires_at = NULL,
          access_granted_by = NULL, access_granted_at = NULL,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
    `, [professional_id]);

    console.log('✅ Scheduling access revoked');

    res.json({ message: 'Acesso à agenda revogado com sucesso' });
  } catch (error) {
    console.error('❌ Error revoking scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// ATTENDANCE LOCATIONS ROUTES
// =============================================================================

// Get attendance locations for a professional
app.get('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const professional_id = req.user.id;

    const result = await pool.query(`
      SELECT id, name, address, address_number, address_complement,
             neighborhood, city, state, zip_code, phone, is_default, created_at
      FROM attendance_locations
      WHERE professional_id = $1
      ORDER BY is_default DESC, name
    `, [professional_id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching attendance locations:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create attendance location
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

    const professional_id = req.user.id;

    if (!name) {
      return res.status(400).json({ message: 'Nome do local é obrigatório' });
    }

    // If setting as default, remove default from other locations
    if (is_default) {
      await pool.query(
        'UPDATE attendance_locations SET is_default = false WHERE professional_id = $1',
        [professional_id]
      );
    }

    // Create location
    const result = await pool.query(`
      INSERT INTO attendance_locations (
        professional_id, name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING id, name, address, is_default, created_at
    `, [
      professional_id, name, address || null, address_number || null,
      address_complement || null, neighborhood || null, city || null,
      state || null, zip_code || null, phone || null, is_default || false
    ]);

    console.log('✅ Attendance location created:', name);

    res.status(201).json({
      message: 'Local de atendimento criado com sucesso',
      location: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error creating attendance location:', error);
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

    const professional_id = req.user.id;

    if (!name) {
      return res.status(400).json({ message: 'Nome do local é obrigatório' });
    }

    // Check if location exists and belongs to the professional
    const locationResult = await pool.query(
      'SELECT id FROM attendance_locations WHERE id = $1 AND professional_id = $2',
      [id, professional_id]
    );

    if (locationResult.rows.length === 0) {
      return res.status(404).json({ message: 'Local não encontrado' });
    }

    // If setting as default, remove default from other locations
    if (is_default) {
      await pool.query(
        'UPDATE attendance_locations SET is_default = false WHERE professional_id = $1 AND id != $2',
        [professional_id, id]
      );
    }

    // Update location
    const result = await pool.query(`
      UPDATE attendance_locations SET
        name = $1, address = $2, address_number = $3, address_complement = $4,
        neighborhood = $5, city = $6, state = $7, zip_code = $8,
        phone = $9, is_default = $10, updated_at = CURRENT_TIMESTAMP
      WHERE id = $11
      RETURNING id, name, address, is_default
    `, [
      name, address || null, address_number || null, address_complement || null,
      neighborhood || null, city || null, state || null, zip_code || null,
      phone || null, is_default || false, id
    ]);

    console.log('✅ Attendance location updated');

    res.json({
      message: 'Local de atendimento atualizado com sucesso',
      location: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error updating attendance location:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete attendance location
app.delete('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const professional_id = req.user.id;

    // Check if location exists and belongs to the professional
    const locationResult = await pool.query(
      'SELECT name FROM attendance_locations WHERE id = $1 AND professional_id = $2',
      [id, professional_id]
    );

    if (locationResult.rows.length === 0) {
      return res.status(404).json({ message: 'Local não encontrado' });
    }

    // Delete location
    await pool.query('DELETE FROM attendance_locations WHERE id = $1', [id]);

    console.log('✅ Attendance location deleted');

    res.json({ message: 'Local de atendimento excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting attendance location:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// MEDICAL RECORDS ROUTES
// =============================================================================

// Get medical records for a professional
app.get('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const professional_id = req.user.id;

    const result = await pool.query(`
      SELECT 
        mr.id, mr.chief_complaint, mr.history_present_illness,
        mr.past_medical_history, mr.medications, mr.allergies,
        mr.physical_examination, mr.diagnosis, mr.treatment_plan,
        mr.notes, mr.vital_signs, mr.created_at, mr.updated_at,
        pp.name as patient_name
      FROM medical_records mr
      JOIN private_patients pp ON mr.private_patient_id = pp.id
      WHERE mr.professional_id = $1
      ORDER BY mr.created_at DESC
    `, [professional_id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical records:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create medical record
app.post('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      private_patient_id,
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

    const professional_id = req.user.id;

    if (!private_patient_id) {
      return res.status(400).json({ message: 'Paciente é obrigatório' });
    }

    // Verify patient belongs to the professional
    const patientResult = await pool.query(
      'SELECT id FROM private_patients WHERE id = $1 AND professional_id = $2',
      [private_patient_id, professional_id]
    );

    if (patientResult.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    // Create medical record
    const result = await pool.query(`
      INSERT INTO medical_records (
        professional_id, private_patient_id, chief_complaint,
        history_present_illness, past_medical_history, medications,
        allergies, physical_examination, diagnosis, treatment_plan,
        notes, vital_signs
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING id, created_at
    `, [
      professional_id, private_patient_id, chief_complaint || null,
      history_present_illness || null, past_medical_history || null,
      medications || null, allergies || null, physical_examination || null,
      diagnosis || null, treatment_plan || null, notes || null,
      vital_signs ? JSON.stringify(vital_signs) : null
    ]);

    console.log('✅ Medical record created successfully');

    res.status(201).json({
      message: 'Prontuário criado com sucesso',
      record: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error creating medical record:', error);
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

    const professional_id = req.user.id;

    // Check if record exists and belongs to the professional
    const recordResult = await pool.query(
      'SELECT id FROM medical_records WHERE id = $1 AND professional_id = $2',
      [id, professional_id]
    );

    if (recordResult.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    // Update record
    await pool.query(`
      UPDATE medical_records SET
        chief_complaint = $1, history_present_illness = $2,
        past_medical_history = $3, medications = $4, allergies = $5,
        physical_examination = $6, diagnosis = $7, treatment_plan = $8,
        notes = $9, vital_signs = $10, updated_at = CURRENT_TIMESTAMP
      WHERE id = $11
    `, [
      chief_complaint || null, history_present_illness || null,
      past_medical_history || null, medications || null, allergies || null,
      physical_examination || null, diagnosis || null, treatment_plan || null,
      notes || null, vital_signs ? JSON.stringify(vital_signs) : null, id
    ]);

    console.log('✅ Medical record updated successfully');

    res.json({ message: 'Prontuário atualizado com sucesso' });
  } catch (error) {
    console.error('❌ Error updating medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete medical record
app.delete('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const professional_id = req.user.id;

    // Check if record exists and belongs to the professional
    const recordResult = await pool.query(
      'SELECT id FROM medical_records WHERE id = $1 AND professional_id = $2',
      [id, professional_id]
    );

    if (recordResult.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    // Delete record
    await pool.query('DELETE FROM medical_records WHERE id = $1', [id]);

    console.log('✅ Medical record deleted successfully');

    res.json({ message: 'Prontuário excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Generate medical record document
app.post('/api/medical-records/generate-document', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { record_id, template_data } = req.body;
    const professional_id = req.user.id;

    if (!record_id || !template_data) {
      return res.status(400).json({ message: 'ID do prontuário e dados do template são obrigatórios' });
    }

    // Verify record belongs to the professional
    const recordResult = await pool.query(
      'SELECT id FROM medical_records WHERE id = $1 AND professional_id = $2',
      [record_id, professional_id]
    );

    if (recordResult.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
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
    res.status(500).json({ message: 'Erro ao gerar documento' });
  }
});

// =============================================================================
// MEDICAL DOCUMENTS ROUTES
// =============================================================================

// Get medical documents for a professional
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const professional_id = req.user.id;

    const result = await pool.query(`
      SELECT 
        md.id, md.title, md.document_type, md.document_url, md.created_at,
        COALESCE(pp.name, 'Paciente não especificado') as patient_name
      FROM medical_documents md
      LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
      WHERE md.professional_id = $1
      ORDER BY md.created_at DESC
    `, [professional_id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical documents:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create medical document
app.post('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { title, document_type, private_patient_id, template_data } = req.body;
    const professional_id = req.user.id;

    if (!title || !document_type || !template_data) {
      return res.status(400).json({ message: 'Título, tipo de documento e dados são obrigatórios' });
    }

    // Validate document type
    const validTypes = ['certificate', 'prescription', 'consent_form', 'exam_request', 'declaration', 'lgpd', 'other'];
    if (!validTypes.includes(document_type)) {
      return res.status(400).json({ message: 'Tipo de documento inválido' });
    }

    // If private_patient_id is provided, verify it belongs to the professional
    if (private_patient_id) {
      const patientResult = await pool.query(
        'SELECT id FROM private_patients WHERE id = $1 AND professional_id = $2',
        [private_patient_id, professional_id]
      );

      if (patientResult.rows.length === 0) {
        return res.status(404).json({ message: 'Paciente não encontrado' });
      }
    }

    // Generate document
    const documentResult = await generateDocumentPDF(document_type, template_data);

    // Save document record
    const result = await pool.query(`
      INSERT INTO medical_documents (
        professional_id, private_patient_id, title, document_type, document_url
      ) VALUES ($1, $2, $3, $4, $5)
      RETURNING id, title, document_type, document_url, created_at
    `, [
      professional_id,
      private_patient_id || null,
      title,
      document_type,
      documentResult.url
    ]);

    console.log('✅ Medical document created:', title);

    res.status(201).json({
      message: 'Documento criado com sucesso',
      title: title,
      documentUrl: documentResult.url,
      document: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error creating medical document:', error);
    res.status(500).json({ message: 'Erro ao criar documento' });
  }
});

// =============================================================================
// REPORTS ROUTES
// =============================================================================

// Revenue report (admin and professional)
app.get('/api/reports/revenue', authenticate, authorize(['admin', 'professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    const user = req.user;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    let query;
    let params;

    if (user.currentRole === 'admin') {
      // Admin sees all revenue
      query = `
        SELECT 
          u.name as professional_name,
          u.percentage::integer as professional_percentage,
          SUM(c.value) as revenue,
          COUNT(c.id) as consultation_count,
          SUM(c.value * (u.percentage::integer / 100.0)) as professional_payment,
          SUM(c.value * ((100 - u.percentage::integer) / 100.0)) as clinic_revenue
        FROM consultations c
        JOIN users u ON c.professional_id = u.id
        WHERE c.date >= $1 AND c.date <= $2
          AND (c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL)
        GROUP BY u.id, u.name, u.percentage
        ORDER BY revenue DESC
      `;
      params = [start_date, end_date + ' 23:59:59'];
    } else {
      // Professional sees only their revenue
      query = `
        SELECT 
          u.name as professional_name,
          u.percentage::integer as professional_percentage,
          SUM(c.value) as revenue,
          COUNT(c.id) as consultation_count,
          SUM(c.value * (u.percentage::integer / 100.0)) as professional_payment,
          SUM(c.value * ((100 - u.percentage::integer) / 100.0)) as clinic_revenue
        FROM consultations c
        JOIN users u ON c.professional_id = u.id
        WHERE c.date >= $1 AND c.date <= $2 AND c.professional_id = $3
          AND (c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL)
        GROUP BY u.id, u.name, u.percentage
      `;
      params = [start_date, end_date + ' 23:59:59', user.id];
    }

    const revenueByProfessional = await pool.query(query, params);

    // Get revenue by service
    const serviceQuery = user.currentRole === 'admin' ? `
      SELECT 
        s.name as service_name,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      WHERE c.date >= $1 AND c.date <= $2
      GROUP BY s.id, s.name
      ORDER BY revenue DESC
    ` : `
      SELECT 
        s.name as service_name,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      WHERE c.date >= $1 AND c.date <= $2 AND c.professional_id = $3
      GROUP BY s.id, s.name
      ORDER BY revenue DESC
    `;

    const serviceParams = user.currentRole === 'admin' 
      ? [start_date, end_date + ' 23:59:59']
      : [start_date, end_date + ' 23:59:59', user.id];

    const revenueByService = await pool.query(serviceQuery, serviceParams);

    // Calculate total revenue
    const totalRevenue = revenueByProfessional.rows.reduce(
      templateData,
      req.user.id // Pass professional ID to get signature
    );

    res.json({
      total_revenue: totalRevenue,
      revenue_by_professional: revenueByProfessional.rows,
      revenue_by_service: revenueByService.rows
    });
  } catch (error) {
    console.error('Error generating revenue report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Professional revenue report (for professional dashboard)
app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    const professional_id = req.user.id;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    // Get professional percentage as integer
    const professionalResult = await pool.query(
      'SELECT percentage::integer as percentage FROM users WHERE id = $1',
      [professional_id]
    );

    const professionalPercentage = professionalResult.rows[0]?.percentage || 50;

    // Get consultations for the period
    const consultationsResult = await pool.query(`
      SELECT 
        c.date, c.value as total_value,
        s.name as service_name,
        COALESCE(u.name, d.name, pp.name) as client_name,
        (c.value * ((100 - $1::integer) / 100.0)) as amount_to_pay,
        CASE 
          WHEN pp.id IS NOT NULL THEN 'private'
          ELSE 'convenio'
        END as patient_type
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      WHERE c.professional_id = $2 AND c.date >= $3 AND c.date <= $4
      ORDER BY c.date DESC
    `, [professionalPercentage, professional_id, start_date, end_date + ' 23:59:59']);

    // Calculate summary
    const convenioConsultations = consultationsResult.rows.filter(c => c.patient_type === 'convenio');
    const privateConsultations = consultationsResult.rows.filter(c => c.patient_type === 'private');

    const convenioRevenue = convenioConsultations.reduce((sum, c) => sum + parseFloat(c.total_value), 0);
    const privateRevenue = privateConsultations.reduce((sum, c) => sum + parseFloat(c.total_value), 0);
    const totalRevenue = convenioRevenue + privateRevenue;
    const amountToPay = convenioRevenue * ((100 - professionalPercentage) / 100.0);

    const summary = {
      professional_percentage: professionalPercentage,
      total_revenue: totalRevenue,
      consultation_count: consultationsResult.rows.length,
      amount_to_pay: amountToPay
    };

    res.json({
      summary,
      consultations: consultationsResult.rows
    });
  } catch (error) {
    console.error('Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Detailed professional report
app.get('/api/reports/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    const professional_id = req.user.id;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    // Get professional's percentage as integer
    const professionalResult = await pool.query(
      'SELECT percentage::integer as percentage FROM users WHERE id = $1',
      [professional_id]
    );

    if (professionalResult.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professionalPercentage = professionalResult.rows[0].percentage || 50;

    // Get consultations breakdown
    const consultationsResult = await pool.query(`
      SELECT 
        COUNT(*) as total_consultations,
        COUNT(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        SUM(c.value) as total_revenue,
        SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value ELSE 0 END) as convenio_revenue,
        SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END) as private_revenue,
        SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value * ((100 - $1::integer) / 100.0) ELSE 0 END) as amount_to_pay
      FROM consultations c
      WHERE c.professional_id = $2 AND c.date >= $3 AND c.date <= $4
    `, [professionalPercentage, professional_id, start_date, end_date + ' 23:59:59']);

    const summary = {
      ...consultationsResult.rows[0],
      professional_percentage: professionalPercentage
    };

    // Convert string numbers to actual numbers
    Object.keys(summary).forEach(key => {
      if (typeof summary[key] === 'string' && !isNaN(summary[key])) {
        summary[key] = parseFloat(summary[key]) || 0;
      }
    });

    res.json({ summary });
  } catch (error) {
    console.error('Error generating detailed professional report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
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
      ORDER BY client_count DESC, city
    `);

    res.json(result.rows);
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
        u.city,
        u.state,
        COUNT(u.id) as total_professionals,
        json_agg(
          json_build_object(
            'category_name', COALESCE(sc.name, 'Sem categoria'),
            'count', 1
          )
        ) as categories
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE 'professional' = ANY(u.roles) AND u.city IS NOT NULL AND u.city != ''
      GROUP BY u.city, u.state
      ORDER BY total_professionals DESC, u.city
    `);

    // Process the categories to group by category name
    const processedResult = result.rows.map(row => {
      const categoryMap = new Map();
      
      row.categories.forEach(cat => {
        const categoryName = cat.category_name;
        if (categoryMap.has(categoryName)) {
          categoryMap.set(categoryName, categoryMap.get(categoryName) + 1);
        } else {
          categoryMap.set(categoryName, 1);
        }
      });

      const categories = Array.from(categoryMap.entries()).map(([category_name, count]) => ({
        category_name,
        count
      }));

      return {
        city: row.city,
        state: row.state,
        total_professionals: parseInt(row.total_professionals),
        categories
      };
    });

    res.json(processedResult);
  } catch (error) {
    console.error('Error generating professionals by city report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// MERCADOPAGO PAYMENT ROUTES
// =============================================================================

// Create subscription payment (for clients)
app.post('/api/create-subscription', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { user_id, dependent_ids } = req.body;
    const user = req.user;

    // Validate that user can only create payment for themselves
    if (user.id !== user_id) {
      return res.status(403).json({ message: 'Você só pode criar pagamentos para sua própria conta' });
    }

    if (!mercadoPagoClient) {
      return res.status(500).json({ message: 'Serviço de pagamento não disponível' });
    }

    // Get dependent count
    const dependentResult = await pool.query(
      'SELECT COUNT(*) as count FROM dependents WHERE client_id = $1',
      [user_id]
    );

    const dependentCount = parseInt(dependentResult.rows[0].count);
    const baseAmount = 250; // R$ 250 for titular
    const dependentAmount = dependentCount * 50; // R$ 50 per dependent
    const totalAmount = baseAmount + dependentAmount;

    const baseUrl = getBaseUrl(req);

    // Create preference
    const preference = new Preference(mercadoPagoClient);
    
    const preferenceData = {
      items: [
        {
          id: `subscription_${user_id}`,
          title: `Assinatura Convênio Quiro Ferreira - ${user.name}`,
          description: `Assinatura mensal (Titular + ${dependentCount} dependente(s))`,
          quantity: 1,
          currency_id: 'BRL',
          unit_price: totalAmount
        }
      ],
      payer: {
        name: user.name,
        email: user.email || `${user.cpf}@temp.com`,
        identification: {
          type: 'CPF',
          number: user.cpf
        }
      },
      back_urls: {
        success: `${baseUrl}/payment-success`,
        failure: `${baseUrl}/payment-failure`,
        pending: `${baseUrl}/payment-pending`
      },
      auto_return: 'approved',
      external_reference: `subscription_${user_id}_${Date.now()}`,
      notification_url: `${baseUrl}/api/mercadopago/webhook`,
      statement_descriptor: 'QUIRO FERREIRA',
      expires: true,
      expiration_date_from: new Date().toISOString(),
      expiration_date_to: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
    };

    console.log('🔄 Creating MercadoPago preference:', preferenceData);

    const response = await preference.create({ body: preferenceData });

    console.log('✅ MercadoPago preference created:', response.id);

    // Save payment record
    await pool.query(`
      INSERT INTO payments (user_id, payment_type, amount, mp_preference_id, status)
      VALUES ($1, 'subscription', $2, $3, 'pending')
    `, [user_id, totalAmount, response.id]);

    res.json({
      preference_id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point
    });
  } catch (error) {
    console.error('❌ Error creating subscription payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento' });
  }
});

// Create professional payment (for professionals)
app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;
    const user = req.user;

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor inválido' });
    }

    if (!mercadoPagoClient) {
      return res.status(500).json({ message: 'Serviço de pagamento não disponível' });
    }

    const baseUrl = getBaseUrl(req);

    // Create preference
    const preference = new Preference(mercadoPagoClient);
    
    const preferenceData = {
      items: [
        {
          id: `professional_payment_${user.id}`,
          title: `Repasse ao Convênio - ${user.name}`,
          description: `Pagamento de repasse ao Convênio Quiro Ferreira`,
          quantity: 1,
          currency_id: 'BRL',
          unit_price: parseFloat(amount)
        }
      ],
      payer: {
        name: user.name,
        email: user.email || `${user.cpf}@temp.com`,
        identification: {
          type: 'CPF',
          number: user.cpf
        }
      },
      back_urls: {
        success: `${baseUrl}/payment-success`,
        failure: `${baseUrl}/payment-failure`,
        pending: `${baseUrl}/payment-pending`
      },
      auto_return: 'approved',
      external_reference: `professional_${user.id}_${Date.now()}`,
      notification_url: `${baseUrl}/api/mercadopago/webhook`,
      statement_descriptor: 'QUIRO FERREIRA',
      expires: true,
      expiration_date_from: new Date().toISOString(),
      expiration_date_to: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
    };

    console.log('🔄 Creating professional payment preference:', preferenceData);

    const response = await preference.create({ body: preferenceData });

    console.log('✅ Professional payment preference created:', response.id);

    // Save payment record
    await pool.query(`
      INSERT INTO payments (user_id, payment_type, amount, mp_preference_id, status)
      VALUES ($1, 'professional_payment', $2, $3, 'pending')
    `, [user.id, amount, response.id]);

    res.json({
      preference_id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point
    });
  } catch (error) {
    console.error('❌ Error creating professional payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento' });
  }
});

// MercadoPago webhook
app.post('/api/mercadopago/webhook', async (req, res) => {
  try {
    console.log('🔔 MercadoPago webhook received:', req.body);

    const { type, data } = req.body;

    if (type === 'payment') {
      const paymentId = data.id;
      
      if (!mercadoPagoClient) {
        console.error('❌ MercadoPago client not available');
        return res.status(500).json({ message: 'Serviço de pagamento não disponível' });
      }

      // Get payment details from MercadoPago
      const payment = new Payment(mercadoPagoClient);
      const paymentData = await payment.get({ id: paymentId });

      console.log('💳 Payment data received:', paymentData);

      const externalReference = paymentData.external_reference;
      const status = paymentData.status;
      const paymentMethod = paymentData.payment_method_id;

      // Update payment in database
      const updateResult = await pool.query(`
        UPDATE payments 
        SET mp_payment_id = $1, status = $2, payment_method = $3, 
            payment_date = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
        WHERE mp_preference_id = $4
        RETURNING user_id, payment_type, amount
      `, [paymentId, status, paymentMethod, paymentData.preference_id]);

      if (updateResult.rows.length > 0) {
        const payment = updateResult.rows[0];
        
        // If payment is approved and it's a subscription, activate the user
        if (status === 'approved' && payment.payment_type === 'subscription') {
          const expiryDate = new Date();
          expiryDate.setMonth(expiryDate.getMonth() + 1); // 1 month from now

          await pool.query(`
            UPDATE users 
            SET subscription_status = 'active', subscription_expiry = $1, updated_at = CURRENT_TIMESTAMP
            WHERE id = $2
          `, [expiryDate.toISOString().split('T')[0], payment.user_id]);

          console.log('✅ User subscription activated:', payment.user_id);
        }

        console.log('✅ Payment updated successfully');
      }
    }

    res.status(200).json({ message: 'Webhook processed' });
  } catch (error) {
    console.error('❌ Error processing webhook:', error);
    res.status(500).json({ message: 'Erro ao processar webhook' });
  }
});

// =============================================================================
// PAYMENT RESULT PAGES
// =============================================================================

// Payment success page
app.get('/payment-success', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Pagamento Aprovado - Convênio Quiro Ferreira</title>
        <style>
            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .container {
                background: white;
                padding: 3rem;
                border-radius: 1rem;
                box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
                text-align: center;
                max-width: 500px;
                width: 90%;
            }
            .success-icon {
                width: 80px;
                height: 80px;
                background: #10B981;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 2rem;
            }
            .checkmark {
                width: 40px;
                height: 40px;
                color: white;
                stroke-width: 3;
            }
            h1 {
                color: #065F46;
                margin-bottom: 1rem;
                font-size: 2rem;
                font-weight: 700;
            }
            p {
                color: #6B7280;
                margin-bottom: 2rem;
                line-height: 1.6;
            }
            .btn {
                background: #c11c22;
                color: white;
                padding: 1rem 2rem;
                border: none;
                border-radius: 0.5rem;
                font-weight: 600;
                text-decoration: none;
                display: inline-block;
                transition: background-color 0.2s;
            }
            .btn:hover {
                background: #9a151a;
            }
            .logo {
                width: 120px;
                margin-bottom: 2rem;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="success-icon">
                <svg class="checkmark" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"></path>
                </svg>
            </div>
            
            <h1>Pagamento Aprovado!</h1>
            
            <p>
                Seu pagamento foi processado com sucesso. Sua assinatura do Convênio Quiro Ferreira 
                está ativa e você já pode utilizar todos os serviços.
            </p>
            
            <p>
                <strong>Próximos passos:</strong><br>
                • Acesse sua conta para ver o histórico<br>
                • Entre em contato com nossos profissionais<br>
                • Agende suas consultas
            </p>
            
            <a href="/" class="btn">Voltar ao Sistema</a>
            
            <div style="margin-top: 2rem; padding-top: 2rem; border-top: 1px solid #E5E7EB;">
                <p style="font-size: 0.875rem; color: #9CA3AF;">
                    Convênio Quiro Ferreira<br>
                    Telefone: (64) 98124-9199
                </p>
            </div>
        </div>
    </body>
    </html>
  `);
});

// Payment failure page
app.get('/payment-failure', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Pagamento Rejeitado - Convênio Quiro Ferreira</title>
        <style>
            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .container {
                background: white;
                padding: 3rem;
                border-radius: 1rem;
                box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
                text-align: center;
                max-width: 500px;
                width: 90%;
            }
            .error-icon {
                width: 80px;
                height: 80px;
                background: #EF4444;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 2rem;
            }
            .x-mark {
                width: 40px;
                height: 40px;
                color: white;
                stroke-width: 3;
            }
            h1 {
                color: #DC2626;
                margin-bottom: 1rem;
                font-size: 2rem;
                font-weight: 700;
            }
            p {
                color: #6B7280;
                margin-bottom: 2rem;
                line-height: 1.6;
            }
            .btn {
                background: #c11c22;
                color: white;
                padding: 1rem 2rem;
                border: none;
                border-radius: 0.5rem;
                font-weight: 600;
                text-decoration: none;
                display: inline-block;
                transition: background-color 0.2s;
                margin: 0.5rem;
            }
            .btn:hover {
                background: #9a151a;
            }
            .btn-secondary {
                background: #6B7280;
            }
            .btn-secondary:hover {
                background: #4B5563;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="error-icon">
                <svg class="x-mark" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"></path>
                </svg>
            </div>
            
            <h1>Pagamento Rejeitado</h1>
            
            <p>
                Infelizmente seu pagamento não pôde ser processado. Isso pode acontecer por diversos motivos,
                como dados incorretos do cartão, limite insuficiente ou problemas temporários.
            </p>
            
            <p>
                <strong>O que fazer:</strong><br>
                • Verifique os dados do seu cartão<br>
                • Confirme se há limite disponível<br>
                • Tente novamente em alguns minutos<br>
                • Entre em contato conosco se o problema persistir
            </p>
            
            <a href="/" class="btn">Tentar Novamente</a>
            <a href="tel:+5564981249199" class="btn btn-secondary">Ligar para Suporte</a>
            
            <div style="margin-top: 2rem; padding-top: 2rem; border-top: 1px solid #E5E7EB;">
                <p style="font-size: 0.875rem; color: #9CA3AF;">
                    Convênio Quiro Ferreira<br>
                    Telefone: (64) 98124-9199
                </p>
            </div>
        </div>
    </body>
    </html>
  `);
});

// Payment pending page
app.get('/payment-pending', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Pagamento Pendente - Convênio Quiro Ferreira</title>
        <style>
            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .container {
                background: white;
                padding: 3rem;
                border-radius: 1rem;
                box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
                text-align: center;
                max-width: 500px;
                width: 90%;
            }
            .pending-icon {
                width: 80px;
                height: 80px;
                background: #F59E0B;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 2rem;
            }
            .clock {
                width: 40px;
                height: 40px;
                color: white;
                stroke-width: 2;
            }
            h1 {
                color: #D97706;
                margin-bottom: 1rem;
                font-size: 2rem;
                font-weight: 700;
            }
            p {
                color: #6B7280;
                margin-bottom: 2rem;
                line-height: 1.6;
            }
            .btn {
                background: #c11c22;
                color: white;
                padding: 1rem 2rem;
                border: none;
                border-radius: 0.5rem;
                font-weight: 600;
                text-decoration: none;
                display: inline-block;
                transition: background-color 0.2s;
            }
            .btn:hover {
                background: #9a151a;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="pending-icon">
                <svg class="clock" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <circle cx="12" cy="12" r="10"></circle>
                    <polyline points="12,6 12,12 16,14"></polyline>
                </svg>
            </div>
            
            <h1>Pagamento Pendente</h1>
            
            <p>
                Seu pagamento está sendo processado. Dependendo da forma de pagamento escolhida,
                pode levar alguns minutos ou até 2 dias úteis para ser confirmado.
            </p>
            
            <p>
                <strong>Formas de pagamento e prazos:</strong><br>
                • Cartão de crédito: Aprovação imediata<br>
                • PIX: Até 2 horas<br>
                • Boleto bancário: Até 2 dias úteis<br>
                • Débito online: Aprovação imediata
            </p>
            
            <p>
                Você receberá uma confirmação por email assim que o pagamento for aprovado.
            </p>
            
            <a href="/" class="btn">Voltar ao Sistema</a>
            
            <div style="margin-top: 2rem; padding-top: 2rem; border-top: 1px solid #E5E7EB;">
                <p style="font-size: 0.875rem; color: #9CA3AF;">
                    Convênio Quiro Ferreira<br>
                    Telefone: (64) 98124-9199
                </p>
            </div>
        </div>
    </body>
    </html>
  `);
});

// =============================================================================
// IMAGE UPLOAD ROUTES
// =============================================================================

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
        return res.status(400).json({ 
          message: err.message || 'Erro no upload da imagem' 
        });
      }

      if (!req.file) {
        return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
      }

      console.log('✅ Image uploaded to Cloudinary:', req.file.path);

      // Update user photo URL in database
      const user = req.user;
      await pool.query(
        'UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
        [req.file.path, user.id]
      );

      console.log('✅ User photo URL updated in database');

      res.json({
        message: 'Imagem enviada com sucesso',
        imageUrl: req.file.path
      });
    });
  } catch (error) {
    console.error('❌ Error in image upload route:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// HEALTH CHECK AND FALLBACK ROUTES
// =============================================================================

// Health check route
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
// Upload signature route
app.post('/api/upload-signature', authenticate, async (req, res) => {
  console.log('🔄 Signature upload route called');
  console.log('🔄 User:', req.user?.id, req.user?.name);
  console.log('🔄 Files received:', req.files);
  console.log('🔄 Body received:', req.body);
  
  try {
    console.log('🔄 Processing signature upload request...');
    
    // Create upload middleware
    const upload = createUpload();
    
    // Use multer middleware
    upload.single('signature')(req, res, async (err) => {
      console.log('🔄 Multer processing completed');
      console.log('🔄 Multer error:', err);
      console.log('🔄 File after multer:', req.file);
      
      if (err) {
        console.error('❌ Multer error:', err);
        return res.status(400).json({ 
          message: err.message || 'Erro no upload da assinatura' 
        });
      }
      
      if (!req.file) {
        console.error('❌ No signature file received');
        console.error('❌ No file received');
        return res.status(400).json({ 
          message: 'Nenhum arquivo foi enviado' 
        });
      }
      
      console.log('✅ Signature file received:', {
        filename: req.file.filename,
        path: req.file.path,
        size: req.file.size
      });
      console.log('✅ Signature uploaded successfully:', req.file.path);
      
      try {
        // Update user signature_url in database
        await pool.query(
          'UPDATE users SET signature_url = $1 WHERE id = $2',
          [req.file.path, req.user.id]
        );
        
        console.log('✅ User signature_url updated in database');
        
        res.json({
          message: 'Assinatura enviada com sucesso',
          signatureUrl: req.file.path
        });
      } catch (dbError) {
      console.log('✅ Database update result:', result.rows[0]);
        console.error('❌ Database error:', dbError);
        res.status(500).json({ 
          message: 'Erro ao salvar URL da assinatura no banco de dados' 
        });
      }
    });
  } catch (error) {
    console.error('❌ Upload signature route error:', error);
    res.status(500).json({ 
      message: 'Erro interno do servidor' 
    });
  }
});

});

// API status route
app.get('/api/status', (req, res) => {
  res.json({
    status: 'online',
    version: '1.0.0',
    database: 'connected',
    mercadopago: mercadoPagoClient ? 'configured' : 'not configured',
    cloudinary: process.env.CLOUDINARY_CLOUD_NAME ? 'configured' : 'not configured'
  });
});

// Catch-all route for SPA (must be last)
app.get('*', (req, res) => {
  // Don't serve index.html for API routes
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ message: 'API endpoint not found' });
  }
  
  res.sendFile('index.html', { root: 'dist' });
});

// =============================================================================
// GLOBAL ERROR HANDLER
// =============================================================================

app.use((error, req, res, next) => {
  console.error('🚨 Global error handler:', error);
  
  // Handle specific error types
  if (error.code === '23505') { // PostgreSQL unique violation
    return res.status(409).json({ message: 'Dados duplicados encontrados' });
  }
  
  if (error.code === '23503') { // PostgreSQL foreign key violation
    return res.status(400).json({ message: 'Referência inválida nos dados' });
  }
  
  if (error.code === '23514') { // PostgreSQL check violation
    return res.status(400).json({ message: 'Dados inválidos fornecidos' });
  }
  
  // JWT errors
  if (error.name === 'JsonWebTokenError') {
    return res.status(401).json({ message: 'Token inválido' });
  }
  
  if (error.name === 'TokenExpiredError') {
    return res.status(401).json({ message: 'Token expirado' });
  }
  
  // Multer errors
  if (error.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ message: 'Arquivo muito grande' });
  }
  
  // Default error response
  res.status(500).json({ 
    message: 'Erro interno do servidor',
    ...(process.env.NODE_ENV === 'development' && { error: error.message })
  });
});

// =============================================================================
// SERVER STARTUP
// =============================================================================

const startServer = async () => {
  try {
    // Initialize database
    await initializeDatabase();
    
    // Start server
    app.listen(PORT, '0.0.0.0', () => {
      console.log('🚀 Server running on port', PORT);
      console.log('🌍 Environment:', process.env.NODE_ENV || 'development');
      console.log('💾 Database:', process.env.DATABASE_URL ? 'Connected' : 'Local');
      console.log('💳 MercadoPago:', mercadoPagoClient ? 'Configured' : 'Not configured');
      console.log('☁️ Cloudinary:', process.env.CLOUDINARY_CLOUD_NAME ? 'Configured' : 'Not configured');
      console.log('🔐 JWT Secret:', process.env.JWT_SECRET ? 'Set' : 'Using default');
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