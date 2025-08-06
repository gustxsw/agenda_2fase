import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';
import createUpload from './middleware/upload.js';
import dotenv from 'dotenv';

// ES module compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Database initialization
const initializeDatabase = async () => {
  try {
    console.log('🔄 Initializing database...');
    
    // Create service_categories table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS service_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
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
        base_price DECIMAL(10,2) NOT NULL DEFAULT 0,
        category_id INTEGER REFERENCES service_categories(id),
        is_base_service BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create users table with proper roles array
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
        zip_code VARCHAR(8),
        password_hash VARCHAR(255) NOT NULL,
        roles TEXT[] DEFAULT '{}',
        percentage INTEGER DEFAULT 50,
        category_id INTEGER REFERENCES service_categories(id),
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry DATE,
        photo_url TEXT,
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
    
    // Create private_patients table
    await pool.query(`
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(professional_id, cpf)
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        service_id INTEGER REFERENCES services(id),
        location_id INTEGER REFERENCES attendance_locations(id),
        value DECIMAL(10,2) NOT NULL,
        date TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create appointments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id),
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        service_id INTEGER REFERENCES services(id),
        location_id INTEGER REFERENCES attendance_locations(id),
        appointment_date DATE NOT NULL,
        appointment_time TIME NOT NULL,
        value DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'scheduled',
        notes TEXT,
        consultation_duration INTEGER DEFAULT 60,
        consultation_id INTEGER REFERENCES consultations(id) ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create medical_records table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_records (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        document_type VARCHAR(50) NOT NULL,
        title VARCHAR(255) NOT NULL,
        patient_name VARCHAR(255) NOT NULL,
        document_url TEXT NOT NULL,
        template_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create professional_schedule_settings table
    await pool.query(`
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create professional_scheduling_subscriptions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_scheduling_subscriptions (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        status VARCHAR(20) DEFAULT 'active',
        expires_at TIMESTAMP,
        granted_by VARCHAR(255),
        granted_at TIMESTAMP,
        revoked_by VARCHAR(255),
        revoked_at TIMESTAMP,
        reason TEXT,
        is_admin_granted BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create client_subscriptions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS client_subscriptions (
        id SERIAL PRIMARY KEY,
        client_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        status VARCHAR(20) DEFAULT 'pending',
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create client_payments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS client_payments (
        id SERIAL PRIMARY KEY,
        client_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        mp_preference_id VARCHAR(255),
        mp_payment_id VARCHAR(255),
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        external_reference VARCHAR(255),
        dependent_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create professional_payments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_payments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        mp_preference_id VARCHAR(255),
        mp_payment_id VARCHAR(255),
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        external_reference VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create professional_scheduling_payments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_scheduling_payments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        mp_preference_id VARCHAR(255),
        mp_payment_id VARCHAR(255),
        amount DECIMAL(10,2) NOT NULL DEFAULT 49.90,
        status VARCHAR(20) DEFAULT 'pending',
        external_reference VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Insert default service categories if they don't exist
    await pool.query(`
      INSERT INTO service_categories (name, description) 
      SELECT * FROM (VALUES 
        ('Fisioterapia', 'Serviços de fisioterapia e reabilitação'),
        ('Psicologia', 'Atendimento psicológico e terapias'),
        ('Nutrição', 'Consultas nutricionais e acompanhamento'),
        ('Medicina', 'Consultas médicas gerais e especializadas'),
        ('Odontologia', 'Tratamentos dentários e ortodônticos'),
        ('Estética', 'Procedimentos estéticos e de beleza')
      ) AS v(name, description)
      WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE service_categories.name = v.name)
    `);
    
    // Insert default services if they don't exist
    await pool.query(`
      INSERT INTO services (name, description, base_price, category_id, is_base_service)
      SELECT v.name, v.description, v.base_price, sc.id, v.is_base_service
      FROM (VALUES 
        ('Consulta Fisioterapêutica', 'Avaliação e tratamento fisioterapêutico', 80.00, 'Fisioterapia', true),
        ('Consulta Psicológica', 'Sessão de psicoterapia individual', 120.00, 'Psicologia', true),
        ('Consulta Nutricional', 'Avaliação nutricional e prescrição de dieta', 100.00, 'Nutrição', true),
        ('Consulta Médica', 'Consulta médica geral', 150.00, 'Medicina', true),
        ('Consulta Odontológica', 'Avaliação odontológica', 90.00, 'Odontologia', true),
        ('Procedimento Estético', 'Tratamento estético facial ou corporal', 200.00, 'Estética', true)
      ) AS v(name, description, base_price, category_name, is_base_service)
      JOIN service_categories sc ON sc.name = v.category_name
      WHERE NOT EXISTS (SELECT 1 FROM services WHERE services.name = v.name)
    `);
    
    // Create admin user if it doesn't exist
    const adminCheck = await pool.query(
      "SELECT id FROM users WHERE roles @> ARRAY['admin']"
    );
    
    if (adminCheck.rows.length === 0) {
      const adminPassword = await bcrypt.hash('admin123', 10);
      await pool.query(`
        INSERT INTO users (name, cpf, password_hash, roles, subscription_status)
        VALUES ('Administrador', '00000000000', $1, ARRAY['admin'], 'active')
      `, [adminPassword]);
      
      console.log('✅ Admin user created - CPF: 00000000000, Password: admin123');
    }
    
    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
    throw error;
  }
};

// Initialize database on startup
initializeDatabase().catch(console.error);

// Middleware
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://localhost:3000',
    'https://cartaoquiroferreira.com.br',
    'https://www.cartaoquiroferreira.com.br'
  ],
  credentials: true
}));

app.use(express.json());
app.use(cookieParser());
app.use(express.static('dist'));

// Helper function to safely parse roles
const parseRoles = (roles) => {
  if (!roles) return [];
  if (Array.isArray(roles)) return roles;
  if (typeof roles === 'string') {
    try {
      return JSON.parse(roles);
    } catch (e) {
      // If it's not valid JSON, treat as single role
      return roles.includes(',') ? roles.split(',').map(r => r.trim()) : [roles];
    }
  }
  return [roles];
};

// Helper function to safely format roles for database (return array directly)
const formatRolesForDB = (roles) => {
  if (!roles) return [];
  if (Array.isArray(roles)) return roles;
  if (typeof roles === 'string') {
    try {
      // Test if it's already valid JSON
      const parsed = JSON.parse(roles);
      return Array.isArray(parsed) ? parsed : [parsed];
    } catch (e) {
      // Convert string to array
      const rolesArray = roles.includes(',') ? roles.split(',').map(r => r.trim()) : [roles];
      return rolesArray;
    }
  }
  return [roles];
};

// MercadoPago configuration
let MercadoPagoConfig, Preference;
try {
  const mercadopago = await import('mercadopago');
  MercadoPagoConfig = mercadopago.MercadoPagoConfig;
  Preference = mercadopago.Preference;
} catch (error) {
  console.warn('⚠️ MercadoPago not available:', error.message);
}

// Initialize MercadoPago if available
let mpClient;
if (MercadoPagoConfig && process.env.MP_ACCESS_TOKEN) {
  mpClient = new MercadoPagoConfig({
    accessToken: process.env.MP_ACCESS_TOKEN,
    options: {
      timeout: 5000,
      idempotencyKey: 'abc'
    }
  });
}

// Auth routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return res.status(400).json({ message: 'CPF e senha são obrigatórios' });
    }

    // Clean CPF (remove formatting)
    const cleanCpf = cpf.replace(/\D/g, '');

    // Find user by CPF
    const result = await pool.query(
      'SELECT id, name, cpf, email, password_hash, roles FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'CPF ou senha inválidos' });
    }

    const user = result.rows[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'CPF ou senha inválidos' });
    }

    // Parse roles safely
    const userRoles = parseRoles(user.roles);

    console.log('🔍 User found:', { id: user.id, name: user.name, roles: userRoles });

    // Return user data for role selection
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

app.post('/api/auth/select-role', async (req, res) => {
  try {
    const { userId, role } = req.body;

    if (!userId || !role) {
      return res.status(400).json({ message: 'ID do usuário e role são obrigatórios' });
    }

    // Get user from database
    const result = await pool.query(
      'SELECT id, name, cpf, email, roles FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];

    // Parse roles safely
    const userRoles = parseRoles(user.roles);

    // Verify user has the requested role
    if (!userRoles.includes(role)) {
      return res.status(403).json({ message: 'Usuário não possui esta role' });
    }

    // Create JWT token with selected role
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

    // Verify current token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');

    // Get user from database
    const result = await pool.query(
      'SELECT id, name, cpf, email, roles FROM users WHERE id = $1',
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];

    // Parse roles safely
    const userRoles = parseRoles(user.roles);

    // Verify user has the requested role
    if (!userRoles.includes(role)) {
      return res.status(403).json({ message: 'Usuário não possui esta role' });
    }

    // Create new JWT token with new role
    const newToken = jwt.sign(
      { 
        id: user.id, 
        currentRole: role,
        roles: userRoles
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    // Set new cookie
    res.cookie('token', newToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
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

    // Clean CPF
    const cleanCpf = cpf.replace(/\D/g, '');

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    // Check if CPF already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create user with client role and pending subscription - PASS ARRAY DIRECTLY
    const result = await pool.query(
      `INSERT INTO users 
       (name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password_hash, roles, 
        subscription_status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, CURRENT_TIMESTAMP)
       RETURNING id, name, cpf, email, roles`,
      [name, cleanCpf, email, phone, birth_date, address, address_number,
       address_complement, neighborhood, city, state, passwordHash, 
       ['client'], 'pending']
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

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

// Users routes
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.*, sc.name as category_name 
       FROM users u
       LEFT JOIN service_categories sc ON u.category_id = sc.id
       ORDER BY u.name`
    );

    // Parse roles for each user
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

    // Clean CPF
    const cleanCpf = cpf.replace(/\D/g, '');

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    // Check if CPF already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Ensure roles is properly formatted - PASS ARRAY DIRECTLY
    const rolesArray = Array.isArray(roles) ? roles : [roles];

    // Set subscription status for clients
    const subscriptionStatus = rolesArray.includes('client') ? 'pending' : null;

    const result = await pool.query(
      `INSERT INTO users 
       (name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password_hash, roles, 
        percentage, category_id, subscription_status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, CURRENT_TIMESTAMP)
       RETURNING id, name, cpf, email, roles`,
      [name, cleanCpf, email, phone, birth_date, address, address_number,
       address_complement, neighborhood, city, state, passwordHash, rolesArray,
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

    // Check if user exists
    const userCheck = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const existingUser = userCheck.rows[0];

    // If password change is requested, verify current password
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

    // Handle roles update - PASS ARRAY DIRECTLY
    let rolesArray = existingUser.roles;
    if (roles !== undefined) {
      rolesArray = Array.isArray(roles) ? roles : [roles];
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
       neighborhood, city, state, rolesArray, percentage, category_id, passwordHash, id]
    );

    const updatedUser = result.rows[0];
    updatedUser.roles = parseRoles(updatedUser.roles);

    res.json(updatedUser);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.put('/api/users/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { expiry_date } = req.body;

    if (!expiry_date) {
      return res.status(400).json({ message: 'Data de expiração é obrigatória' });
    }

    // Check if user exists and is a client
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

    // Update subscription status
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

app.delete('/api/users/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    // Check if user has consultations
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

// Service Categories routes
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

app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    const result = await pool.query(
      'INSERT INTO service_categories (name, description) VALUES ($1, $2) RETURNING *',
      [name, description]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating service category:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Services routes
app.get('/api/services', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.*, sc.name as category_name 
       FROM services s
       LEFT JOIN service_categories sc ON s.category_id = sc.id
       ORDER BY s.name`
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

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

app.delete('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

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

// Consultations routes
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query;
    let params;
    
    const userRoles = parseRoles(req.user.roles);
    
    if (req.user.currentRole === 'client' || userRoles.includes('client')) {
      // For clients, get their consultations and their dependents' consultations
      query = `
        SELECT c.*, 
               COALESCE(pp.name, cl.name, d.name) as client_name,
               p.name as professional_name,
               s.name as service_name,
               CASE 
                 WHEN c.dependent_id IS NOT NULL THEN true
                 ELSE false
               END as is_dependent
        FROM consultations c
        LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
        LEFT JOIN users cl ON c.client_id = cl.id
        LEFT JOIN dependents d ON c.dependent_id = d.id
        JOIN users p ON c.professional_id = p.id
        LEFT JOIN services s ON c.service_id = s.id
        WHERE (c.client_id = $1 OR d.client_id = $1)
        ORDER BY c.date DESC
      `;
      params = [req.user.id];
    } else if (req.user.currentRole === 'professional' || userRoles.includes('professional')) {
      // For professionals, get their consultations
      query = `
        SELECT c.*, 
               COALESCE(pp.name, cl.name, d.name) as client_name,
               p.name as professional_name,
               s.name as service_name,
               CASE 
                 WHEN c.dependent_id IS NOT NULL THEN true
                 ELSE false
               END as is_dependent
        FROM consultations c
        LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
        LEFT JOIN users cl ON c.client_id = cl.id
        LEFT JOIN dependents d ON c.dependent_id = d.id
        JOIN users p ON c.professional_id = p.id
        LEFT JOIN services s ON c.service_id = s.id
        WHERE c.professional_id = $1
        ORDER BY c.date DESC
      `;
      params = [req.user.id];
    } else if (req.user.currentRole === 'admin' || userRoles.includes('admin')) {
      // For admins, get all consultations
      query = `
        SELECT c.*, 
               COALESCE(pp.name, cl.name, d.name) as client_name,
               p.name as professional_name,
               s.name as service_name,
               CASE 
                 WHEN c.dependent_id IS NOT NULL THEN true
                 ELSE false
               END as is_dependent
        FROM consultations c
        LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
        LEFT JOIN users cl ON c.client_id = cl.id
        LEFT JOIN dependents d ON c.dependent_id = d.id
        JOIN users p ON c.professional_id = p.id
        LEFT JOIN services s ON c.service_id = s.id
        ORDER BY c.date DESC
      `;
      params = [];
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
      appointment_date,
      appointment_time,
      create_appointment
    } = req.body;

    if (!service_id || !value || !date) {
      return res.status(400).json({ message: 'Serviço, valor e data são obrigatórios' });
    }

    // Validate that at least one patient type is provided
    if (!client_id && !dependent_id && !private_patient_id) {
      return res.status(400).json({ message: 'É necessário especificar um cliente, dependente ou paciente particular' });
    }

    const client = await pool.connect();
    
    try {
      await client.query('BEGIN');
      
      // Create consultation
      const consultationResult = await client.query(
        `INSERT INTO consultations 
         (professional_id, client_id, dependent_id, private_patient_id, service_id, location_id, value, date)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *`,
        [req.user.id, client_id, dependent_id, private_patient_id, service_id, location_id, value, date]
      );

      const consultation = consultationResult.rows[0];
      
      // Create appointment if requested
      if (create_appointment && appointment_date && appointment_time) {
        // Get consultation duration from settings
        const settingsResult = await client.query(
          `SELECT consultation_duration FROM professional_schedule_settings WHERE professional_id = $1`,
          [req.user.id]
        );
        
        const consultationDuration = settingsResult.rows[0]?.consultation_duration || 60;
        
        const appointmentResult = await client.query(
          `INSERT INTO appointments 
           (professional_id, private_patient_id, client_id, dependent_id, service_id,
            appointment_date, appointment_time, location_id, value, status, consultation_duration, consultation_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'completed', $10, $11)`,
          [req.user.id, private_patient_id, client_id, dependent_id, service_id, 
           appointment_date, appointment_time, location_id, value, consultationDuration, consultation.id]
        );
      }
      
      await client.query('COMMIT');
      res.status(201).json(consultation);
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Dependents routes
// 🔥 IMPORTANT: Lookup route MUST come before /:id route
app.get('/api/dependents/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    // Clean CPF
    const cleanCpf = cpf.toString().replace(/\D/g, '');

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    // Find dependent by CPF with client info
    const result = await pool.query(
      `SELECT d.*, 
              c.name as client_name,
              c.subscription_status as client_subscription_status
       FROM dependents d
       JOIN users c ON d.client_id = c.id
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

app.get('/api/dependents/:client_id', authenticate, async (req, res) => {
  try {
    const { client_id } = req.params;

    const result = await pool.query(
      'SELECT * FROM dependents WHERE client_id = $1 ORDER BY name',
      [client_id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching dependents:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/dependents', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    if (!name || !cpf) {
      return res.status(400).json({ message: 'Nome e CPF são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    // Check if CPF already exists
    const existingDependent = await pool.query(
      'SELECT id FROM dependents WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingDependent.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado como dependente' });
    }

    // Check if CPF exists as user
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado como usuário' });
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

app.put('/api/dependents/:id', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    const result = await pool.query(
      `UPDATE dependents 
       SET name = $1, birth_date = $2, updated_at = CURRENT_TIMESTAMP
       WHERE id = $3 AND client_id = $4
       RETURNING *`,
      [name, birth_date, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.delete('/api/dependents/:id', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM dependents WHERE id = $1 AND client_id = $2 RETURNING *',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json({ message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Professionals routes
app.get('/api/professionals', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.phone, u.address, u.address_number, 
              u.address_complement, u.neighborhood, u.city, u.state, u.roles, u.photo_url,
              sc.name as category_name
       FROM users u
       LEFT JOIN service_categories sc ON u.category_id = sc.id
       WHERE u.roles @> ARRAY['professional']
       ORDER BY u.name`
    );

    // Parse roles for each professional
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

// Clients lookup route
app.get('/api/clients/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    // Clean CPF
    const cleanCpf = cpf.toString().replace(/\D/g, '');

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    // Find client by CPF
    const result = await pool.query(
      `SELECT id, name, cpf, email, phone, roles, subscription_status, subscription_expiry
       FROM users 
       WHERE cpf = $1 AND roles @> ARRAY['client']`,
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

// Reports routes
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Datas de início e fim são obrigatórias' });
    }

    // Get revenue by professional
    const professionalRevenueResult = await pool.query(
      `SELECT 
        p.name as professional_name,
        p.percentage as professional_percentage,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count,
        SUM(c.value * (p.percentage / 100.0)) as professional_payment,
        SUM(c.value * ((100 - p.percentage) / 100.0)) as clinic_revenue
        FROM consultations c
        JOIN users p ON c.professional_id = p.id
        LEFT JOIN services s ON c.service_id = s.id
        WHERE p.roles @> ARRAY['professional']
        AND c.date >= $1 AND c.date <= $2
        GROUP BY p.id, p.name, p.percentage
        ORDER BY revenue DESC`,
      [start_date, end_date]
    );

    // Get revenue by service
    const serviceRevenueResult = await pool.query(
      `SELECT 
        s.name as service_name,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count
        FROM consultations c
        JOIN services s ON c.service_id = s.id
        WHERE c.date >= $1 AND c.date <= $2
        GROUP BY s.id, s.name
        ORDER BY revenue DESC`,
      [start_date, end_date]
    );

    // Calculate total revenue
    const totalRevenue = professionalRevenueResult.rows.reduce((sum, row) => sum + parseFloat(row.revenue), 0);

    res.json({
      total_revenue: totalRevenue,
      revenue_by_professional: professionalRevenueResult.rows,
      revenue_by_service: serviceRevenueResult.rows
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
      return res.status(400).json({ message: 'Datas de início e fim são obrigatórias' });
    }

    console.log('🔍 Fetching professional revenue for user:', req.user.id);
    console.log('🔍 Date range:', { start_date, end_date });

    // Get professional's percentage
    const professionalResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = professionalResult.rows[0]?.percentage || 50;

    // Get consultations for this professional
    const consultationsResult = await pool.query(
      `SELECT 
         c.id,
         c.date,
         c.value as total_value,
         c.value * ($3 / 100.0) as professional_payment,
         c.value * ((100 - $3) / 100.0) as amount_to_pay,
         s.name as service_name,
         COALESCE(pp.name, cl.name, d.name) as client_name,
         CASE 
           WHEN pp.id IS NOT NULL THEN 'particular'
           WHEN cl.id IS NOT NULL THEN 'convenio'
           WHEN d.id IS NOT NULL THEN 'dependente'
           ELSE 'unknown'
         END as patient_type
       FROM consultations c
       LEFT JOIN services s ON c.service_id = s.id
       LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
       LEFT JOIN users cl ON c.client_id = cl.id
       LEFT JOIN dependents d ON c.dependent_id = d.id
       WHERE c.professional_id = $1
       AND c.date >= $2 AND c.date <= $4
       ORDER BY c.date DESC`,
      [req.user.id, start_date, professionalPercentage, end_date]
    );

    // Calculate summary
    const consultations = consultationsResult.rows;
    const totalRevenue = consultations.reduce((sum, c) => sum + parseFloat(c.total_value), 0);
    const totalAmountToPay = consultations.reduce((sum, c) => sum + parseFloat(c.amount_to_pay), 0);
    const convenioConsultations = consultations.filter(c => c.patient_type === 'convenio' || c.patient_type === 'dependente').length;
    const privateConsultations = consultations.filter(c => c.patient_type === 'particular').length;
    const convenioRevenue = consultations
      .filter(c => c.patient_type === 'convenio' || c.patient_type === 'dependente')
      .reduce((sum, c) => sum + parseFloat(c.total_value), 0);
    const privateRevenue = consultations
      .filter(c => c.patient_type === 'particular')
      .reduce((sum, c) => sum + parseFloat(c.total_value), 0);

    const summary = {
      total_consultations: consultations.length,
      convenio_consultations: convenioConsultations,
      private_consultations: privateConsultations,
      total_revenue: totalRevenue,
      convenio_revenue: convenioRevenue,
      private_revenue: privateRevenue,
      professional_percentage: professionalPercentage,
      amount_to_pay: totalAmountToPay
    };

    console.log('✅ Professional revenue summary:', summary);

    res.json({
      summary,
      consultations: consultations.map(c => ({
        date: c.date,
        client_name: c.client_name,
        service_name: c.service_name,
        total_value: parseFloat(c.total_value),
        amount_to_pay: parseFloat(c.amount_to_pay),
        patient_type: c.patient_type
      }))
    });
  } catch (error) {
    console.error('❌ Error fetching professional revenue:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get detailed professional report
app.get('/api/reports/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Datas de início e fim são obrigatórias' });
    }

    // Get professional's percentage
    const professionalResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = professionalResult.rows[0]?.percentage || 50;

    // Get detailed consultations
    const consultationsResult = await pool.query(
      `SELECT 
         c.id,
         c.date,
         c.value as total_value,
         s.name as service_name,
         COALESCE(pp.name, cl.name, d.name) as client_name,
         CASE 
           WHEN pp.id IS NOT NULL THEN 'particular'
           WHEN cl.id IS NOT NULL THEN 'convenio'
           WHEN d.id IS NOT NULL THEN 'dependente'
           ELSE 'unknown'
         END as patient_type
       FROM consultations c
       LEFT JOIN services s ON c.service_id = s.id
       LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
       LEFT JOIN users cl ON c.client_id = cl.id
       LEFT JOIN dependents d ON c.dependent_id = d.id
       WHERE c.professional_id = $1
       AND c.date >= $2 AND c.date <= $3
       ORDER BY c.date DESC`,
      [req.user.id, start_date, end_date]
    );

    const consultations = consultationsResult.rows;
    
    // Calculate metrics
    const convenioConsultations = consultations.filter(c => c.patient_type === 'convenio' || c.patient_type === 'dependente');
    const privateConsultations = consultations.filter(c => c.patient_type === 'particular');
    
    const convenioRevenue = convenioConsultations.reduce((sum, c) => sum + parseFloat(c.total_value), 0);
    const privateRevenue = privateConsultations.reduce((sum, c) => sum + parseFloat(c.total_value), 0);
    const totalRevenue = convenioRevenue + privateRevenue;
    
    // Calculate what professional owes to clinic (only from convenio consultations)
    const amountToPay = convenioRevenue * ((100 - professionalPercentage) / 100);

    const summary = {
      total_consultations: consultations.length,
      convenio_consultations: convenioConsultations.length,
      private_consultations: privateConsultations.length,
      total_revenue: totalRevenue,
      convenio_revenue: convenioRevenue,
      private_revenue: privateRevenue,
      professional_percentage: professionalPercentage,
      amount_to_pay: amountToPay
    };

    res.json({ summary });
  } catch (error) {
    console.error('Error fetching detailed professional report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Private patients routes
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

    // Check if CPF already exists for this professional
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

app.delete('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    // Check if patient has appointments
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

// Attendance locations routes
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

    // If this is set as default, remove default from others
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

    // If this is set as default, remove default from others
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

app.delete('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    // Check if location has appointments
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

// Scheduling routes
app.get('/api/scheduling/settings', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM professional_schedule_settings WHERE professional_id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      // Return default settings if none exist
      return res.json({
        professional_id: req.user.id,
        work_days: [1, 2, 3, 4, 5], // Monday to Friday
        work_start_time: '08:00',
        work_end_time: '18:00',
        break_start_time: '12:00',
        break_end_time: '13:00',
        consultation_duration: 60,
        has_scheduling_subscription: true
      });
    }

    // Ensure all professionals have scheduling access
    const settings = result.rows[0];
    settings.has_scheduling_subscription = true;

    res.json(settings);
  } catch (error) {
    console.error('Error fetching schedule settings:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

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
       (professional_id, work_days, work_start_time, work_end_time, break_start_time, break_end_time, consultation_duration)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (professional_id) 
       DO UPDATE SET 
         work_days = $2,
         work_start_time = $3,
         work_end_time = $4,
         break_start_time = $5,
         break_end_time = $6,
         consultation_duration = $7,
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

// Scheduling subscription status (always active for all professionals)
app.get('/api/scheduling-payment/subscription-status', authenticate, authorize(['professional']), async (req, res) => {
  try {
    // 🔥 LIBERADO: Todos os profissionais têm acesso à agenda
    res.json({
      has_subscription: true,
      status: 'active',
      expires_at: null,
      created_at: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching subscription status:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Admin routes for scheduling access management
app.get('/api/admin/professionals-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         u.id,
         u.name,
         u.email,
         u.phone,
         sc.name as category_name,
         true as has_scheduling_access,
         null as access_expires_at,
         'Sistema' as access_granted_by,
         u.created_at as access_granted_at
       FROM users u
       LEFT JOIN service_categories sc ON u.category_id = sc.id
       WHERE u.roles @> ARRAY['professional']
       ORDER BY u.name`
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/admin/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id } = req.body;

    if (!professional_id) {
      return res.status(400).json({ message: 'ID do profissional é obrigatório' });
    }

    // Since scheduling is free for all, just return success
    res.json({
      message: 'Acesso à agenda já está liberado para todos os profissionais',
      subscription: {
        professional_id,
        status: 'active',
        expires_at: null,
        granted_by: 'Sistema',
        granted_at: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Error granting access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/admin/revoke-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    res.json({ 
      message: 'O acesso à agenda está liberado para todos os profissionais e não pode ser revogado' 
    });
  } catch (error) {
    console.error('Error revoking access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Payment routes
app.post('/api/create-subscription', authenticate, authorize(['client']), async (req, res) => {
  try {
    if (!mpClient || !Preference) {
      return res.status(503).json({ message: 'Serviço de pagamento não disponível' });
    }

    console.log('🔄 Creating subscription for client:', req.user.id);

    // Check if client already has active subscription
    const existingSubscription = await pool.query(
      `SELECT * FROM users 
       WHERE id = $1 AND subscription_status = 'active' AND subscription_expiry > NOW()`,
      [req.user.id]
    );

    if (existingSubscription.rows.length > 0) {
      return res.status(400).json({ 
        message: 'Você já possui uma assinatura ativa' 
      });
    }

    // Get dependents count for pricing
    const dependentsResult = await pool.query(
      `SELECT COUNT(*) as count FROM dependents WHERE client_id = $1`,
      [req.user.id]
    );

    const dependentCount = parseInt(dependentsResult.rows[0].count) || 0;
    const basePrice = 250; // R$ 250 for titular
    const dependentPrice = 50; // R$ 50 per dependent
    const totalAmount = basePrice + (dependentCount * dependentPrice);

    const preference = new Preference(mpClient);

    const items = [
      {
        title: 'Assinatura Cartão Quiro Ferreira - Titular',
        description: 'Assinatura mensal do cartão de convênio',
        quantity: 1,
        unit_price: basePrice,
        currency_id: 'BRL',
      }
    ];

    // Add dependent items if any
    if (dependentCount > 0) {
      items.push({
        title: `Dependentes (${dependentCount})`,
        description: 'Taxa adicional por dependente',
        quantity: dependentCount,
        unit_price: dependentPrice,
        currency_id: 'BRL',
      });
    }

    const preferenceData = {
      items,
      payer: {
        name: req.user.name,
        email: req.user.email || `client${req.user.id}@quiroferreira.com.br`,
      },
      back_urls: {
        success: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/client/payment-success`,
        failure: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/client/payment-failure`,
        pending: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/client/payment-pending`,
      },
      auto_return: 'approved',
      external_reference: `subscription_${req.user.id}_${Date.now()}`,
      notification_url: `${process.env.API_URL || 'http://localhost:3001'}/api/payment/webhook`,
      statement_descriptor: 'QUIRO FERREIRA',
      expires: true,
      expiration_date_from: new Date().toISOString(),
      expiration_date_to: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24 hours
    };

    console.log('🔄 Creating MercadoPago preference:', preferenceData);

    const result = await preference.create({ body: preferenceData });

    console.log('✅ MercadoPago preference created:', result);

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point,
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

app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    if (!mpClient || !Preference) {
      return res.status(503).json({ message: 'Serviço de pagamento não disponível' });
    }

    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor inválido' });
    }

    console.log('🔄 Creating professional payment for:', req.user.id, 'Amount:', amount);

    const preference = new Preference(mpClient);

    const preferenceData = {
      items: [
        {
          title: 'Repasse ao Convênio Quiro Ferreira',
          description: 'Pagamento referente às consultas realizadas',
          quantity: 1,
          unit_price: Number(amount),
          currency_id: 'BRL',
        }
      ],
      payer: {
        name: req.user.name,
        email: req.user.email || `professional${req.user.id}@quiroferreira.com.br`,
      },
      back_urls: {
        success: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/payment-success`,
        failure: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/payment-failure`,
        pending: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/payment-pending`,
      },
      auto_return: 'approved',
      external_reference: `professional_${req.user.id}_${Date.now()}`,
      notification_url: `${process.env.API_URL || 'http://localhost:3001'}/api/payment/webhook`,
      statement_descriptor: 'QUIRO FERREIRA REPASSE',
    };

    const result = await preference.create({ body: preferenceData });

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point,
    });
  } catch (error) {
    console.error('❌ Error creating professional payment:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento',
      error: error.message 
    });
  }
});

app.post('/api/payment/webhook', async (req, res) => {
  try {
    console.log('🔔 Payment webhook received:', req.body);
    const { type, data } = req.body;

    if (type === 'payment') {
      const paymentId = data.id;
      console.log('✅ Payment webhook processed for payment ID:', paymentId);
    }

    res.status(200).json({ received: true });
  } catch (error) {
    console.error('❌ Error processing payment webhook:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Image upload route
app.post('/api/upload-image', authenticate, authorize(['professional']), async (req, res) => {
  try {
    console.log('🔄 Starting image upload process...');
    
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
        console.error('❌ No file received');
        return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
      }

      console.log('✅ File uploaded successfully:', {
        filename: req.file.filename,
        path: req.file.path,
        size: req.file.size
      });

      try {
        // Update user's photo_url in database
        const result = await pool.query(
          'UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING photo_url',
          [req.file.path, req.user.id]
        );

        if (result.rows.length === 0) {
          return res.status(404).json({ message: 'Usuário não encontrado' });
        }

        res.json({
          message: 'Imagem enviada com sucesso',
          imageUrl: req.file.path
        });
      } catch (dbError) {
        console.error('❌ Database error:', dbError);
        res.status(500).json({ message: 'Erro ao salvar URL da imagem no banco de dados' });
      }
    });
  } catch (error) {
    console.error('❌ Upload route error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Medical documents routes
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

app.post('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      private_patient_id,
      client_id,
      dependent_id,
      document_type,
      title,
      template_data
    } = req.body;

    // Generate document URL (in production, this would generate actual PDF)
    const documentUrl = `${process.env.API_URL || 'http://localhost:3001'}/documents/${Date.now()}_${document_type}.pdf`;

    const result = await pool.query(
      `INSERT INTO medical_documents 
       (professional_id, private_patient_id, client_id, dependent_id, 
        document_type, title, document_url, template_data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [req.user.id, private_patient_id, client_id, dependent_id, 
       document_type, title, documentUrl, template_data]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating medical document:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Medical records routes
app.get('/api/medical-records/patient/:patientId/:patientType', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { patientId, patientType } = req.params;

    let whereClause = '';
    if (patientType === 'private') {
      whereClause = 'private_patient_id = $2';
    } else if (patientType === 'client') {
      whereClause = 'client_id = $2';
    } else if (patientType === 'dependent') {
      whereClause = 'dependent_id = $2';
    }

    const result = await pool.query(
      `SELECT mr.*, 
              COALESCE(pp.name, c.name, d.name) as patient_name
       FROM medical_records mr
       LEFT JOIN private_patients pp ON mr.private_patient_id = pp.id
       LEFT JOIN users c ON mr.client_id = c.id
       LEFT JOIN dependents d ON mr.dependent_id = d.id
       WHERE mr.professional_id = $1 AND ${whereClause}
       ORDER BY mr.created_at DESC`,
      [req.user.id, patientId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical records:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

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

// Appointments routes
app.get('/api/appointments', authenticate, authorize(['professional']), async (req, res) => {
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

// Get available time slots for a specific date
app.get('/api/scheduling/available-slots', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { date } = req.query;

    if (!date) {
      return res.status(400).json({ message: 'Data é obrigatória' });
    }

    // Get professional's schedule settings
    const settingsResult = await pool.query(
      `SELECT * FROM professional_schedule_settings WHERE professional_id = $1`,
      [req.user.id]
    );

    const settings = settingsResult.rows[0] || {
      work_days: [1, 2, 3, 4, 5],
      work_start_time: '08:00',
      work_end_time: '18:00',
      break_start_time: '12:00',
      break_end_time: '13:00',
      consultation_duration: 60
    };

    // Check if the date is a working day
    const dayOfWeek = new Date(date).getDay();
    if (!settings.work_days.includes(dayOfWeek)) {
      return res.json({ available_slots: [], message: 'Dia não é dia de trabalho' });
    }

    // Get existing appointments for this date
    const appointmentsResult = await pool.query(
      `SELECT appointment_time, consultation_duration FROM appointments 
       WHERE professional_id = $1 AND appointment_date = $2 AND status != 'cancelled'`,
      [req.user.id, date]
    );

    const bookedSlots = appointmentsResult.rows.map(apt => ({
      time: apt.appointment_time,
      duration: apt.consultation_duration || settings.consultation_duration
    }));

    // Generate available slots
    const slots = [];
    const startTime = settings.work_start_time;
    const endTime = settings.work_end_time;
    const breakStart = settings.break_start_time;
    const breakEnd = settings.break_end_time;
    const duration = settings.consultation_duration;

    let currentTime = new Date(`2000-01-01T${startTime}`);
    const endDateTime = new Date(`2000-01-01T${endTime}`);
    const breakStartTime = new Date(`2000-01-01T${breakStart}`);
    const breakEndTime = new Date(`2000-01-01T${breakEnd}`);

    while (currentTime < endDateTime) {
      const timeString = currentTime.toTimeString().slice(0, 5);
      const slotEndTime = new Date(currentTime.getTime() + duration * 60000);

      // Check if slot conflicts with break time
      const isInBreak = currentTime >= breakStartTime && currentTime < breakEndTime;
      
      // Check if slot conflicts with existing appointments
      const isBooked = bookedSlots.some(booked => {
        const bookedStart = new Date(`2000-01-01T${booked.time}`);
        const bookedEnd = new Date(bookedStart.getTime() + booked.duration * 60000);
        return (currentTime >= bookedStart && currentTime < bookedEnd) ||
               (slotEndTime > bookedStart && slotEndTime <= bookedEnd);
      });

      if (!isInBreak && !isBooked) {
        slots.push({
          time: timeString,
          available: true,
          duration: duration
        });
      }

      currentTime = new Date(currentTime.getTime() + duration * 60000);
    }

    res.json({ available_slots: slots });
  } catch (error) {
    console.error('Error fetching available slots:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/appointments', authenticate, authorize(['professional']), async (req, res) => {
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

    // Get consultation duration from settings
    const settingsResult = await pool.query(
      `SELECT consultation_duration FROM professional_schedule_settings WHERE professional_id = $1`,
      [req.user.id]
    );
    
    const consultationDuration = settingsResult.rows[0]?.consultation_duration || 60;

    const result = await pool.query(
      `INSERT INTO appointments 
       (professional_id, private_patient_id, client_id, dependent_id, service_id,
        appointment_date, appointment_time, location_id, notes, value, status, consultation_duration)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'scheduled', $11)
       RETURNING *`,
      [req.user.id, private_patient_id, client_id, dependent_id, service_id, 
       appointment_date, appointment_time, location_id, notes, value, consultationDuration]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating appointment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.put('/api/appointments/:id', authenticate, authorize(['professional']), async (req, res) => {
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

app.delete('/api/appointments/:id', authenticate, authorize(['professional']), async (req, res) => {
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

// Health check route
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Serve React app for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.resolve(__dirname, '../dist/index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ message: 'Erro interno do servidor' });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
  
  if (process.env.NODE_ENV !== 'production') {
    console.log(`📱 Frontend: http://localhost:${PORT}`);
    console.log(`🔗 API: http://localhost:${PORT}/api`);
  }
});