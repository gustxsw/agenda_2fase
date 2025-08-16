const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { MercadoPagoConfig, Preference } = require('mercadopago');
const { pool } = require('./db.js');
const { authenticate, authorize } = require('./middleware/auth.js');
const createUpload = require('./middleware/upload.js');
const { generateDocumentPDF } = require('./utils/documentGenerator.js');
const { ensureSignatureColumn } = require('./database/signatureColumn.js');
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';
import { ensureSignatureColumn } from './database/signatureColumn.js';
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
  options: { timeout: 5000 }
});

const preference = new Preference(client);
const payment = new Payment(client);

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:3000',
      'https://cartaoquiroferreira.com.br',
      'https://www.cartaoquiroferreira.com.br'
    ];
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Serve static files
app.use(express.static('dist'));

// Database initialization
const initializeDatabase = async () => {
  try {
    console.log('🔄 Initializing database...');
    
    // Create tables if they don't exist
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
        password_hash VARCHAR(255) NOT NULL,
        roles TEXT[] DEFAULT ARRAY['client'],
        percentage INTEGER DEFAULT 50,
        category_id INTEGER,
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry TIMESTAMP,
        photo_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS service_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS dependents (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) UNIQUE NOT NULL,
        birth_date DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS private_patients (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS attendance_locations (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        private_patient_id INTEGER REFERENCES private_patients(id),
        professional_id INTEGER REFERENCES users(id) NOT NULL,
        service_id INTEGER REFERENCES services(id) NOT NULL,
        location_id INTEGER REFERENCES attendance_locations(id),
        value DECIMAL(10,2) NOT NULL,
        date TIMESTAMP NOT NULL,
        status VARCHAR(20) DEFAULT 'completed',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_records (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) NOT NULL,
        private_patient_id INTEGER REFERENCES private_patients(id) NOT NULL,
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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_documents (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) NOT NULL,
        private_patient_id INTEGER REFERENCES private_patients(id),
        title VARCHAR(255) NOT NULL,
        document_type VARCHAR(50) NOT NULL,
        document_url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS scheduling_access (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        granted_by INTEGER REFERENCES users(id),
        expires_at TIMESTAMP,
        reason TEXT,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 🔥 NEW: Payment tables
    await pool.query(`
      CREATE TABLE IF NOT EXISTS client_payments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        preference_id VARCHAR(255) NOT NULL,
        payment_id VARCHAR(255),
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        payment_method VARCHAR(100),
        payment_type VARCHAR(100),
        external_reference VARCHAR(255),
        description TEXT,
        payer_email VARCHAR(255),
        date_approved TIMESTAMP,
        date_created TIMESTAMP,
        last_modified TIMESTAMP,
        webhook_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_payments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        preference_id VARCHAR(255) NOT NULL,
        payment_id VARCHAR(255),
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        payment_method VARCHAR(100),
        payment_type VARCHAR(100),
        external_reference VARCHAR(255),
        description TEXT,
        payer_email VARCHAR(255),
        date_approved TIMESTAMP,
        date_created TIMESTAMP,
        last_modified TIMESTAMP,
        webhook_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS scheduling_payments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        preference_id VARCHAR(255) NOT NULL,
        payment_id VARCHAR(255),
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        payment_method VARCHAR(100),
        payment_type VARCHAR(100),
        external_reference VARCHAR(255),
        description TEXT,
        payer_email VARCHAR(255),
        date_approved TIMESTAMP,
        date_created TIMESTAMP,
        last_modified TIMESTAMP,
        webhook_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Ensure signature column exists
    await ensureSignatureColumn();

    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
    throw error;
  }
};

// Initialize database on startup
initializeDatabase().catch(console.error);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ==================== AUTH ROUTES ====================

// Login route
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return res.status(400).json({ message: 'CPF e senha são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    const result = await pool.query(
      'SELECT id, name, cpf, roles, password_hash FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password_hash);

    if (!isValidPassword) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    res.json({
      user: {
        id: user.id,
        name: user.name,
        cpf: user.cpf,
        roles: user.roles || ['client']
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Role selection route
app.post('/api/auth/select-role', async (req, res) => {
  try {
    const { userId, role } = req.body;

    if (!userId || !role) {
      return res.status(400).json({ message: 'User ID e role são obrigatórios' });
    }

    const result = await pool.query(
      'SELECT id, name, cpf, roles FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];

    if (!user.roles || !user.roles.includes(role)) {
      return res.status(403).json({ message: 'Role não autorizada para este usuário' });
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
    console.error('Role selection error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Switch role route
app.post('/api/auth/switch-role', authenticate, async (req, res) => {
  try {
    const { role } = req.body;
    const userId = req.user.id;

    if (!role) {
      return res.status(400).json({ message: 'Role é obrigatória' });
    }

    const result = await pool.query(
      'SELECT id, name, cpf, roles FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];

    if (!user.roles || !user.roles.includes(role)) {
      return res.status(403).json({ message: 'Role não autorizada para este usuário' });
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
    console.error('Switch role error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
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
      return res.status(409).json({ message: 'CPF já cadastrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password_hash, roles
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING id, name, cpf, roles`,
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

    const user = result.rows[0];

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      user: {
        id: user.id,
        name: user.name,
        cpf: user.cpf,
        roles: user.roles
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    if (error.code === '23505') {
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

// ==================== USER ROUTES ====================

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
    res.status(500).json({ message: 'Erro ao buscar usuários' });
  }
});

// Get user by ID
app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    
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
    res.status(500).json({ message: 'Erro ao buscar usuário' });
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

    if (!name || !cpf || !password || !roles || roles.length === 0) {
      return res.status(400).json({ message: 'Campos obrigatórios não preenchidos' });
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
      return res.status(409).json({ message: 'CPF já cadastrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password_hash, roles,
        percentage, category_id
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      RETURNING id, name, cpf, roles`,
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
        roles,
        roles.includes('professional') ? percentage : null,
        roles.includes('professional') ? category_id : null
      ]
    );

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating user:', error);
    if (error.code === '23505') {
      res.status(409).json({ message: 'CPF já cadastrado' });
    } else {
      res.status(500).json({ message: 'Erro interno do servidor' });
    }
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

    // Check if user can update this profile
    if (req.user.currentRole !== 'admin' && req.user.id !== parseInt(id)) {
      return res.status(403).json({ message: 'Não autorizado a editar este usuário' });
    }

    let updateQuery = `
      UPDATE users SET 
        name = $1, email = $2, phone = $3, birth_date = $4,
        address = $5, address_number = $6, address_complement = $7,
        neighborhood = $8, city = $9, state = $10, updated_at = CURRENT_TIMESTAMP
    `;
    let queryParams = [
      name?.trim(),
      email?.trim() || null,
      phone?.replace(/\D/g, '') || null,
      birth_date || null,
      address?.trim() || null,
      address_number?.trim() || null,
      address_complement?.trim() || null,
      neighborhood?.trim() || null,
      city?.trim() || null,
      state || null
    ];

    let paramIndex = 11;

    // Only admin can update roles
    if (req.user.currentRole === 'admin' && roles) {
      updateQuery += `, roles = $${paramIndex}`;
      queryParams.push(roles);
      paramIndex++;

      if (roles.includes('professional')) {
        updateQuery += `, percentage = $${paramIndex}, category_id = $${paramIndex + 1}`;
        queryParams.push(percentage, category_id);
        paramIndex += 2;
      }
    }

    // Handle password change
    if (newPassword && currentPassword) {
      const userResult = await pool.query(
        'SELECT password_hash FROM users WHERE id = $1',
        [id]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
      }

      const isValidPassword = await bcrypt.compare(currentPassword, userResult.rows[0].password_hash);
      if (!isValidPassword) {
        return res.status(400).json({ message: 'Senha atual incorreta' });
      }

      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      updateQuery += `, password_hash = $${paramIndex}`;
      queryParams.push(hashedNewPassword);
      paramIndex++;
    }

    updateQuery += ` WHERE id = $${paramIndex} RETURNING id, name, cpf, roles`;
    queryParams.push(id);

    const result = await pool.query(updateQuery, queryParams);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json({
      message: 'Usuário atualizado com sucesso',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating user:', error);
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

    const result = await pool.query(
      `UPDATE users SET 
        subscription_status = 'active',
        subscription_expiry = $1,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $2 AND 'client' = ANY(roles)
      RETURNING id, name, subscription_status, subscription_expiry`,
      [expiry_date, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    res.json({
      message: 'Cliente ativado com sucesso',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('Error activating client:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete user (admin only)
app.delete('/api/users/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM users WHERE id = $1 RETURNING id',
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

// ==================== SERVICE CATEGORY ROUTES ====================

// Get all service categories
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM service_categories ORDER BY name'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching service categories:', error);
    res.status(500).json({ message: 'Erro ao buscar categorias' });
  }
});

// Create service category (admin only)
app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    const result = await pool.query(
      'INSERT INTO service_categories (name, description) VALUES ($1, $2) RETURNING *',
      [name.trim(), description?.trim() || null]
    );

    res.status(201).json({
      message: 'Categoria criada com sucesso',
      category: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating service category:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== SERVICE ROUTES ====================

// Get all services
app.get('/api/services', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.*, sc.name as category_name
      FROM services s
      LEFT JOIN service_categories sc ON s.category_id = sc.id
      ORDER BY s.name
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({ message: 'Erro ao buscar serviços' });
  }
});

// Create service (admin only)
app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !description || !base_price) {
      return res.status(400).json({ message: 'Nome, descrição e preço são obrigatórios' });
    }

    const result = await pool.query(
      `INSERT INTO services (name, description, base_price, category_id, is_base_service)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [name.trim(), description.trim(), base_price, category_id || null, is_base_service || false]
    );

    res.status(201).json({
      message: 'Serviço criado com sucesso',
      service: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update service (admin only)
app.put('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, base_price, category_id, is_base_service } = req.body;

    const result = await pool.query(
      `UPDATE services SET 
        name = $1, description = $2, base_price = $3, 
        category_id = $4, is_base_service = $5
       WHERE id = $6 RETURNING *`,
      [name.trim(), description.trim(), base_price, category_id || null, is_base_service || false, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    res.json({
      message: 'Serviço atualizado com sucesso',
      service: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete service (admin only)
app.delete('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM services WHERE id = $1 RETURNING id',
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

// ==================== DEPENDENT ROUTES ====================

// Get dependents by client ID
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;

    const result = await pool.query(
      'SELECT * FROM dependents WHERE client_id = $1 ORDER BY name',
      [clientId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching dependents:', error);
    res.status(500).json({ message: 'Erro ao buscar dependentes' });
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
    res.status(500).json({ message: 'Erro ao buscar dependente' });
  }
});

// Create dependent
app.post('/api/dependents', authenticate, async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    if (!client_id || !name || !cpf) {
      return res.status(400).json({ message: 'Client ID, nome e CPF são obrigatórios' });
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
      return res.status(409).json({ message: 'CPF já cadastrado como dependente' });
    }

    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'CPF já cadastrado como usuário' });
    }

    const result = await pool.query(
      'INSERT INTO dependents (client_id, name, cpf, birth_date) VALUES ($1, $2, $3, $4) RETURNING *',
      [client_id, name.trim(), cleanCpf, birth_date || null]
    );

    res.status(201).json({
      message: 'Dependente criado com sucesso',
      dependent: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating dependent:', error);
    if (error.code === '23505') {
      res.status(409).json({ message: 'CPF já cadastrado' });
    } else {
      res.status(500).json({ message: 'Erro interno do servidor' });
    }
  }
});

// Update dependent
app.put('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    const result = await pool.query(
      'UPDATE dependents SET name = $1, birth_date = $2 WHERE id = $3 RETURNING *',
      [name?.trim(), birth_date || null, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json({
      message: 'Dependente atualizado com sucesso',
      dependent: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete dependent
app.delete('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM dependents WHERE id = $1 RETURNING id',
      [id]
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

// ==================== CLIENT ROUTES ====================

// Lookup client by CPF
app.get('/api/clients/lookup', authenticate, async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    const result = await pool.query(
      `SELECT id, name, cpf, subscription_status, subscription_expiry
       FROM users 
       WHERE cpf = $1 AND 'client' = ANY(roles)`,
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error looking up client:', error);
    res.status(500).json({ message: 'Erro ao buscar cliente' });
  }
});

// ==================== PROFESSIONAL ROUTES ====================

// Get all professionals
app.get('/api/professionals', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone, u.roles,
        u.address, u.address_number, u.address_complement,
        u.neighborhood, u.city, u.state, u.photo_url,
        sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE 'professional' = ANY(u.roles)
      ORDER BY u.name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro ao buscar profissionais' });
  }
});

// ==================== PRIVATE PATIENT ROUTES ====================

// Get private patients for professional
app.get('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM private_patients WHERE professional_id = $1 ORDER BY name',
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching private patients:', error);
    res.status(500).json({ message: 'Erro ao buscar pacientes' });
  }
});

// Create private patient
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

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    const cleanCpf = cpf ? cpf.replace(/\D/g, '') : null;

    if (cleanCpf && !/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    if (cleanCpf) {
      const existingPatient = await pool.query(
        'SELECT id FROM private_patients WHERE cpf = $1 AND professional_id = $2',
        [cleanCpf, req.user.id]
      );

      if (existingPatient.rows.length > 0) {
        return res.status(409).json({ message: 'CPF já cadastrado' });
      }
    }

    const result = await pool.query(
      `INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date,
        address, address_number, address_complement, neighborhood,
        city, state, zip_code
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

    res.status(201).json({
      message: 'Paciente criado com sucesso',
      patient: result.rows[0]
    });
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
      `UPDATE private_patients SET 
        name = $1, email = $2, phone = $3, birth_date = $4,
        address = $5, address_number = $6, address_complement = $7,
        neighborhood = $8, city = $9, state = $10, zip_code = $11
       WHERE id = $12 AND professional_id = $13 RETURNING *`,
      [
        name?.trim(),
        email?.trim() || null,
        phone?.replace(/\D/g, '') || null,
        birth_date || null,
        address?.trim() || null,
        address_number?.trim() || null,
        address_complement?.trim() || null,
        neighborhood?.trim() || null,
        city?.trim() || null,
        state || null,
        zip_code?.replace(/\D/g, '') || null,
        id,
        req.user.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    res.json({
      message: 'Paciente atualizado com sucesso',
      patient: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete private patient
app.delete('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM private_patients WHERE id = $1 AND professional_id = $2 RETURNING id',
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

// ==================== ATTENDANCE LOCATION ROUTES ====================

// Get attendance locations for professional
app.get('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM attendance_locations WHERE professional_id = $1 ORDER BY is_default DESC, name',
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching attendance locations:', error);
    res.status(500).json({ message: 'Erro ao buscar locais de atendimento' });
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
        is_default || false
      ]
    );

    res.status(201).json({
      message: 'Local criado com sucesso',
      location: result.rows[0]
    });
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

    // If setting as default, remove default from other locations
    if (is_default) {
      await pool.query(
        'UPDATE attendance_locations SET is_default = false WHERE professional_id = $1 AND id != $2',
        [req.user.id, id]
      );
    }

    const result = await pool.query(
      `UPDATE attendance_locations SET 
        name = $1, address = $2, address_number = $3, address_complement = $4,
        neighborhood = $5, city = $6, state = $7, zip_code = $8, phone = $9, is_default = $10
       WHERE id = $11 AND professional_id = $12 RETURNING *`,
      [
        name?.trim(),
        address?.trim() || null,
        address_number?.trim() || null,
        address_complement?.trim() || null,
        neighborhood?.trim() || null,
        city?.trim() || null,
        state || null,
        zip_code?.replace(/\D/g, '') || null,
        phone?.replace(/\D/g, '') || null,
        is_default || false,
        id,
        req.user.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Local não encontrado' });
    }

    res.json({
      message: 'Local atualizado com sucesso',
      location: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating attendance location:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete attendance location
app.delete('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM attendance_locations WHERE id = $1 AND professional_id = $2 RETURNING id',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Local não encontrado' });
    }

    res.json({ message: 'Local excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting attendance location:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== CONSULTATION ROUTES ====================

// Get all consultations
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query = `
      SELECT 
        c.id, c.value, c.date, c.status, c.notes,
        COALESCE(u.name, d.name, pp.name) as client_name,
        s.name as service_name,
        prof.name as professional_name,
        CASE 
          WHEN c.dependent_id IS NOT NULL THEN true 
          ELSE false 
        END as is_dependent
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users prof ON c.professional_id = prof.id
    `;

    let queryParams = [];

    if (req.user.currentRole === 'professional') {
      query += ' WHERE c.professional_id = $1';
      queryParams.push(req.user.id);
    }

    query += ' ORDER BY c.date DESC';

    const result = await pool.query(query, queryParams);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching consultations:', error);
    res.status(500).json({ message: 'Erro ao buscar consultas' });
  }
});

// Get consultations by client ID
app.get('/api/consultations/client/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;
    
    console.log('🔍 Fetching consultations for client:', clientId);
    
    // Get consultations for the client and their dependents
    const query = `
      SELECT 
        c.id,
        c.date,
        c.value,
        c.status,
        s.name as service_name,
        u.name as professional_name,
        COALESCE(cl.name, d.name) as client_name,
        CASE WHEN d.id IS NOT NULL THEN true ELSE false END as is_dependent
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      JOIN users u ON c.professional_id = u.id
      LEFT JOIN users cl ON c.client_id = cl.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      WHERE (c.client_id = $1 OR d.client_id = $1)
      AND c.status = 'completed'
      ORDER BY c.date DESC
    `;
    
    const result = await pool.query(query, [clientId]);
    
    console.log(`✅ Found ${result.rows.length} completed consultations for client`);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching client consultations:', error);
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

    if (!client_id && !dependent_id && !private_patient_id) {
      return res.status(400).json({ message: 'É necessário especificar um cliente, dependente ou paciente particular' });
    }

    const result = await pool.query(
      `INSERT INTO consultations (
        client_id, dependent_id, private_patient_id, professional_id,
        service_id, location_id, value, date, status, notes
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *`,
      [
        client_id || null,
        dependent_id || null,
        private_patient_id || null,
        req.user.id,
        service_id,
        location_id || null,
        value,
        date,
        status || 'completed',
        notes || null
      ]
    );

    res.status(201).json({
      message: 'Consulta registrada com sucesso',
      consultation: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
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

    const result = await pool.query(
      'UPDATE consultations SET status = $1 WHERE id = $2 AND professional_id = $3 RETURNING *',
      [status, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Consulta não encontrada' });
    }

    res.json({
      message: 'Status atualizado com sucesso',
      consultation: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating consultation status:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== MEDICAL RECORDS ROUTES ====================

// Get medical records for professional
app.get('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        mr.*,
        pp.name as patient_name
      FROM medical_records mr
      JOIN private_patients pp ON mr.private_patient_id = pp.id
      WHERE mr.professional_id = $1
      ORDER BY mr.created_at DESC
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical records:', error);
    res.status(500).json({ message: 'Erro ao buscar prontuários' });
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

    if (!private_patient_id) {
      return res.status(400).json({ message: 'Paciente é obrigatório' });
    }

    const result = await pool.query(
      `INSERT INTO medical_records (
        professional_id, private_patient_id, chief_complaint,
        history_present_illness, past_medical_history, medications,
        allergies, physical_examination, diagnosis, treatment_plan,
        notes, vital_signs
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *`,
      [
        req.user.id,
        private_patient_id,
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

    res.status(201).json({
      message: 'Prontuário criado com sucesso',
      record: result.rows[0]
    });
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
      `UPDATE medical_records SET 
        chief_complaint = $1, history_present_illness = $2,
        past_medical_history = $3, medications = $4, allergies = $5,
        physical_examination = $6, diagnosis = $7, treatment_plan = $8,
        notes = $9, vital_signs = $10, updated_at = CURRENT_TIMESTAMP
       WHERE id = $11 AND professional_id = $12 RETURNING *`,
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
        id,
        req.user.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    res.json({
      message: 'Prontuário atualizado com sucesso',
      record: result.rows[0]
    });
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
      'DELETE FROM medical_records WHERE id = $1 AND professional_id = $2 RETURNING id',
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

// Generate medical record document
app.post('/api/medical-records/generate-document', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { record_id, template_data } = req.body;

    if (!record_id || !template_data) {
      return res.status(400).json({ message: 'ID do prontuário e dados do template são obrigatórios' });
    }

    const documentResult = await generateDocumentPDF('medical_record', template_data);

    res.json({
      message: 'Documento gerado com sucesso',
      documentUrl: documentResult.url
    });
  } catch (error) {
    console.error('Error generating medical record document:', error);
    res.status(500).json({ message: 'Erro ao gerar documento' });
  }
});

// ==================== MEDICAL DOCUMENTS ROUTES ====================

// Get medical documents for professional
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        md.*,
        pp.name as patient_name
      FROM medical_documents md
      LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
      WHERE md.professional_id = $1
      ORDER BY md.created_at DESC
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical documents:', error);
    res.status(500).json({ message: 'Erro ao buscar documentos' });
  }
});

// Create medical document
app.post('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { title, document_type, private_patient_id, template_data } = req.body;

    if (!title || !document_type || !template_data) {
      return res.status(400).json({ message: 'Título, tipo e dados do template são obrigatórios' });
    }

    const documentResult = await generateDocumentPDF(document_type, template_data);

    const result = await pool.query(
      `INSERT INTO medical_documents (
        professional_id, private_patient_id, title, document_type, document_url
      ) VALUES ($1, $2, $3, $4, $5)
      RETURNING *`,
      [
        req.user.id,
        private_patient_id || null,
        title,
        document_type,
        documentResult.url
      ]
    );

    res.status(201).json({
      message: 'Documento criado com sucesso',
      document: result.rows[0],
      title: title,
      documentUrl: documentResult.url
    });
  } catch (error) {
    console.error('Error creating medical document:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== SCHEDULING ACCESS ROUTES ====================

// Get professionals with scheduling access status (admin only)
app.get('/api/admin/professionals-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone,
        sc.name as category_name,
        CASE 
          WHEN sa.id IS NOT NULL AND sa.is_active = true AND (sa.expires_at IS NULL OR sa.expires_at > CURRENT_TIMESTAMP)
          THEN true 
          ELSE false 
        END as has_scheduling_access,
        sa.expires_at as access_expires_at,
        granted_by_user.name as access_granted_by,
        sa.created_at as access_granted_at
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      LEFT JOIN scheduling_access sa ON u.id = sa.professional_id AND sa.is_active = true
      LEFT JOIN users granted_by_user ON sa.granted_by = granted_by_user.id
      WHERE 'professional' = ANY(u.roles)
      ORDER BY u.name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals scheduling access:', error);
    res.status(500).json({ message: 'Erro ao buscar dados de acesso à agenda' });
  }
});

// Grant scheduling access (admin only)
app.post('/api/admin/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;

    if (!professional_id) {
      return res.status(400).json({ message: 'ID do profissional é obrigatório' });
    }

    // Deactivate any existing access
    await pool.query(
      'UPDATE scheduling_access SET is_active = false WHERE professional_id = $1',
      [professional_id]
    );

    // Create new access
    const result = await pool.query(
      `INSERT INTO scheduling_access (professional_id, granted_by, expires_at, reason)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [professional_id, req.user.id, expires_at || null, reason || null]
    );

    res.status(201).json({
      message: 'Acesso à agenda concedido com sucesso',
      access: result.rows[0]
    });
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

    await pool.query(
      'UPDATE scheduling_access SET is_active = false WHERE professional_id = $1',
      [professional_id]
    );

    res.json({ message: 'Acesso à agenda revogado com sucesso' });
  } catch (error) {
    console.error('Error revoking scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Admin home page data
app.get('/api/admin/dashboard', authenticate, authorize(['admin']), async (req, res) => {
  try {
    console.log('📊 Fetching admin dashboard data');
    
    // Get consultation counts with completed status only
    const consultationCountsQuery = `
      SELECT 
        COUNT(*) as total,
        COUNT(CASE WHEN DATE(date) = CURRENT_DATE THEN 1 END) as today,
        COUNT(CASE WHEN date >= CURRENT_DATE - INTERVAL '7 days' THEN 1 END) as week,
        COUNT(CASE WHEN date >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as month
      FROM consultations
      WHERE status = 'completed'
    `;
    
    const consultationCounts = await pool.query(consultationCountsQuery);
    
    // Get user counts by role
    const userCountsQuery = `
      SELECT 
        COUNT(CASE WHEN 'client' = ANY(roles) THEN 1 END) as clients,
        COUNT(CASE WHEN 'professional' = ANY(roles) THEN 1 END) as professionals,
        COUNT(*) as total
      FROM users
    `;
    
    const userCounts = await pool.query(userCountsQuery);
    
    // Get current month revenue with completed status only
    const currentMonth = new Date();
    const firstDay = new Date(currentMonth.getFullYear(), currentMonth.getMonth(), 1);
    const lastDay = new Date(currentMonth.getFullYear(), currentMonth.getMonth() + 1, 0);
    
    const revenueQuery = `
      SELECT 
        SUM(c.value) as total_revenue,
        SUM(c.value * ((100 - u.percentage) / 100)) as clinic_revenue
      FROM consultations c
      JOIN users u ON c.professional_id = u.id
      WHERE c.date >= $1 AND c.date <= $2 AND c.status = 'completed'
    `;
    
    const revenueResult = await pool.query(revenueQuery, [firstDay.toISOString(), lastDay.toISOString()]);
    
    const dashboardData = {
      consultation_counts: consultationCounts.rows[0],
      user_counts: userCounts.rows[0],
      monthly_revenue: revenueResult.rows[0]
    };
    
    console.log('✅ Admin dashboard data generated successfully');
    res.json(dashboardData);
  } catch (error) {
    console.error('❌ Error fetching admin dashboard data:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== UPLOAD ROUTES ====================

// Upload image route
app.post('/api/upload-image', authenticate, async (req, res) => {
  try {
    console.log('🔄 Starting image upload process...');
    
    const upload = createUpload();
    
    upload.single('image')(req, res, async (err) => {
      if (err) {
        console.error('❌ Upload error:', err);
        return res.status(400).json({ 
          message: err.message || 'Erro no upload da imagem' 
        });
      }

      if (!req.file) {
        console.error('❌ No file received');
        return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
      }

      console.log('✅ File uploaded successfully:', req.file.path);

      try {
        // Update user's photo_url in database
        await pool.query(
          'UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
          [req.file.path, req.user.id]
        );

        console.log('✅ Database updated with new photo URL');

        res.json({
          message: 'Imagem enviada com sucesso',
          imageUrl: req.file.path
        });
      } catch (dbError) {
        console.error('❌ Database update error:', dbError);
        res.status(500).json({ message: 'Erro ao salvar URL da imagem no banco de dados' });
      }
    });
  } catch (error) {
    console.error('❌ Upload route error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== PAYMENT ROUTES ====================

// 🔥 CLIENT SUBSCRIPTION PAYMENT
app.post('/api/create-subscription', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { user_id, dependent_ids = [] } = req.body;
    
    if (!user_id) {
      return res.status(400).json({ message: 'User ID é obrigatório' });
    }

    // Calculate amount: R$250 for titular + R$50 per dependent
    const baseAmount = 250;
    const dependentAmount = dependent_ids.length * 50;
    const totalAmount = baseAmount + dependentAmount;

    const preferenceData = {
      items: [
        {
          id: `subscription_${user_id}`,
          title: `Assinatura Convênio Quiro Ferreira - Titular + ${dependent_ids.length} Dependente(s)`,
          quantity: 1,
          unit_price: totalAmount,
          currency_id: 'BRL'
        }
      ],
      payer: {
        email: 'cliente@quiroferreira.com.br'
      },
      back_urls: {
        success: `${req.protocol}://${req.get('host')}/api/payment/client/success`,
        failure: `${req.protocol}://${req.get('host')}/api/payment/client/failure`,
        pending: `${req.protocol}://${req.get('host')}/api/payment/client/pending`
      },
      auto_return: 'approved',
      external_reference: `client_${user_id}_${Date.now()}`,
      notification_url: `${req.protocol}://${req.get('host')}/api/payment/client/webhook`,
      statement_descriptor: 'QUIRO FERREIRA',
      expires: true,
      expiration_date_from: new Date().toISOString(),
      expiration_date_to: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
    };

    console.log('🔄 Creating client subscription preference:', preferenceData);

    const result = await preference.create({ body: preferenceData });
    
    console.log('✅ Client preference created:', result.id);

    // Save payment record
    await pool.query(
      `INSERT INTO client_payments (
        user_id, preference_id, amount, external_reference, description
      ) VALUES ($1, $2, $3, $4, $5)`,
      [
        user_id,
        result.id,
        totalAmount,
        preferenceData.external_reference,
        `Assinatura Convênio - Titular + ${dependent_ids.length} Dependente(s)`
      ]
    );

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point
    });
  } catch (error) {
    console.error('❌ Error creating client subscription:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento de assinatura' });
  }
});

// 🔥 PROFESSIONAL PAYMENT TO CLINIC
app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor deve ser maior que zero' });
    }

    const professional_id = req.user.id;

    const preferenceData = {
      items: [
        {
          id: `professional_payment_${professional_id}`,
          title: `Repasse ao Convênio Quiro Ferreira - ${req.user.name}`,
          quantity: 1,
          unit_price: parseFloat(amount),
          currency_id: 'BRL'
        }
      ],
      payer: {
        email: 'profissional@quiroferreira.com.br'
      },
      back_urls: {
        success: `${req.protocol}://${req.get('host')}/api/payment/professional/success`,
        failure: `${req.protocol}://${req.get('host')}/api/payment/professional/failure`,
        pending: `${req.protocol}://${req.get('host')}/api/payment/professional/pending`
      },
      auto_return: 'approved',
      external_reference: `professional_${professional_id}_${Date.now()}`,
      notification_url: `${req.protocol}://${req.get('host')}/api/payment/professional/webhook`,
      statement_descriptor: 'QUIRO FERREIRA',
      expires: true,
      expiration_date_from: new Date().toISOString(),
      expiration_date_to: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
    };

    console.log('🔄 Creating professional payment preference:', preferenceData);

    const result = await preference.create({ body: preferenceData });
    
    console.log('✅ Professional preference created:', result.id);

    // Save payment record
    await pool.query(
      `INSERT INTO professional_payments (
        professional_id, preference_id, amount, external_reference, description
      ) VALUES ($1, $2, $3, $4, $5)`,
      [
        professional_id,
        result.id,
        amount,
        preferenceData.external_reference,
        `Repasse ao Convênio - ${req.user.name}`
      ]
    );

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point
    });
  } catch (error) {
    console.error('❌ Error creating professional payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento profissional' });
  }
});

// 🔥 SCHEDULING ACCESS PAYMENT (prepared for future use)
app.post('/api/scheduling/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { months = 1 } = req.body;
    
    const professional_id = req.user.id;
    const monthlyPrice = 99.90; // R$99,90 per month
    const totalAmount = monthlyPrice * months;

    const preferenceData = {
      items: [
        {
          id: `scheduling_${professional_id}`,
          title: `Acesso à Agenda Quiro Ferreira - ${months} mês(es)`,
          quantity: 1,
          unit_price: totalAmount,
          currency_id: 'BRL'
        }
      ],
      payer: {
        email: 'profissional@quiroferreira.com.br'
      },
      back_urls: {
        success: `${req.protocol}://${req.get('host')}/api/payment/scheduling/success`,
        failure: `${req.protocol}://${req.get('host')}/api/payment/scheduling/failure`,
        pending: `${req.protocol}://${req.get('host')}/api/payment/scheduling/pending`
      },
      auto_return: 'approved',
      external_reference: `scheduling_${professional_id}_${Date.now()}`,
      notification_url: `${req.protocol}://${req.get('host')}/api/payment/scheduling/webhook`,
      statement_descriptor: 'QUIRO FERREIRA',
      expires: true,
      expiration_date_from: new Date().toISOString(),
      expiration_date_to: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
    };

    console.log('🔄 Creating scheduling payment preference:', preferenceData);

    const result = await preference.create({ body: preferenceData });
    
    console.log('✅ Scheduling preference created:', result.id);

    // Save payment record
    await pool.query(
      `INSERT INTO scheduling_payments (
        professional_id, preference_id, amount, external_reference, description
      ) VALUES ($1, $2, $3, $4, $5)`,
      [
        professional_id,
        result.id,
        totalAmount,
        preferenceData.external_reference,
        `Acesso à Agenda - ${months} mês(es)`
      ]
    );

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point
    });
  } catch (error) {
    console.error('❌ Error creating scheduling payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento de agenda' });
  }
});

// ==================== PAYMENT CALLBACK ROUTES ====================

// 🔥 CLIENT PAYMENT CALLBACKS
app.get('/api/payment/client/success', async (req, res) => {
  try {
    const { payment_id, status, external_reference } = req.query;
    
    console.log('✅ Client payment success callback:', { payment_id, status, external_reference });
    
    if (payment_id && status === 'approved') {
      // Update payment status
      await pool.query(
        `UPDATE client_payments SET 
          payment_id = $1, status = 'approved', date_approved = CURRENT_TIMESTAMP
         WHERE external_reference = $2`,
        [payment_id, external_reference]
      );

      // Activate client subscription
      const paymentResult = await pool.query(
        'SELECT user_id FROM client_payments WHERE external_reference = $1',
        [external_reference]
      );

      if (paymentResult.rows.length > 0) {
        const userId = paymentResult.rows[0].user_id;
        const expiryDate = new Date();
        expiryDate.setFullYear(expiryDate.getFullYear() + 1); // 1 year from now

        await pool.query(
          `UPDATE users SET 
            subscription_status = 'active',
            subscription_expiry = $1
           WHERE id = $2`,
          [expiryDate, userId]
        );

        console.log('✅ Client subscription activated for user:', userId);
      }
    }

    res.redirect('/?payment=success');
  } catch (error) {
    console.error('❌ Client payment success callback error:', error);
    res.redirect('/?payment=error');
  }
});

app.get('/api/payment/client/failure', async (req, res) => {
  try {
    const { payment_id, status, external_reference } = req.query;
    
    console.log('❌ Client payment failure callback:', { payment_id, status, external_reference });
    
    if (external_reference) {
      await pool.query(
        `UPDATE client_payments SET 
          payment_id = $1, status = 'rejected'
         WHERE external_reference = $2`,
        [payment_id || null, external_reference]
      );
    }

    res.redirect('/?payment=failure');
  } catch (error) {
    console.error('❌ Client payment failure callback error:', error);
    res.redirect('/?payment=error');
  }
});

app.get('/api/payment/client/pending', async (req, res) => {
  try {
    const { payment_id, status, external_reference } = req.query;
    
    console.log('⏳ Client payment pending callback:', { payment_id, status, external_reference });
    
    if (external_reference) {
      await pool.query(
        `UPDATE client_payments SET 
          payment_id = $1, status = 'pending'
         WHERE external_reference = $2`,
        [payment_id || null, external_reference]
      );
    }

    res.redirect('/?payment=pending');
  } catch (error) {
    console.error('❌ Client payment pending callback error:', error);
    res.redirect('/?payment=error');
  }
});

// 🔥 PROFESSIONAL PAYMENT CALLBACKS
app.get('/api/payment/professional/success', async (req, res) => {
  try {
    const { payment_id, status, external_reference } = req.query;
    
    console.log('✅ Professional payment success callback:', { payment_id, status, external_reference });
    
    if (payment_id && status === 'approved') {
      await pool.query(
        `UPDATE professional_payments SET 
          payment_id = $1, status = 'approved', date_approved = CURRENT_TIMESTAMP
         WHERE external_reference = $2`,
        [payment_id, external_reference]
      );
    }

    res.redirect('/professional?payment=success');
  } catch (error) {
    console.error('❌ Professional payment success callback error:', error);
    res.redirect('/professional?payment=error');
  }
});

app.get('/api/payment/professional/failure', async (req, res) => {
  try {
    const { payment_id, status, external_reference } = req.query;
    
    console.log('❌ Professional payment failure callback:', { payment_id, status, external_reference });
    
    if (external_reference) {
      await pool.query(
        `UPDATE professional_payments SET 
          payment_id = $1, status = 'rejected'
         WHERE external_reference = $2`,
        [payment_id || null, external_reference]
      );
    }

    res.redirect('/professional?payment=failure');
  } catch (error) {
    console.error('❌ Professional payment failure callback error:', error);
    res.redirect('/professional?payment=error');
  }
});

app.get('/api/payment/professional/pending', async (req, res) => {
  try {
    const { payment_id, status, external_reference } = req.query;
    
    console.log('⏳ Professional payment pending callback:', { payment_id, status, external_reference });
    
    if (external_reference) {
      await pool.query(
        `UPDATE professional_payments SET 
          payment_id = $1, status = 'pending'
         WHERE external_reference = $2`,
        [payment_id || null, external_reference]
      );
    }

    res.redirect('/professional?payment=pending');
  } catch (error) {
    console.error('❌ Professional payment pending callback error:', error);
    res.redirect('/professional?payment=error');
  }
});

// 🔥 SCHEDULING PAYMENT CALLBACKS
app.get('/api/payment/scheduling/success', async (req, res) => {
  try {
    const { payment_id, status, external_reference } = req.query;
    
    console.log('✅ Scheduling payment success callback:', { payment_id, status, external_reference });
    
    if (payment_id && status === 'approved') {
      await pool.query(
        `UPDATE scheduling_payments SET 
          payment_id = $1, status = 'approved', date_approved = CURRENT_TIMESTAMP
         WHERE external_reference = $2`,
        [payment_id, external_reference]
      );

      // Grant scheduling access (future implementation)
      // This would activate scheduling access for the professional
    }

    res.redirect('/professional?payment=success');
  } catch (error) {
    console.error('❌ Scheduling payment success callback error:', error);
    res.redirect('/professional?payment=error');
  }
});

app.get('/api/payment/scheduling/failure', async (req, res) => {
  try {
    const { payment_id, status, external_reference } = req.query;
    
    console.log('❌ Scheduling payment failure callback:', { payment_id, status, external_reference });
    
    if (external_reference) {
      await pool.query(
        `UPDATE scheduling_payments SET 
          payment_id = $1, status = 'rejected'
         WHERE external_reference = $2`,
        [payment_id || null, external_reference]
      );
    }

    res.redirect('/professional?payment=failure');
  } catch (error) {
    console.error('❌ Scheduling payment failure callback error:', error);
    res.redirect('/professional?payment=error');
  }
});

app.get('/api/payment/scheduling/pending', async (req, res) => {
  try {
    const { payment_id, status, external_reference } = req.query;
    
    console.log('⏳ Scheduling payment pending callback:', { payment_id, status, external_reference });
    
    if (external_reference) {
      await pool.query(
        `UPDATE scheduling_payments SET 
          payment_id = $1, status = 'pending'
         WHERE external_reference = $2`,
        [payment_id || null, external_reference]
      );
    }

    res.redirect('/professional?payment=pending');
  } catch (error) {
    console.error('❌ Scheduling payment pending callback error:', error);
    res.redirect('/professional?payment=error');
  }
});

// ==================== PAYMENT WEBHOOK ROUTES ====================

// 🔥 CLIENT PAYMENT WEBHOOK
app.post('/api/payment/client/webhook', async (req, res) => {
  try {
    console.log('🔔 Client payment webhook received:', req.body);
    
    const { type, data } = req.body;
    
    if (type === 'payment') {
      const paymentId = data.id;
      
      try {
        const paymentInfo = await payment.get({ id: paymentId });
        console.log('💳 Client payment info:', paymentInfo);
        
        const externalReference = paymentInfo.external_reference;
        const status = paymentInfo.status;
        
        // Update payment record
        await pool.query(
          `UPDATE client_payments SET 
            payment_id = $1, status = $2, payment_method = $3, payment_type = $4,
            payer_email = $5, date_approved = $6, date_created = $7,
            last_modified = $8, webhook_data = $9
           WHERE external_reference = $10`,
          [
            paymentId,
            status,
            paymentInfo.payment_method_id || null,
            paymentInfo.payment_type_id || null,
            paymentInfo.payer?.email || null,
            paymentInfo.date_approved || null,
            paymentInfo.date_created || null,
            paymentInfo.date_last_updated || null,
            JSON.stringify(paymentInfo),
            externalReference
          ]
        );

        // If payment approved, activate subscription
        if (status === 'approved') {
          const paymentResult = await pool.query(
            'SELECT user_id FROM client_payments WHERE external_reference = $1',
            [externalReference]
          );

          if (paymentResult.rows.length > 0) {
            const userId = paymentResult.rows[0].user_id;
            const expiryDate = new Date();
            expiryDate.setFullYear(expiryDate.getFullYear() + 1); // 1 year from now

            await pool.query(
              `UPDATE users SET 
                subscription_status = 'active',
                subscription_expiry = $1
               WHERE id = $2`,
              [expiryDate, userId]
            );

            console.log('✅ Client subscription activated via webhook for user:', userId);
          }
        }
      } catch (paymentError) {
        console.error('❌ Error processing client payment webhook:', paymentError);
      }
    }
    
    res.status(200).send('OK');
  } catch (error) {
    console.error('❌ Client webhook error:', error);
    res.status(500).send('Error');
  }
});

// 🔥 PROFESSIONAL PAYMENT WEBHOOK
app.post('/api/payment/professional/webhook', async (req, res) => {
  try {
    console.log('🔔 Professional payment webhook received:', req.body);
    
    const { type, data } = req.body;
    
    if (type === 'payment') {
      const paymentId = data.id;
      
      try {
        const paymentInfo = await payment.get({ id: paymentId });
        console.log('💳 Professional payment info:', paymentInfo);
        
        const externalReference = paymentInfo.external_reference;
        const status = paymentInfo.status;
        
        // Update payment record
        await pool.query(
          `UPDATE professional_payments SET 
            payment_id = $1, status = $2, payment_method = $3, payment_type = $4,
            payer_email = $5, date_approved = $6, date_created = $7,
            last_modified = $8, webhook_data = $9
           WHERE external_reference = $10`,
          [
            paymentId,
            status,
            paymentInfo.payment_method_id || null,
            paymentInfo.payment_type_id || null,
            paymentInfo.payer?.email || null,
            paymentInfo.date_approved || null,
            paymentInfo.date_created || null,
            paymentInfo.date_last_updated || null,
            JSON.stringify(paymentInfo),
            externalReference
          ]
        );

        console.log('✅ Professional payment webhook processed successfully');
      } catch (paymentError) {
        console.error('❌ Error processing professional payment webhook:', paymentError);
      }
    }
    
    res.status(200).send('OK');
  } catch (error) {
    console.error('❌ Professional webhook error:', error);
    res.status(500).send('Error');
  }
});

// 🔥 SCHEDULING PAYMENT WEBHOOK
app.post('/api/payment/scheduling/webhook', async (req, res) => {
  try {
    console.log('🔔 Scheduling payment webhook received:', req.body);
    
    const { type, data } = req.body;
    
    if (type === 'payment') {
      const paymentId = data.id;
      
      try {
        const paymentInfo = await payment.get({ id: paymentId });
        console.log('💳 Scheduling payment info:', paymentInfo);
        
        const externalReference = paymentInfo.external_reference;
        const status = paymentInfo.status;
        
        // Update payment record
        await pool.query(
          `UPDATE scheduling_payments SET 
            payment_id = $1, status = $2, payment_method = $3, payment_type = $4,
            payer_email = $5, date_approved = $6, date_created = $7,
            last_modified = $8, webhook_data = $9
           WHERE external_reference = $10`,
          [
            paymentId,
            status,
            paymentInfo.payment_method_id || null,
            paymentInfo.payment_type_id || null,
            paymentInfo.payer?.email || null,
            paymentInfo.date_approved || null,
            paymentInfo.date_created || null,
            paymentInfo.date_last_updated || null,
            JSON.stringify(paymentInfo),
            externalReference
          ]
        );

        // If payment approved, grant scheduling access (future implementation)
        if (status === 'approved') {
          // This would grant scheduling access to the professional
          console.log('✅ Scheduling access payment approved - ready for activation');
        }

        console.log('✅ Scheduling payment webhook processed successfully');
      } catch (paymentError) {
        console.error('❌ Error processing scheduling payment webhook:', paymentError);
      }
    }
    
    res.status(200).send('OK');
  } catch (error) {
    console.error('❌ Scheduling webhook error:', error);
    res.status(500).send('Error');
  }
});

// ==================== PAYMENT HISTORY ROUTES ====================

// Get client payment history
app.get('/api/payments/client/:userId', authenticate, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Check authorization
    if (req.user.currentRole !== 'admin' && req.user.id !== parseInt(userId)) {
      return res.status(403).json({ message: 'Não autorizado' });
    }

    const result = await pool.query(
      `SELECT * FROM client_payments 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [userId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching client payment history:', error);
    res.status(500).json({ message: 'Erro ao buscar histórico de pagamentos' });
  }
});

// Get professional payment history
app.get('/api/payments/professional/:professionalId', authenticate, async (req, res) => {
  try {
    const { professionalId } = req.params;
    
    // Check authorization
    if (req.user.currentRole !== 'admin' && req.user.id !== parseInt(professionalId)) {
      return res.status(403).json({ message: 'Não autorizado' });
    }

    const result = await pool.query(
      `SELECT * FROM professional_payments 
       WHERE professional_id = $1 
       ORDER BY created_at DESC`,
      [professionalId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professional payment history:', error);
    res.status(500).json({ message: 'Erro ao buscar histórico de pagamentos' });
  }
});

// Get scheduling payment history
app.get('/api/payments/scheduling/:professionalId', authenticate, async (req, res) => {
  try {
    const { professionalId } = req.params;
    
    // Check authorization
    if (req.user.currentRole !== 'admin' && req.user.id !== parseInt(professionalId)) {
      return res.status(403).json({ message: 'Não autorizado' });
    }

    const result = await pool.query(
      `SELECT * FROM scheduling_payments 
       WHERE professional_id = $1 
       ORDER BY created_at DESC`,
      [professionalId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching scheduling payment history:', error);
    res.status(500).json({ message: 'Erro ao buscar histórico de pagamentos' });
  }
});

// ==================== REPORT ROUTES ====================

// Revenue report (admin only)
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Datas de início e fim são obrigatórias' });
    }

    // Get revenue by professional
    const professionalRevenueResult = await pool.query(`
      SELECT 
        prof.name as professional_name,
        prof.percentage as professional_percentage,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count,
        SUM(c.value * (prof.percentage / 100.0)) as professional_payment,
        SUM(c.value * ((100 - prof.percentage) / 100.0)) as clinic_revenue
      FROM consultations c
      JOIN users prof ON c.professional_id = prof.id
      WHERE c.date >= $1 AND c.date <= $2
        AND (c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL)
      GROUP BY prof.id, prof.name, prof.percentage
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    // Get revenue by service
    const serviceRevenueResult = await pool.query(`
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
    const totalRevenue = professionalRevenueResult.rows.reduce(
      (sum, row) => sum + parseFloat(row.revenue || 0), 0
    );

    res.json({
      total_revenue: totalRevenue,
      revenue_by_professional: professionalRevenueResult.rows,
      revenue_by_service: serviceRevenueResult.rows
    });
  } catch (error) {
    console.error('Error generating revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de receita' });
  }
});

// Professional revenue report
app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
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

    // Get consultations for the professional in the date range
    const consultationsResult = await pool.query(`
      SELECT 
        c.date,
        COALESCE(u.name, d.name, pp.name) as client_name,
        s.name as service_name,
        c.value as total_value,
        CASE 
          WHEN c.private_patient_id IS NOT NULL THEN c.value
          ELSE c.value * ($3 / 100.0)
        END as professional_payment,
        CASE 
          WHEN c.private_patient_id IS NOT NULL THEN 0
          ELSE c.value * ((100 - $3) / 100.0)
        END as amount_to_pay
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN services s ON c.service_id = s.id
      WHERE c.professional_id = $1 
        AND c.date >= $2 AND c.date <= $4 AND c.status = 'completed'
      ORDER BY c.date DESC
    `, [req.user.id, start_date, professionalPercentage, end_date]);

    // Calculate summary
    const consultations = consultationsResult.rows;
    const totalRevenue = consultations.reduce((sum, c) => sum + parseFloat(c.total_value), 0);
    const totalAmountToPay = consultations.reduce((sum, c) => sum + parseFloat(c.amount_to_pay), 0);

    res.json({
      summary: {
        professional_percentage: professionalPercentage,
        total_revenue: totalRevenue,
        consultation_count: consultations.length,
        amount_to_pay: totalAmountToPay
      },
      consultations: consultations
    });
  } catch (error) {
    console.error('Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de receita do profissional' });
  }
});

// Professional detailed report
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

    // Get detailed consultation data
    const result = await pool.query(`
      SELECT 
        COUNT(CASE WHEN c.private_patient_id IS NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        COUNT(*) as total_consultations,
        SUM(CASE WHEN c.private_patient_id IS NULL THEN c.value ELSE 0 END) as convenio_revenue,
        SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END) as private_revenue,
        SUM(c.value) as total_revenue,
        SUM(CASE WHEN c.private_patient_id IS NULL THEN c.value * ((100 - $2) / 100.0) ELSE 0 END) as amount_to_pay
      FROM consultations c
      WHERE c.professional_id = $1 
        AND c.date >= $3 AND c.date <= $4
    `, [req.user.id, professionalPercentage, start_date, end_date]);

    const summary = result.rows[0] || {
      convenio_consultations: 0,
      private_consultations: 0,
      total_consultations: 0,
      convenio_revenue: 0,
      private_revenue: 0,
      total_revenue: 0,
      amount_to_pay: 0
    };

    // Convert string values to numbers
    Object.keys(summary).forEach(key => {
      if (summary[key] !== null) {
        summary[key] = parseFloat(summary[key]) || 0;
      }
    });

    summary.professional_percentage = professionalPercentage;

    res.json({ summary });
  } catch (error) {
    console.error('Error generating detailed professional report:', error);
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
      WHERE 'client' = ANY(roles) 
        AND city IS NOT NULL 
        AND city != ''
      GROUP BY city, state
      ORDER BY client_count DESC, city
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error generating clients by city report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de clientes por cidade' });
  }
});

// Professionals by city report (admin only)
app.get('/api/reports/professionals-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.city,
        u.state,
        COUNT(*) as total_professionals,
        json_agg(
          json_build_object(
            'category_name', COALESCE(sc.name, 'Sem categoria'),
            'count', 1
          )
        ) as categories
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE 'professional' = ANY(u.roles) 
        AND u.city IS NOT NULL 
        AND u.city != ''
      GROUP BY u.city, u.state
      ORDER BY total_professionals DESC, u.city
    `);

    // Process the categories to group by category name
    const processedResult = result.rows.map(row => {
      const categoryMap = new Map();
      
      row.categories.forEach(cat => {
        const name = cat.category_name;
        if (categoryMap.has(name)) {
          categoryMap.set(name, categoryMap.get(name) + cat.count);
        } else {
          categoryMap.set(name, cat.count);
        }
      });

      return {
        ...row,
        categories: Array.from(categoryMap.entries()).map(([category_name, count]) => ({
          category_name,
          count
        }))
      };
    });

    res.json(processedResult);
  } catch (error) {
    console.error('Error generating professionals by city report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de profissionais por cidade' });
  }
});

// ==================== ERROR HANDLING ====================

// Global error handler
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);
  res.status(500).json({ message: 'Erro interno do servidor' });
const express = require('express');
});
const cors = require('cors');

const dotenv = require('dotenv');
export default app;