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
import { MercadoPagoConfig, Preference } from 'mercadopago';
import path from 'path';
import { fileURLToPath } from 'url';

// ES modules compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Initialize MercadoPago SDK v2
const client = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN,
  options: { timeout: 5000 }
});

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:3000',
      'https://www.cartaoquiroferreira.com.br',
      'https://cartaoquiroferreira.com.br'
    ];
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

// Serve static files from dist directory
app.use(express.static(path.join(__dirname, '../dist')));

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

    // Clean CPF
    const cleanCpf = cpf.replace(/\D/g, '');

    // Find user by CPF
    const result = await pool.query(
      'SELECT id, name, cpf, password_hash, roles FROM users WHERE cpf = $1',
      [cleanCpf]
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

    // Return user data without token (will be created on role selection)
    res.json({
      user: {
        id: user.id,
        name: user.name,
        cpf: user.cpf,
        roles: user.roles || []
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
      return res.status(400).json({ message: 'ID do usuário e role são obrigatórios' });
    }

    // Verify user exists and has the requested role
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

    // Generate JWT token with selected role
    const token = jwt.sign(
      { 
        id: user.id, 
        currentRole: role,
        roles: user.roles 
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

    if (!role) {
      return res.status(400).json({ message: 'Role é obrigatória' });
    }

    if (!req.user.roles || !req.user.roles.includes(role)) {
      return res.status(403).json({ message: 'Role não autorizada para este usuário' });
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
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });

    res.json({
      token,
      user: {
        id: req.user.id,
        name: req.user.name,
        cpf: req.user.cpf,
        roles: req.user.roles,
        currentRole: role
      }
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

    if (!name || !cpf || !password) {
      return res.status(400).json({ message: 'Nome, CPF e senha são obrigatórios' });
    }

    // Clean CPF
    const cleanCpf = cpf.replace(/\D/g, '');

    // Validate CPF format
    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
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
    const passwordHash = await bcrypt.hash(password, 10);

    // Insert new user with client role and pending subscription
    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password_hash, 
        roles, subscription_status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW()) 
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
        passwordHash,
        ['client'], // Only client role for registration
        'pending' // Default subscription status
      ]
    );

    const newUser = result.rows[0];

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      user: {
        id: newUser.id,
        name: newUser.name,
        cpf: newUser.cpf,
        roles: newUser.roles
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
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

// ==================== USER ROUTES ====================

// Get all users (admin only)
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.cpf, u.email, u.phone, u.birth_date, u.address, 
        u.address_number, u.address_complement, u.neighborhood, u.city, u.state,
        u.roles, u.percentage, u.category_id, u.subscription_status, 
        u.subscription_expiry, u.created_at, u.photo_url,
        sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      ORDER BY u.created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Erro ao carregar usuários' });
  }
});

// Get user by ID
app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Users can only access their own data unless they're admin
    if (req.user.currentRole !== 'admin' && req.user.id !== parseInt(id)) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.cpf, u.email, u.phone, u.birth_date, u.address, 
        u.address_number, u.address_complement, u.neighborhood, u.city, u.state,
        u.roles, u.percentage, u.category_id, u.subscription_status, 
        u.subscription_expiry, u.created_at, u.photo_url,
        sc.name as category_name
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
    res.status(500).json({ message: 'Erro ao carregar usuário' });
  }
});

// Create user (admin only)
app.post('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, password, roles,
      percentage, category_id
    } = req.body;

    if (!name || !cpf || !password || !roles || roles.length === 0) {
      return res.status(400).json({ message: 'Campos obrigatórios não preenchidos' });
    }

    // Clean CPF
    const cleanCpf = cpf.replace(/\D/g, '');

    // Validate CPF format
    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    // Check if user already exists
    const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cleanCpf]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'Usuário já cadastrado com este CPF' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Determine subscription status based on roles
    let subscriptionStatus = null;
    if (roles.includes('client')) {
      subscriptionStatus = 'pending'; // Clients start with pending subscription
    }

    // Insert new user
    const result = await pool.query(`
      INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password_hash, roles,
        percentage, category_id, subscription_status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW())
      RETURNING id, name, cpf, roles
    `, [
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
      passwordHash,
      roles,
      percentage || null,
      category_id || null,
      subscriptionStatus
    ]);

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating user:', error);
    if (error.code === '23505') {
      res.status(409).json({ message: 'CPF já cadastrado' });
    } else {
      res.status(500).json({ message: 'Erro ao criar usuário' });
    }
  }
});

// Update user
app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, roles,
      percentage, category_id, currentPassword, newPassword
    } = req.body;

    // Users can only update their own data unless they're admin
    if (req.user.currentRole !== 'admin' && req.user.id !== parseInt(id)) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    // Get current user data
    const currentUser = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    if (currentUser.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    let updateFields = [];
    let updateValues = [];
    let paramCount = 1;

    // Build dynamic update query
    if (name !== undefined) {
      updateFields.push(`name = $${paramCount}`);
      updateValues.push(name.trim());
      paramCount++;
    }

    if (email !== undefined) {
      updateFields.push(`email = $${paramCount}`);
      updateValues.push(email?.trim() || null);
      paramCount++;
    }

    if (phone !== undefined) {
      updateFields.push(`phone = $${paramCount}`);
      updateValues.push(phone?.replace(/\D/g, '') || null);
      paramCount++;
    }

    if (birth_date !== undefined) {
      updateFields.push(`birth_date = $${paramCount}`);
      updateValues.push(birth_date || null);
      paramCount++;
    }

    if (address !== undefined) {
      updateFields.push(`address = $${paramCount}`);
      updateValues.push(address?.trim() || null);
      paramCount++;
    }

    if (address_number !== undefined) {
      updateFields.push(`address_number = $${paramCount}`);
      updateValues.push(address_number?.trim() || null);
      paramCount++;
    }

    if (address_complement !== undefined) {
      updateFields.push(`address_complement = $${paramCount}`);
      updateValues.push(address_complement?.trim() || null);
      paramCount++;
    }

    if (neighborhood !== undefined) {
      updateFields.push(`neighborhood = $${paramCount}`);
      updateValues.push(neighborhood?.trim() || null);
      paramCount++;
    }

    if (city !== undefined) {
      updateFields.push(`city = $${paramCount}`);
      updateValues.push(city?.trim() || null);
      paramCount++;
    }

    if (state !== undefined) {
      updateFields.push(`state = $${paramCount}`);
      updateValues.push(state || null);
      paramCount++;
    }

    if (roles !== undefined && req.user.currentRole === 'admin') {
      updateFields.push(`roles = $${paramCount}`);
      updateValues.push(roles);
      paramCount++;
    }

    if (percentage !== undefined && req.user.currentRole === 'admin') {
      updateFields.push(`percentage = $${paramCount}`);
      updateValues.push(percentage || null);
      paramCount++;
    }

    if (category_id !== undefined && req.user.currentRole === 'admin') {
      updateFields.push(`category_id = $${paramCount}`);
      updateValues.push(category_id || null);
      paramCount++;
    }

    // Handle password change
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: 'Senha atual é obrigatória para alterar a senha' });
      }

      // Verify current password
      const isValidPassword = await bcrypt.compare(currentPassword, currentUser.rows[0].password_hash);
      if (!isValidPassword) {
        return res.status(400).json({ message: 'Senha atual incorreta' });
      }

      // Hash new password
      const newPasswordHash = await bcrypt.hash(newPassword, 10);
      updateFields.push(`password_hash = $${paramCount}`);
      updateValues.push(newPasswordHash);
      paramCount++;
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ message: 'Nenhum campo para atualizar' });
    }

    // Add updated_at
    updateFields.push(`updated_at = NOW()`);

    // Add user ID for WHERE clause
    updateValues.push(id);

    const query = `
      UPDATE users 
      SET ${updateFields.join(', ')}
      WHERE id = $${paramCount}
      RETURNING id, name, cpf, email, phone, roles
    `;

    const result = await pool.query(query, updateValues);

    res.json({
      message: 'Usuário atualizado com sucesso',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Erro ao atualizar usuário' });
  }
});

// Delete user (admin only)
app.delete('/api/users/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    // Check if user exists
    const user = await pool.query('SELECT id FROM users WHERE id = $1', [id]);
    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    // Delete user (this will cascade to related records)
    await pool.query('DELETE FROM users WHERE id = $1', [id]);

    res.json({ message: 'Usuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Erro ao excluir usuário' });
  }
});

// Activate client subscription (admin only)
app.put('/api/users/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { expiry_date } = req.body;

    if (!expiry_date) {
      return res.status(400).json({ message: 'Data de expiração é obrigatória' });
    }

    // Check if user exists and is a client
    const user = await pool.query(
      'SELECT id, roles FROM users WHERE id = $1',
      [id]
    );

    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    if (!user.rows[0].roles || !user.rows[0].roles.includes('client')) {
      return res.status(400).json({ message: 'Usuário não é um cliente' });
    }

    // Update subscription status
    await pool.query(
      'UPDATE users SET subscription_status = $1, subscription_expiry = $2, updated_at = NOW() WHERE id = $3',
      ['active', expiry_date, id]
    );

    res.json({ message: 'Cliente ativado com sucesso' });
  } catch (error) {
    console.error('Error activating client:', error);
    res.status(500).json({ message: 'Erro ao ativar cliente' });
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

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching service categories:', error);
    res.status(500).json({ message: 'Erro ao carregar categorias' });
  }
});

// Create service category (admin only)
app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome da categoria é obrigatório' });
    }

    const result = await pool.query(
      'INSERT INTO service_categories (name, description, created_at) VALUES ($1, $2, NOW()) RETURNING *',
      [name.trim(), description?.trim() || null]
    );

    res.status(201).json({
      message: 'Categoria criada com sucesso',
      category: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating service category:', error);
    if (error.code === '23505') {
      res.status(409).json({ message: 'Categoria já existe' });
    } else {
      res.status(500).json({ message: 'Erro ao criar categoria' });
    }
  }
});

// ==================== SERVICES ROUTES ====================

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
    console.error('Error fetching services:', error);
    res.status(500).json({ message: 'Erro ao carregar serviços' });
  }
});

// Create service (admin only)
app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !description || !base_price) {
      return res.status(400).json({ message: 'Nome, descrição e preço são obrigatórios' });
    }

    const result = await pool.query(`
      INSERT INTO services (name, description, base_price, category_id, is_base_service, created_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
      RETURNING *
    `, [
      name.trim(),
      description.trim(),
      parseFloat(base_price),
      category_id || null,
      is_base_service || false
    ]);

    res.status(201).json({
      message: 'Serviço criado com sucesso',
      service: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating service:', error);
    res.status(500).json({ message: 'Erro ao criar serviço' });
  }
});

// Update service (admin only)
app.put('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, base_price, category_id, is_base_service } = req.body;

    const result = await pool.query(`
      UPDATE services 
      SET name = $1, description = $2, base_price = $3, category_id = $4, 
          is_base_service = $5, updated_at = NOW()
      WHERE id = $6
      RETURNING *
    `, [
      name.trim(),
      description.trim(),
      parseFloat(base_price),
      category_id || null,
      is_base_service || false,
      id
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    res.json({
      message: 'Serviço atualizado com sucesso',
      service: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating service:', error);
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

    res.json({ message: 'Serviço excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting service:', error);
    res.status(500).json({ message: 'Erro ao excluir serviço' });
  }
});

// ==================== PROFESSIONALS ROUTES ====================

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
      WHERE u.roles @> '["professional"]'
      ORDER BY u.name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro ao carregar profissionais' });
  }
});

// Get professionals with scheduling access info (admin only)
app.get('/api/admin/professionals-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone,
        sc.name as category_name,
        u.has_scheduling_access,
        u.access_expires_at,
        u.access_granted_by,
        u.access_granted_at
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE u.roles @> '["professional"]'
      ORDER BY u.name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals scheduling access:', error);
    res.status(500).json({ message: 'Erro ao carregar dados de acesso' });
  }
});

// Grant scheduling access (admin only)
app.post('/api/admin/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;

    if (!professional_id || !expires_at) {
      return res.status(400).json({ message: 'ID do profissional e data de expiração são obrigatórios' });
    }

    await pool.query(`
      UPDATE users 
      SET has_scheduling_access = true,
          access_expires_at = $1,
          access_granted_by = $2,
          access_granted_at = NOW(),
          access_reason = $3,
          updated_at = NOW()
      WHERE id = $4 AND roles @> '["professional"]'
    `, [expires_at, req.user.name, reason || null, professional_id]);

    res.json({ message: 'Acesso à agenda concedido com sucesso' });
  } catch (error) {
    console.error('Error granting scheduling access:', error);
    res.status(500).json({ message: 'Erro ao conceder acesso' });
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
      SET has_scheduling_access = false,
          access_expires_at = NULL,
          access_granted_by = NULL,
          access_granted_at = NULL,
          access_reason = NULL,
          updated_at = NOW()
      WHERE id = $1 AND roles @> '["professional"]'
    `, [professional_id]);

    res.json({ message: 'Acesso à agenda revogado com sucesso' });
  } catch (error) {
    console.error('Error revoking scheduling access:', error);
    res.status(500).json({ message: 'Erro ao revogar acesso' });
  }
});

// ==================== CLIENTS ROUTES ====================

// Lookup client by CPF
app.get('/api/clients/lookup', authenticate, authorize(['professional', 'admin']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.toString().replace(/\D/g, '');

    const result = await pool.query(`
      SELECT id, name, cpf, subscription_status, subscription_expiry
      FROM users 
      WHERE cpf = $1 AND roles @> '["client"]'
    `, [cleanCpf]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error looking up client:', error);
    res.status(500).json({ message: 'Erro ao buscar cliente' });
  }
});

// ==================== DEPENDENTS ROUTES ====================

// Get dependents by client ID
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;

    // Clients can only access their own dependents
    if (req.user.currentRole === 'client' && req.user.id !== parseInt(clientId)) {
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
    res.status(500).json({ message: 'Erro ao carregar dependentes' });
  }
});

// Lookup dependent by CPF
app.get('/api/dependents/lookup', authenticate, authorize(['professional', 'admin']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.toString().replace(/\D/g, '');

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
app.post('/api/dependents', authenticate, authorize(['client', 'admin']), async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    if (!client_id || !name || !cpf) {
      return res.status(400).json({ message: 'ID do cliente, nome e CPF são obrigatórios' });
    }

    // Clients can only create dependents for themselves
    if (req.user.currentRole === 'client' && req.user.id !== client_id) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    // Validate CPF format
    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
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
      'SELECT COUNT(*) FROM dependents WHERE client_id = $1',
      [client_id]
    );

    if (parseInt(dependentCount.rows[0].count) >= 10) {
      return res.status(400).json({ message: 'Limite de 10 dependentes por cliente atingido' });
    }

    const result = await pool.query(`
      INSERT INTO dependents (client_id, name, cpf, birth_date, created_at)
      VALUES ($1, $2, $3, $4, NOW())
      RETURNING *
    `, [client_id, name.trim(), cleanCpf, birth_date || null]);

    res.status(201).json({
      message: 'Dependente criado com sucesso',
      dependent: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating dependent:', error);
    res.status(500).json({ message: 'Erro ao criar dependente' });
  }
});

// Update dependent
app.put('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    // Get dependent to check ownership
    const dependent = await pool.query(
      'SELECT client_id FROM dependents WHERE id = $1',
      [id]
    );

    if (dependent.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    // Clients can only update their own dependents
    if (req.user.currentRole === 'client' && req.user.id !== dependent.rows[0].client_id) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    const result = await pool.query(`
      UPDATE dependents 
      SET name = $1, birth_date = $2, updated_at = NOW()
      WHERE id = $3
      RETURNING *
    `, [name.trim(), birth_date || null, id]);

    res.json({
      message: 'Dependente atualizado com sucesso',
      dependent: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating dependent:', error);
    res.status(500).json({ message: 'Erro ao atualizar dependente' });
  }
});

// Delete dependent
app.delete('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    // Get dependent to check ownership
    const dependent = await pool.query(
      'SELECT client_id FROM dependents WHERE id = $1',
      [id]
    );

    if (dependent.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    // Clients can only delete their own dependents
    if (req.user.currentRole === 'client' && req.user.id !== dependent.rows[0].client_id) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    await pool.query('DELETE FROM dependents WHERE id = $1', [id]);

    res.json({ message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting dependent:', error);
    res.status(500).json({ message: 'Erro ao excluir dependente' });
  }
});

// ==================== PRIVATE PATIENTS ROUTES ====================

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
    console.error('Error fetching private patients:', error);
    res.status(500).json({ message: 'Erro ao carregar pacientes' });
  }
});

// Create private patient
app.post('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    if (!name || !cpf) {
      return res.status(400).json({ message: 'Nome e CPF são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    // Validate CPF format
    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    // Check if CPF already exists for this professional
    const existingPatient = await pool.query(
      'SELECT id FROM private_patients WHERE cpf = $1 AND professional_id = $2',
      [cleanCpf, req.user.id]
    );

    if (existingPatient.rows.length > 0) {
      return res.status(409).json({ message: 'Paciente já cadastrado com este CPF' });
    }

    const result = await pool.query(`
      INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date, address,
        address_number, address_complement, neighborhood, city, state, zip_code, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
      RETURNING *
    `, [
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
    ]);

    res.status(201).json({
      message: 'Paciente criado com sucesso',
      patient: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating private patient:', error);
    res.status(500).json({ message: 'Erro ao criar paciente' });
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

    // Check if patient belongs to this professional
    const patient = await pool.query(
      'SELECT professional_id FROM private_patients WHERE id = $1',
      [id]
    );

    if (patient.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    if (patient.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    const result = await pool.query(`
      UPDATE private_patients 
      SET name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
          address_number = $6, address_complement = $7, neighborhood = $8,
          city = $9, state = $10, zip_code = $11, updated_at = NOW()
      WHERE id = $12
      RETURNING *
    `, [
      name.trim(),
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
      id
    ]);

    res.json({
      message: 'Paciente atualizado com sucesso',
      patient: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating private patient:', error);
    res.status(500).json({ message: 'Erro ao atualizar paciente' });
  }
});

// Delete private patient
app.delete('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    // Check if patient belongs to this professional
    const patient = await pool.query(
      'SELECT professional_id FROM private_patients WHERE id = $1',
      [id]
    );

    if (patient.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    if (patient.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    await pool.query('DELETE FROM private_patients WHERE id = $1', [id]);

    res.json({ message: 'Paciente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting private patient:', error);
    res.status(500).json({ message: 'Erro ao excluir paciente' });
  }
});

// ==================== CONSULTATIONS ROUTES ====================

// Get consultations
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query = `
      SELECT 
        c.id, c.date, c.value, c.status, c.notes, c.created_at,
        s.name as service_name,
        u.name as professional_name,
        COALESCE(u2.name, pp.name) as client_name,
        CASE 
          WHEN c.dependent_id IS NOT NULL THEN true 
          ELSE false 
        END as is_dependent,
        al.name as location_name
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      JOIN users u ON c.professional_id = u.id
      LEFT JOIN users u2 ON c.client_id = u2.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN attendance_locations al ON c.location_id = al.id
    `;

    let params = [];
    let whereConditions = [];

    // Filter based on user role
    if (req.user.currentRole === 'client') {
      whereConditions.push('(c.client_id = $1 OR d.client_id = $1)');
      params.push(req.user.id);
    } else if (req.user.currentRole === 'professional') {
      whereConditions.push('c.professional_id = $1');
      params.push(req.user.id);
    }

    if (whereConditions.length > 0) {
      query += ' WHERE ' + whereConditions.join(' AND ');
    }

    query += ' ORDER BY c.date DESC';

    const result = await pool.query(query, params);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching consultations:', error);
    res.status(500).json({ message: 'Erro ao carregar consultas' });
  }
});

// Create consultation
app.post('/api/consultations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      client_id, dependent_id, private_patient_id, service_id,
      location_id, value, date, status, notes
    } = req.body;

    if (!service_id || !value || !date) {
      return res.status(400).json({ message: 'Serviço, valor e data são obrigatórios' });
    }

    // Validate that at least one patient type is selected
    if (!client_id && !dependent_id && !private_patient_id) {
      return res.status(400).json({ message: 'É necessário selecionar um cliente, dependente ou paciente particular' });
    }

    const result = await pool.query(`
      INSERT INTO consultations (
        client_id, dependent_id, private_patient_id, professional_id, service_id,
        location_id, value, date, status, notes, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
      RETURNING *
    `, [
      client_id || null,
      dependent_id || null,
      private_patient_id || null,
      req.user.id,
      service_id,
      location_id || null,
      parseFloat(value),
      new Date(date),
      status || 'completed',
      notes || null
    ]);

    res.status(201).json({
      message: 'Consulta registrada com sucesso',
      consultation: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro ao registrar consulta' });
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

    // Check if consultation belongs to this professional
    const consultation = await pool.query(
      'SELECT professional_id FROM consultations WHERE id = $1',
      [id]
    );

    if (consultation.rows.length === 0) {
      return res.status(404).json({ message: 'Consulta não encontrada' });
    }

    if (consultation.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    await pool.query(
      'UPDATE consultations SET status = $1, updated_at = NOW() WHERE id = $2',
      [status, id]
    );

    res.json({ message: 'Status atualizado com sucesso' });
  } catch (error) {
    console.error('Error updating consultation status:', error);
    res.status(500).json({ message: 'Erro ao atualizar status' });
  }
});

// ==================== MEDICAL RECORDS ROUTES ====================

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

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical records:', error);
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
      return res.status(400).json({ message: 'ID do paciente é obrigatório' });
    }

    // Verify patient belongs to this professional
    const patient = await pool.query(
      'SELECT id FROM private_patients WHERE id = $1 AND professional_id = $2',
      [private_patient_id, req.user.id]
    );

    if (patient.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    const result = await pool.query(`
      INSERT INTO medical_records (
        professional_id, private_patient_id, chief_complaint, history_present_illness,
        past_medical_history, medications, allergies, physical_examination,
        diagnosis, treatment_plan, notes, vital_signs, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
      RETURNING *
    `, [
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
      vital_signs || null
    ]);

    res.status(201).json({
      message: 'Prontuário criado com sucesso',
      record: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating medical record:', error);
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

    // Check if record belongs to this professional
    const record = await pool.query(
      'SELECT professional_id FROM medical_records WHERE id = $1',
      [id]
    );

    if (record.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    if (record.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    const result = await pool.query(`
      UPDATE medical_records 
      SET chief_complaint = $1, history_present_illness = $2, past_medical_history = $3,
          medications = $4, allergies = $5, physical_examination = $6, diagnosis = $7,
          treatment_plan = $8, notes = $9, vital_signs = $10, updated_at = NOW()
      WHERE id = $11
      RETURNING *
    `, [
      chief_complaint || null,
      history_present_illness || null,
      past_medical_history || null,
      medications || null,
      allergies || null,
      physical_examination || null,
      diagnosis || null,
      treatment_plan || null,
      notes || null,
      vital_signs || null,
      id
    ]);

    res.json({
      message: 'Prontuário atualizado com sucesso',
      record: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating medical record:', error);
    res.status(500).json({ message: 'Erro ao atualizar prontuário' });
  }
});

// Delete medical record
app.delete('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    // Check if record belongs to this professional
    const record = await pool.query(
      'SELECT professional_id FROM medical_records WHERE id = $1',
      [id]
    );

    if (record.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    if (record.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    await pool.query('DELETE FROM medical_records WHERE id = $1', [id]);

    res.json({ message: 'Prontuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting medical record:', error);
    res.status(500).json({ message: 'Erro ao excluir prontuário' });
  }
});

// ==================== MEDICAL DOCUMENTS ROUTES ====================

// Get medical documents for professional
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        md.id, md.title, md.document_type, md.document_url, md.created_at,
        COALESCE(pp.name, d.name, u.name) as patient_name
      FROM medical_documents md
      LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
      LEFT JOIN dependents d ON md.dependent_id = d.id
      LEFT JOIN users u ON md.client_id = u.id
      WHERE md.professional_id = $1
      ORDER BY md.created_at DESC
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical documents:', error);
    res.status(500).json({ message: 'Erro ao carregar documentos' });
  }
});

// Create medical document
app.post('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { title, document_type, private_patient_id, client_id, dependent_id, template_data } = req.body;

    if (!title || !document_type || !template_data) {
      return res.status(400).json({ message: 'Título, tipo de documento e dados do template são obrigatórios' });
    }

    // Generate document
    const documentResult = await generateDocumentPDF(document_type, template_data);

    // Save document record
    const result = await pool.query(`
      INSERT INTO medical_documents (
        professional_id, private_patient_id, client_id, dependent_id,
        title, document_type, document_url, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      RETURNING *
    `, [
      req.user.id,
      private_patient_id || null,
      client_id || null,
      dependent_id || null,
      title,
      document_type,
      documentResult.url
    ]);

    res.status(201).json({
      message: 'Documento criado com sucesso',
      document: result.rows[0],
      title: title,
      documentUrl: documentResult.url
    });
  } catch (error) {
    console.error('Error creating medical document:', error);
    res.status(500).json({ message: 'Erro ao criar documento' });
  }
});

// ==================== ATTENDANCE LOCATIONS ROUTES ====================

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
    console.error('Error fetching attendance locations:', error);
    res.status(500).json({ message: 'Erro ao carregar locais' });
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
      return res.status(400).json({ message: 'Nome do local é obrigatório' });
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
        neighborhood, city, state, zip_code, phone, is_default, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
      RETURNING *
    `, [
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
    ]);

    res.status(201).json({
      message: 'Local criado com sucesso',
      location: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating attendance location:', error);
    res.status(500).json({ message: 'Erro ao criar local' });
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

    // Check if location belongs to this professional
    const location = await pool.query(
      'SELECT professional_id FROM attendance_locations WHERE id = $1',
      [id]
    );

    if (location.rows.length === 0) {
      return res.status(404).json({ message: 'Local não encontrado' });
    }

    if (location.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
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
          neighborhood = $5, city = $6, state = $7, zip_code = $8, phone = $9,
          is_default = $10, updated_at = NOW()
      WHERE id = $11
      RETURNING *
    `, [
      name.trim(),
      address?.trim() || null,
      address_number?.trim() || null,
      address_complement?.trim() || null,
      neighborhood?.trim() || null,
      city?.trim() || null,
      state || null,
      zip_code?.replace(/\D/g, '') || null,
      phone?.replace(/\D/g, '') || null,
      is_default || false,
      id
    ]);

    res.json({
      message: 'Local atualizado com sucesso',
      location: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating attendance location:', error);
    res.status(500).json({ message: 'Erro ao atualizar local' });
  }
});

// Delete attendance location
app.delete('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    // Check if location belongs to this professional
    const location = await pool.query(
      'SELECT professional_id FROM attendance_locations WHERE id = $1',
      [id]
    );

    if (location.rows.length === 0) {
      return res.status(404).json({ message: 'Local não encontrado' });
    }

    if (location.rows[0].professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    await pool.query('DELETE FROM attendance_locations WHERE id = $1', [id]);

    res.json({ message: 'Local excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting attendance location:', error);
    res.status(500).json({ message: 'Erro ao excluir local' });
  }
});

// ==================== UPLOAD ROUTES ====================

// Upload image route
app.post('/api/upload-image', authenticate, async (req, res) => {
  try {
    // Create upload middleware instance
    const upload = createUpload();
    
    // Use multer middleware
    upload.single('image')(req, res, async (err) => {
      if (err) {
        console.error('Upload error:', err);
        return res.status(400).json({ message: err.message || 'Erro no upload da imagem' });
      }

      if (!req.file) {
        return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
      }

      try {
        // Update user's photo_url in database
        await pool.query(
          'UPDATE users SET photo_url = $1, updated_at = NOW() WHERE id = $2',
          [req.file.path, req.user.id]
        );

        res.json({
          message: 'Imagem enviada com sucesso',
          imageUrl: req.file.path
        });
      } catch (dbError) {
        console.error('Database error after upload:', dbError);
        res.status(500).json({ message: 'Erro ao salvar URL da imagem' });
      }
    });
  } catch (error) {
    console.error('Error in upload route:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== PAYMENT ROUTES ====================

// Get base URL for redirects
const getBaseUrl = () => {
  if (process.env.NODE_ENV === 'production') {
    return 'https://www.cartaoquiroferreira.com.br';
  }
  return 'http://localhost:5173';
};

// Create subscription payment (clients)
app.post('/api/create-subscription', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { user_id, dependent_ids = [] } = req.body;

    // Verify user is the authenticated client
    if (req.user.id !== user_id) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    // Get user data
    const userResult = await pool.query(
      'SELECT name, email FROM users WHERE id = $1',
      [user_id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = userResult.rows[0];

    // Calculate total amount
    const baseAmount = 250; // R$250 for titular
    const dependentAmount = dependent_ids.length * 50; // R$50 per dependent
    const totalAmount = baseAmount + dependentAmount;

    const baseUrl = getBaseUrl();

    // Create preference
    const preference = new Preference(client);
    
    const preferenceData = {
      items: [
        {
          id: `subscription_${user_id}`,
          title: `Assinatura Cartão Quiro Ferreira - ${user.name}`,
          description: `Assinatura mensal (Titular + ${dependent_ids.length} dependente(s))`,
          quantity: 1,
          unit_price: totalAmount
        }
      ],
      payer: {
        name: user.name,
        email: user.email || 'contato@quiroferreira.com.br'
      },
      back_urls: {
        success: `${baseUrl}/client?payment=success`,
        failure: `${baseUrl}/client?payment=failure`,
        pending: `${baseUrl}/client?payment=pending`
      },
      auto_return: 'approved',
      notification_url: `${getBaseUrl().replace('localhost:5173', 'localhost:3001')}/api/webhooks/mercadopago`,
      metadata: {
        user_id: user_id.toString(),
        payment_type: 'subscription',
        dependent_ids: dependent_ids.join(',')
      }
    };

    const result = await preference.create({ body: preferenceData });

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point
    });
  } catch (error) {
    console.error('Error creating subscription payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento' });
  }
});

// Create professional payment
app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor inválido' });
    }

    // Get professional data
    const userResult = await pool.query(
      'SELECT name, email FROM users WHERE id = $1',
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professional = userResult.rows[0];
    const baseUrl = getBaseUrl();

    // Create preference
    const preference = new Preference(client);
    
    const preferenceData = {
      items: [
        {
          id: `professional_payment_${req.user.id}`,
          title: `Repasse ao Convênio - ${professional.name}`,
          description: 'Pagamento de repasse mensal ao Convênio Quiro Ferreira',
          quantity: 1,
          unit_price: amount
        }
      ],
      payer: {
        name: professional.name,
        email: professional.email || 'contato@quiroferreira.com.br'
      },
      back_urls: {
        success: `${baseUrl}/professional?payment=success`,
        failure: `${baseUrl}/professional?payment=failure`,
        pending: `${baseUrl}/professional?payment=pending`
      },
      auto_return: 'approved',
      notification_url: `${getBaseUrl().replace('localhost:5173', 'localhost:3001')}/api/webhooks/mercadopago`,
      metadata: {
        professional_id: req.user.id.toString(),
        payment_type: 'professional_payment',
        amount: amount.toString()
      }
    };

    const result = await preference.create({ body: preferenceData });

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point
    });
  } catch (error) {
    console.error('Error creating professional payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento' });
  }
});

// ==================== WEBHOOK ROUTES ====================

// MercadoPago webhook
app.post('/api/webhooks/mercadopago', async (req, res) => {
  try {
    console.log('🔔 Webhook received:', req.body);

    const { type, data } = req.body;

    if (type === 'payment') {
      const paymentId = data.id;
      
      // Get payment details from MercadoPago
      const paymentResponse = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
        headers: {
          'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}`
        }
      });

      if (!paymentResponse.ok) {
        throw new Error('Failed to fetch payment details');
      }

      const payment = await paymentResponse.json();
      console.log('💳 Payment details:', payment);

      if (payment.status === 'approved') {
        const metadata = payment.metadata;
        
        if (metadata.payment_type === 'subscription') {
          // Handle subscription payment
          const userId = parseInt(metadata.user_id);
          
          // Set subscription expiry to 1 month from now
          const expiryDate = new Date();
          expiryDate.setMonth(expiryDate.getMonth() + 1);
          
          await pool.query(
            'UPDATE users SET subscription_status = $1, subscription_expiry = $2, updated_at = NOW() WHERE id = $3',
            ['active', expiryDate.toISOString().split('T')[0], userId]
          );

          console.log('✅ Subscription activated for user:', userId);
          
        } else if (metadata.payment_type === 'professional_payment') {
          // Handle professional payment
          const professionalId = parseInt(metadata.professional_id);
          const amount = parseFloat(metadata.amount);
          
          // Record payment
          await pool.query(`
            INSERT INTO professional_payments (
              professional_id, amount, payment_id, payment_status, payment_date, created_at
            ) VALUES ($1, $2, $3, $4, NOW(), NOW())
          `, [professionalId, amount, paymentId, 'approved']);

          console.log('✅ Professional payment recorded:', { professionalId, amount });
        }
      }
    }

    res.status(200).json({ message: 'Webhook processed' });
  } catch (error) {
    console.error('❌ Webhook error:', error);
    res.status(500).json({ message: 'Webhook processing failed' });
  }
});

// ==================== REPORTS ROUTES ====================

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
        u.name as professional_name,
        u.percentage as professional_percentage,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count,
        SUM(c.value * (u.percentage / 100.0)) as professional_payment,
        SUM(c.value * ((100 - u.percentage) / 100.0)) as clinic_revenue
      FROM consultations c
      JOIN users u ON c.professional_id = u.id
      WHERE c.date >= $1 AND c.date <= $2
        AND c.client_id IS NOT NULL  -- Only convenio consultations
      GROUP BY u.id, u.name, u.percentage
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
    const totalRevenueResult = await pool.query(`
      SELECT SUM(value) as total_revenue
      FROM consultations
      WHERE date >= $1 AND date <= $2
        AND client_id IS NOT NULL  -- Only convenio consultations
    `, [start_date, end_date]);

    const totalRevenue = parseFloat(totalRevenueResult.rows[0].total_revenue) || 0;

    res.json({
      total_revenue: totalRevenue,
      revenue_by_professional: professionalRevenueResult.rows.map(row => ({
        ...row,
        revenue: parseFloat(row.revenue),
        professional_payment: parseFloat(row.professional_payment),
        clinic_revenue: parseFloat(row.clinic_revenue)
      })),
      revenue_by_service: serviceRevenueResult.rows.map(row => ({
        ...row,
        revenue: parseFloat(row.revenue)
      }))
    });
  } catch (error) {
    console.error('Error generating revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
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
        c.date, c.value,
        s.name as service_name,
        COALESCE(u.name, pp.name, d.name) as client_name,
        c.value * ((100 - $3) / 100.0) as amount_to_pay
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      WHERE c.professional_id = $1 
        AND c.date >= $2 AND c.date <= $4
        AND c.client_id IS NOT NULL  -- Only convenio consultations count for payment
      ORDER BY c.date DESC
    `, [req.user.id, start_date, professionalPercentage, end_date]);

    // Calculate summary
    const consultations = consultationsResult.rows;
    const totalRevenue = consultations.reduce((sum, c) => sum + parseFloat(c.value), 0);
    const amountToPay = consultations.reduce((sum, c) => sum + parseFloat(c.amount_to_pay), 0);

    res.json({
      summary: {
        professional_percentage: professionalPercentage,
        total_revenue: totalRevenue,
        consultation_count: consultations.length,
        amount_to_pay: amountToPay
      },
      consultations: consultations.map(c => ({
        ...c,
        total_value: parseFloat(c.value),
        amount_to_pay: parseFloat(c.amount_to_pay)
      }))
    });
  } catch (error) {
    console.error('Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
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

    // Get all consultations (convenio and private)
    const consultationsResult = await pool.query(`
      SELECT 
        c.date, c.value,
        s.name as service_name,
        COALESCE(u.name, pp.name, d.name) as client_name,
        CASE 
          WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN 'convenio'
          ELSE 'private'
        END as consultation_type
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      WHERE c.professional_id = $1 
        AND c.date >= $2 AND c.date <= $3
      ORDER BY c.date DESC
    `, [req.user.id, start_date, end_date]);

    const consultations = consultationsResult.rows;

    // Calculate summary
    const convenioConsultations = consultations.filter(c => c.consultation_type === 'convenio');
    const privateConsultations = consultations.filter(c => c.consultation_type === 'private');

    const convenioRevenue = convenioConsultations.reduce((sum, c) => sum + parseFloat(c.value), 0);
    const privateRevenue = privateConsultations.reduce((sum, c) => sum + parseFloat(c.value), 0);
    const totalRevenue = convenioRevenue + privateRevenue;

    const amountToPay = convenioRevenue * ((100 - professionalPercentage) / 100);

    res.json({
      summary: {
        total_consultations: consultations.length,
        convenio_consultations: convenioConsultations.length,
        private_consultations: privateConsultations.length,
        total_revenue: totalRevenue,
        convenio_revenue: convenioRevenue,
        private_revenue: privateRevenue,
        professional_percentage: professionalPercentage,
        amount_to_pay: amountToPay
      }
    });
  } catch (error) {
    console.error('Error generating professional detailed report:', error);
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
      WHERE roles @> '["client"]' 
        AND city IS NOT NULL 
        AND city != ''
      GROUP BY city, state
      ORDER BY client_count DESC, city
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error generating clients by city report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório por cidade' });
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
      WHERE u.roles @> '["professional"]' 
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
    res.status(500).json({ message: 'Erro ao gerar relatório por cidade' });
  }
});

// ==================== ERROR HANDLING ====================

// Global error handler
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);
  res.status(500).json({ 
    message: 'Erro interno do servidor',
    error: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
});

// Handle 404 for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ message: 'Rota não encontrada' });
});

// Serve React app for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`💳 MercadoPago configured: ${process.env.MP_ACCESS_TOKEN ? '✅' : '❌'}`);
});

export default app;