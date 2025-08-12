import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';
import createUpload from './middleware/upload.js';
import { generateDocumentPDF } from './utils/documentGenerator.js';

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

// ==================== AUTH ROUTES ====================

// Login route
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

    console.log('🔄 Login attempt for CPF:', cpf);

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

    console.log('✅ Login successful for user:', user.name);

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
      return res.status(400).json({ message: 'userId e role são obrigatórios' });
    }

    // Get user and verify role
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

    // Generate JWT token with role
    const token = jwt.sign(
      { id: user.id, currentRole: role },
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

    console.log('✅ Role selected and token generated');

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
    const userId = req.user.id;

    console.log('🔄 Role switch:', { userId, role });

    if (!role) {
      return res.status(400).json({ message: 'Role é obrigatória' });
    }

    // Get user and verify role
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

    // Generate new JWT token with new role
    const token = jwt.sign(
      { id: user.id, currentRole: role },
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

    console.log('✅ Role switched successfully');

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

    console.log('🔄 Registration attempt for:', name);

    // Validate required fields
    if (!name || !cpf || !password) {
      return res.status(400).json({ message: 'Nome, CPF e senha são obrigatórios' });
    }

    // Validate CPF format
    const cleanCpf = cpf.replace(/\D/g, '');
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

    // Insert new user (client only)
    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password_hash, roles,
        subscription_status, created_at
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
        JSON.stringify(['client']),
        'pending'
      ]
    );

    const newUser = result.rows[0];

    console.log('✅ User registered successfully:', newUser.name);

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
    console.error('❌ Registration error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
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
    res.status(500).json({ message: 'Erro interno do servidor' });
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
    res.status(500).json({ message: 'Erro interno do servidor' });
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

    // Validate required fields
    if (!name || !cpf || !password || !roles || roles.length === 0) {
      return res.status(400).json({ message: 'Campos obrigatórios: nome, CPF, senha e pelo menos uma role' });
    }

    // Validate CPF
    const cleanCpf = cpf.replace(/\D/g, '');
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

    // Set subscription status for clients
    const subscriptionStatus = roles.includes('client') ? 'pending' : null;

    // Insert user
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
      JSON.stringify(roles),
      percentage || null,
      category_id || null,
      subscriptionStatus
    ]);

    console.log('✅ User created:', result.rows[0].name);

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      user: result.rows[0]
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
    const {
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, roles,
      percentage, category_id, currentPassword, newPassword
    } = req.body;

    // Check if user exists
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = userResult.rows[0];

    // If changing password, verify current password
    let passwordHash = user.password_hash;
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: 'Senha atual é obrigatória para alterar a senha' });
      }

      const isValidPassword = await bcrypt.compare(currentPassword, user.password_hash);
      if (!isValidPassword) {
        return res.status(401).json({ message: 'Senha atual incorreta' });
      }

      passwordHash = await bcrypt.hash(newPassword, 10);
    }

    // Update user
    const result = await pool.query(`
      UPDATE users SET
        name = $1, email = $2, phone = $3, birth_date = $4,
        address = $5, address_number = $6, address_complement = $7,
        neighborhood = $8, city = $9, state = $10, roles = $11,
        percentage = $12, category_id = $13, password_hash = $14,
        updated_at = NOW()
      WHERE id = $15
      RETURNING id, name, cpf, roles
    `, [
      name?.trim() || user.name,
      email?.trim() || user.email,
      phone?.replace(/\D/g, '') || user.phone,
      birth_date || user.birth_date,
      address?.trim() || user.address,
      address_number?.trim() || user.address_number,
      address_complement?.trim() || user.address_complement,
      neighborhood?.trim() || user.neighborhood,
      city?.trim() || user.city,
      state || user.state,
      roles ? JSON.stringify(roles) : user.roles,
      percentage || user.percentage,
      category_id || user.category_id,
      passwordHash,
      id
    ]);

    console.log('✅ User updated:', result.rows[0].name);

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

    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING name', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    console.log('✅ User deleted:', result.rows[0].name);

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

    const result = await pool.query(`
      UPDATE users 
      SET subscription_status = 'active', subscription_expiry = $1, updated_at = NOW()
      WHERE id = $2 AND roles @> '["client"]'
      RETURNING name
    `, [expiry_date, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    console.log('✅ Client activated:', result.rows[0].name);

    res.json({ message: 'Cliente ativado com sucesso' });
  } catch (error) {
    console.error('❌ Error activating client:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== PROFESSIONAL ROUTES ====================

// Get professionals for clients
app.get('/api/professionals', authenticate, authorize(['client', 'admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone, u.roles,
        u.address, u.address_number, u.address_complement,
        u.neighborhood, u.city, u.state, u.photo_url,
        sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE u.roles @> '["professional"]'
      ORDER BY u.name
    `);

    res.json(result.rows);
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
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Grant scheduling access (admin only)
app.post('/api/admin/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;
    const adminName = req.user.name;

    if (!professional_id || !expires_at) {
      return res.status(400).json({ message: 'professional_id e expires_at são obrigatórios' });
    }

    const result = await pool.query(`
      UPDATE users 
      SET 
        has_scheduling_access = true,
        access_expires_at = $1,
        access_granted_by = $2,
        access_granted_at = NOW(),
        access_reason = $3,
        updated_at = NOW()
      WHERE id = $4 AND roles @> '["professional"]'
      RETURNING name
    `, [expires_at, adminName, reason, professional_id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    console.log('✅ Scheduling access granted to:', result.rows[0].name);

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
      return res.status(400).json({ message: 'professional_id é obrigatório' });
    }

    const result = await pool.query(`
      UPDATE users 
      SET 
        has_scheduling_access = false,
        access_expires_at = NULL,
        access_granted_by = NULL,
        access_granted_at = NULL,
        access_reason = NULL,
        updated_at = NOW()
      WHERE id = $1 AND roles @> '["professional"]'
      RETURNING name
    `, [professional_id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    console.log('✅ Scheduling access revoked from:', result.rows[0].name);

    res.json({ message: 'Acesso à agenda revogado com sucesso' });
  } catch (error) {
    console.error('❌ Error revoking scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== CLIENT ROUTES ====================

// Lookup client by CPF
app.get('/api/clients/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    const result = await pool.query(`
      SELECT id, name, cpf, subscription_status
      FROM users 
      WHERE cpf = $1 AND roles @> '["client"]'
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

// ==================== DEPENDENT ROUTES ====================

// Get dependents by client ID
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;

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

    const result = await pool.query(`
      SELECT 
        d.id, d.name, d.cpf, d.client_id,
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
app.post('/api/dependents', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    // Validate required fields
    if (!client_id || !name || !cpf) {
      return res.status(400).json({ message: 'client_id, nome e CPF são obrigatórios' });
    }

    // Validate CPF
    const cleanCpf = cpf.replace(/\D/g, '');
    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    // Check if CPF already exists
    const existingCpf = await pool.query(`
      SELECT 1 FROM users WHERE cpf = $1
      UNION
      SELECT 1 FROM dependents WHERE cpf = $1
    `, [cleanCpf]);

    if (existingCpf.rows.length > 0) {
      return res.status(409).json({ message: 'CPF já cadastrado no sistema' });
    }

    // Check dependent limit (10 per client)
    const dependentCount = await pool.query(
      'SELECT COUNT(*) as count FROM dependents WHERE client_id = $1',
      [client_id]
    );

    if (parseInt(dependentCount.rows[0].count) >= 10) {
      return res.status(400).json({ message: 'Limite máximo de 10 dependentes por cliente' });
    }

    // Insert dependent
    const result = await pool.query(`
      INSERT INTO dependents (client_id, name, cpf, birth_date, created_at)
      VALUES ($1, $2, $3, $4, NOW())
      RETURNING id, name, cpf, birth_date, created_at
    `, [client_id, name.trim(), cleanCpf, birth_date || null]);

    console.log('✅ Dependent created:', result.rows[0].name);

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
app.put('/api/dependents/:id', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    const result = await pool.query(`
      UPDATE dependents 
      SET name = $1, birth_date = $2, updated_at = NOW()
      WHERE id = $3
      RETURNING id, name, cpf, birth_date, created_at
    `, [name?.trim(), birth_date, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    console.log('✅ Dependent updated:', result.rows[0].name);

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
app.delete('/api/dependents/:id', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query('DELETE FROM dependents WHERE id = $1 RETURNING name', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    console.log('✅ Dependent deleted:', result.rows[0].name);

    res.json({ message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== SERVICE ROUTES ====================

// Get all services
app.get('/api/services', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        s.id, s.name, s.description, s.base_price, s.category_id,
        s.is_base_service, sc.name as category_name
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

    const result = await pool.query(`
      INSERT INTO services (name, description, base_price, category_id, is_base_service, created_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
      RETURNING id, name
    `, [name.trim(), description.trim(), base_price, category_id || null, is_base_service || false]);

    console.log('✅ Service created:', result.rows[0].name);

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

    const result = await pool.query(`
      UPDATE services 
      SET name = $1, description = $2, base_price = $3, category_id = $4, 
          is_base_service = $5, updated_at = NOW()
      WHERE id = $6
      RETURNING id, name
    `, [name?.trim(), description?.trim(), base_price, category_id || null, is_base_service || false, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    console.log('✅ Service updated:', result.rows[0].name);

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

    const result = await pool.query('DELETE FROM services WHERE id = $1 RETURNING name', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    console.log('✅ Service deleted:', result.rows[0].name);

    res.json({ message: 'Serviço excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting service:', error);
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

    if (!name || !description) {
      return res.status(400).json({ message: 'Nome e descrição são obrigatórios' });
    }

    const result = await pool.query(`
      INSERT INTO service_categories (name, description, created_at)
      VALUES ($1, $2, NOW())
      RETURNING id, name, description
    `, [name.trim(), description.trim()]);

    console.log('✅ Service category created:', result.rows[0].name);

    res.status(201).json({
      message: 'Categoria criada com sucesso',
      category: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error creating service category:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== CONSULTATION ROUTES ====================

// Get consultations
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query;
    let params;

    if (req.user.currentRole === 'client') {
      // For clients, get their consultations and their dependents' consultations
      query = `
        SELECT 
          c.id, c.date, c.value, s.name as service_name,
          u.name as professional_name,
          COALESCE(cl.name, d.name) as client_name,
          CASE WHEN d.id IS NOT NULL THEN true ELSE false END as is_dependent
        FROM consultations c
        LEFT JOIN users cl ON c.client_id = cl.id
        LEFT JOIN dependents d ON c.dependent_id = d.id
        LEFT JOIN users u ON c.professional_id = u.id
        LEFT JOIN services s ON c.service_id = s.id
        WHERE c.client_id = $1 OR c.dependent_id IN (
          SELECT id FROM dependents WHERE client_id = $1
        )
        ORDER BY c.date DESC
      `;
      params = [req.user.id];
    } else if (req.user.currentRole === 'professional') {
      // For professionals, get their consultations
      query = `
        SELECT 
          c.id, c.date, c.value, s.name as service_name,
          u.name as professional_name,
          COALESCE(cl.name, d.name, pp.name) as client_name,
          CASE WHEN d.id IS NOT NULL THEN true ELSE false END as is_dependent
        FROM consultations c
        LEFT JOIN users cl ON c.client_id = cl.id
        LEFT JOIN dependents d ON c.dependent_id = d.id
        LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
        LEFT JOIN users u ON c.professional_id = u.id
        LEFT JOIN services s ON c.service_id = s.id
        WHERE c.professional_id = $1
        ORDER BY c.date DESC
      `;
      params = [req.user.id];
    } else {
      // For admins, get all consultations
      query = `
        SELECT 
          c.id, c.date, c.value, s.name as service_name,
          u.name as professional_name,
          COALESCE(cl.name, d.name, pp.name) as client_name,
          CASE WHEN d.id IS NOT NULL THEN true ELSE false END as is_dependent
        FROM consultations c
        LEFT JOIN users cl ON c.client_id = cl.id
        LEFT JOIN dependents d ON c.dependent_id = d.id
        LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
        LEFT JOIN users u ON c.professional_id = u.id
        LEFT JOIN services s ON c.service_id = s.id
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
      appointment_date,
      appointment_time,
      create_appointment
    } = req.body;

    const professional_id = req.user.id;

    // Validate required fields
    if (!service_id || !value || !date) {
      return res.status(400).json({ message: 'service_id, value e date são obrigatórios' });
    }

    // Validate that either client_id, dependent_id, or private_patient_id is provided
    if (!client_id && !dependent_id && !private_patient_id) {
      return res.status(400).json({ message: 'É necessário especificar client_id, dependent_id ou private_patient_id' });
    }

    // Start transaction
    const client = await pool.connect();
    
    try {
      await client.query('BEGIN');

      // Insert consultation
      const consultationResult = await client.query(`
        INSERT INTO consultations (
          client_id, dependent_id, private_patient_id, professional_id,
          service_id, location_id, value, date, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        RETURNING id
      `, [
        client_id || null,
        dependent_id || null,
        private_patient_id || null,
        professional_id,
        service_id,
        location_id || null,
        value,
        date
      ]);

      const consultationId = consultationResult.rows[0].id;

      // Create appointment if requested
      let appointmentId = null;
      if (create_appointment && appointment_date && appointment_time) {
        const appointmentDateTime = new Date(`${appointment_date}T${appointment_time}`);
        
        const appointmentResult = await client.query(`
          INSERT INTO appointments (
            client_id, dependent_id, private_patient_id, professional_id,
            service_id, location_id, date, status, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'scheduled', NOW())
          RETURNING id
        `, [
          client_id || null,
          dependent_id || null,
          private_patient_id || null,
          professional_id,
          service_id,
          location_id || null,
          appointmentDateTime
        ]);

        appointmentId = appointmentResult.rows[0].id;
      }

      await client.query('COMMIT');

      console.log('✅ Consultation created:', consultationId);
      if (appointmentId) {
        console.log('✅ Appointment created:', appointmentId);
      }

      res.status(201).json({
        message: 'Consulta registrada com sucesso',
        consultation: { id: consultationId },
        appointment: appointmentId ? { id: appointmentId } : null
      });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('❌ Error creating consultation:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== PRIVATE PATIENT ROUTES ====================

// Get private patients for professional
app.get('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, cpf, email, phone, birth_date,
        address, address_number, address_complement,
        neighborhood, city, state, zip_code, created_at
      FROM private_patients 
      WHERE professional_id = $1
      ORDER BY name
    `, [req.user.id]);

    res.json(result.rows);
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

    if (!name || !cpf) {
      return res.status(400).json({ message: 'Nome e CPF são obrigatórios' });
    }

    // Validate CPF
    const cleanCpf = cpf.replace(/\D/g, '');
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
        professional_id, name, cpf, email, phone, birth_date,
        address, address_number, address_complement, neighborhood,
        city, state, zip_code, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
      RETURNING id, name, cpf
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

    console.log('✅ Private patient created:', result.rows[0].name);

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
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    const result = await pool.query(`
      UPDATE private_patients 
      SET 
        name = $1, email = $2, phone = $3, birth_date = $4,
        address = $5, address_number = $6, address_complement = $7,
        neighborhood = $8, city = $9, state = $10, zip_code = $11,
        updated_at = NOW()
      WHERE id = $12 AND professional_id = $13
      RETURNING id, name, cpf
    `, [
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
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    console.log('✅ Private patient updated:', result.rows[0].name);

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

    const result = await pool.query(
      'DELETE FROM private_patients WHERE id = $1 AND professional_id = $2 RETURNING name',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    console.log('✅ Private patient deleted:', result.rows[0].name);

    res.json({ message: 'Paciente excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== MEDICAL RECORDS ROUTES ====================

// Get medical records for professional
app.get('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        mr.id, mr.chief_complaint, mr.history_present_illness,
        mr.past_medical_history, mr.medications, mr.allergies,
        mr.physical_examination, mr.diagnosis, mr.treatment_plan,
        mr.notes, mr.vital_signs, mr.created_at, mr.updated_at,
        pp.name as patient_name
      FROM medical_records mr
      JOIN private_patients pp ON mr.private_patient_id = pp.id
      WHERE pp.professional_id = $1
      ORDER BY mr.created_at DESC
    `, [req.user.id]);

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
      private_patient_id, chief_complaint, history_present_illness,
      past_medical_history, medications, allergies, physical_examination,
      diagnosis, treatment_plan, notes, vital_signs
    } = req.body;

    if (!private_patient_id) {
      return res.status(400).json({ message: 'private_patient_id é obrigatório' });
    }

    // Verify patient belongs to this professional
    const patientCheck = await pool.query(
      'SELECT id FROM private_patients WHERE id = $1 AND professional_id = $2',
      [private_patient_id, req.user.id]
    );

    if (patientCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    const result = await pool.query(`
      INSERT INTO medical_records (
        private_patient_id, chief_complaint, history_present_illness,
        past_medical_history, medications, allergies, physical_examination,
        diagnosis, treatment_plan, notes, vital_signs, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
      RETURNING id
    `, [
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
    ]);

    console.log('✅ Medical record created:', result.rows[0].id);

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
      chief_complaint, history_present_illness, past_medical_history,
      medications, allergies, physical_examination, diagnosis,
      treatment_plan, notes, vital_signs
    } = req.body;

    // Verify record belongs to this professional's patient
    const recordCheck = await pool.query(`
      SELECT mr.id 
      FROM medical_records mr
      JOIN private_patients pp ON mr.private_patient_id = pp.id
      WHERE mr.id = $1 AND pp.professional_id = $2
    `, [id, req.user.id]);

    if (recordCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    const result = await pool.query(`
      UPDATE medical_records 
      SET 
        chief_complaint = $1, history_present_illness = $2,
        past_medical_history = $3, medications = $4, allergies = $5,
        physical_examination = $6, diagnosis = $7, treatment_plan = $8,
        notes = $9, vital_signs = $10, updated_at = NOW()
      WHERE id = $11
      RETURNING id
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
      vital_signs ? JSON.stringify(vital_signs) : null,
      id
    ]);

    console.log('✅ Medical record updated:', result.rows[0].id);

    res.json({
      message: 'Prontuário atualizado com sucesso',
      record: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error updating medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete medical record
app.delete('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    // Verify record belongs to this professional's patient
    const result = await pool.query(`
      DELETE FROM medical_records 
      WHERE id = $1 AND private_patient_id IN (
        SELECT id FROM private_patients WHERE professional_id = $2
      )
      RETURNING id
    `, [id, req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    console.log('✅ Medical record deleted:', result.rows[0].id);

    res.json({ message: 'Prontuário excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== MEDICAL DOCUMENTS ROUTES ====================

// Get medical documents for professional
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        md.id, md.title, md.document_type, md.document_url, md.created_at,
        COALESCE(pp.name, 'Paciente não identificado') as patient_name
      FROM medical_documents md
      LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
      WHERE md.professional_id = $1
      ORDER BY md.created_at DESC
    `, [req.user.id]);

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

    if (!title || !document_type || !template_data) {
      return res.status(400).json({ message: 'title, document_type e template_data são obrigatórios' });
    }

    // Generate document
    const documentResult = await generateDocumentPDF(document_type, template_data);

    // Save document record
    const result = await pool.query(`
      INSERT INTO medical_documents (
        professional_id, private_patient_id, title, document_type,
        document_url, created_at
      ) VALUES ($1, $2, $3, $4, $5, NOW())
      RETURNING id, title, document_url
    `, [
      req.user.id,
      private_patient_id || null,
      title.trim(),
      document_type,
      documentResult.url
    ]);

    console.log('✅ Medical document created:', result.rows[0].title);

    res.status(201).json({
      message: 'Documento criado com sucesso',
      title: result.rows[0].title,
      documentUrl: result.rows[0].document_url
    });
  } catch (error) {
    console.error('❌ Error creating medical document:', error);
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
      name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    const client = await pool.connect();
    
    try {
      await client.query('BEGIN');

      // If setting as default, remove default from other locations
      if (is_default) {
        await client.query(
          'UPDATE attendance_locations SET is_default = false WHERE professional_id = $1',
          [req.user.id]
        );
      }

      // Insert new location
      const result = await client.query(`
        INSERT INTO attendance_locations (
          professional_id, name, address, address_number, address_complement,
          neighborhood, city, state, zip_code, phone, is_default, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
        RETURNING id, name
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

      await client.query('COMMIT');

      console.log('✅ Attendance location created:', result.rows[0].name);

      res.status(201).json({
        message: 'Local criado com sucesso',
        location: result.rows[0]
      });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
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
      name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    } = req.body;

    const client = await pool.connect();
    
    try {
      await client.query('BEGIN');

      // If setting as default, remove default from other locations
      if (is_default) {
        await client.query(
          'UPDATE attendance_locations SET is_default = false WHERE professional_id = $1 AND id != $2',
          [req.user.id, id]
        );
      }

      // Update location
      const result = await client.query(`
        UPDATE attendance_locations 
        SET 
          name = $1, address = $2, address_number = $3, address_complement = $4,
          neighborhood = $5, city = $6, state = $7, zip_code = $8,
          phone = $9, is_default = $10, updated_at = NOW()
        WHERE id = $11 AND professional_id = $12
        RETURNING id, name
      `, [
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
      ]);

      if (result.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ message: 'Local não encontrado' });
      }

      await client.query('COMMIT');

      console.log('✅ Attendance location updated:', result.rows[0].name);

      res.json({
        message: 'Local atualizado com sucesso',
        location: result.rows[0]
      });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('❌ Error updating attendance location:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete attendance location
app.delete('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM attendance_locations WHERE id = $1 AND professional_id = $2 RETURNING name',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Local não encontrado' });
    }

    console.log('✅ Attendance location deleted:', result.rows[0].name);

    res.json({ message: 'Local excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting attendance location:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== IMAGE UPLOAD ROUTE ====================

// Upload image route
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
        return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
      }

      console.log('📁 File uploaded to Cloudinary:', req.file.path);

      try {
        // Update user photo URL in database
        const result = await pool.query(
          'UPDATE users SET photo_url = $1, updated_at = NOW() WHERE id = $2 RETURNING photo_url',
          [req.file.path, req.user.id]
        );

        if (result.rows.length === 0) {
          return res.status(404).json({ message: 'Usuário não encontrado' });
        }

        console.log('✅ User photo updated in database');

        res.json({
          message: 'Imagem enviada com sucesso',
          imageUrl: req.file.path
        });
      } catch (dbError) {
        console.error('❌ Database error updating photo URL:', dbError);
        res.status(500).json({ message: 'Erro ao salvar URL da imagem no banco de dados' });
      }
    });
  } catch (error) {
    console.error('❌ Error in upload route:', error);
    res.status(500).json({ 
      message: 'Erro interno do servidor no upload',
      error: error.message 
    });
  }
});

// ==================== REPORT ROUTES ====================

// Professional revenue report - FIXED
app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    const professionalId = req.user.id;

    console.log('🔄 Generating professional revenue report for:', {
      professionalId,
      start_date,
      end_date
    });

    // Validate dates
    if (!start_date || !end_date) {
      return res.status(400).json({ 
        message: 'start_date e end_date são obrigatórios' 
      });
    }

    // Get professional percentage
    const professionalQuery = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [professionalId]
    );

    if (professionalQuery.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professionalPercentage = professionalQuery.rows[0].percentage || 50;

    // Get consultations with proper type casting and null handling
    const consultationsQuery = `
      SELECT 
        c.id,
        c.date,
        COALESCE(cl.name, d.name, pp.name) as client_name,
        s.name as service_name,
        c.value as total_value,
        CASE 
          WHEN c.private_patient_id IS NOT NULL THEN 0.00
          ELSE ROUND((c.value * (100 - $3) / 100), 2)
        END as amount_to_pay
      FROM consultations c
      LEFT JOIN users cl ON c.client_id = cl.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN services s ON c.service_id = s.id
      WHERE c.professional_id = $1
        AND c.date >= $2::date
        AND c.date <= $4::date
      ORDER BY c.date DESC
    `;

    const consultationsResult = await pool.query(consultationsQuery, [
      professionalId,
      start_date,
      professionalPercentage,
      end_date
    ]);

    console.log('📊 Found consultations:', consultationsResult.rows.length);

    // Calculate summary with proper numeric handling
    const consultations = consultationsResult.rows;
    
    const summary = {
      professional_percentage: professionalPercentage,
      total_revenue: consultations.reduce((sum, c) => sum + parseFloat(c.total_value || 0), 0),
      consultation_count: consultations.length,
      amount_to_pay: consultations.reduce((sum, c) => sum + parseFloat(c.amount_to_pay || 0), 0)
    };

    // Format consultations data properly
    const formattedConsultations = consultations.map(c => ({
      date: c.date,
      client_name: c.client_name || 'N/A',
      service_name: c.service_name || 'N/A',
      total_value: parseFloat(c.total_value || 0),
      amount_to_pay: parseFloat(c.amount_to_pay || 0)
    }));

    const reportData = {
      summary,
      consultations: formattedConsultations
    };

    console.log('✅ Professional revenue report generated:', {
      consultationCount: summary.consultation_count,
      totalRevenue: summary.total_revenue,
      amountToPay: summary.amount_to_pay
    });

    res.json(reportData);
  } catch (error) {
    console.error('❌ Error generating professional revenue report:', error);
    res.status(500).json({ 
      message: 'Erro interno do servidor ao gerar relatório',
      error: error.message 
    });
  }
});

// Detailed professional report
app.get('/api/reports/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    const professionalId = req.user.id;

    console.log('🔄 Generating detailed professional report for:', {
      professionalId,
      start_date,
      end_date
    });

    // Validate dates
    if (!start_date || !end_date) {
      return res.status(400).json({ 
        message: 'start_date e end_date são obrigatórios' 
      });
    }

    // Get professional percentage
    const professionalQuery = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [professionalId]
    );

    if (professionalQuery.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professionalPercentage = professionalQuery.rows[0].percentage || 50;

    // Get detailed consultation breakdown
    const detailedQuery = `
      SELECT 
        COUNT(CASE WHEN c.private_patient_id IS NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        COUNT(*) as total_consultations,
        COALESCE(SUM(CASE WHEN c.private_patient_id IS NULL THEN c.value ELSE 0 END), 0) as convenio_revenue,
        COALESCE(SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END), 0) as private_revenue,
        COALESCE(SUM(c.value), 0) as total_revenue,
        COALESCE(SUM(CASE 
          WHEN c.private_patient_id IS NOT NULL THEN 0
          ELSE ROUND((c.value * (100 - $3) / 100), 2)
        END), 0) as amount_to_pay
      FROM consultations c
      WHERE c.professional_id = $1
        AND c.date >= $2::date
        AND c.date <= $4::date
    `;

    const detailedResult = await pool.query(detailedQuery, [
      professionalId,
      start_date,
      professionalPercentage,
      end_date
    ]);

    const row = detailedResult.rows[0];

    const summary = {
      total_consultations: parseInt(row.total_consultations) || 0,
      convenio_consultations: parseInt(row.convenio_consultations) || 0,
      private_consultations: parseInt(row.private_consultations) || 0,
      total_revenue: parseFloat(row.total_revenue) || 0,
      convenio_revenue: parseFloat(row.convenio_revenue) || 0,
      private_revenue: parseFloat(row.private_revenue) || 0,
      professional_percentage: professionalPercentage,
      amount_to_pay: parseFloat(row.amount_to_pay) || 0
    };

    console.log('✅ Detailed professional report generated:', summary);

    res.json({ summary });
  } catch (error) {
    console.error('❌ Error generating detailed professional report:', error);
    res.status(500).json({ 
      message: 'Erro interno do servidor ao gerar relatório detalhado',
      error: error.message 
    });
  }
});

// Revenue report for admin
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    console.log('🔄 Generating admin revenue report for period:', { start_date, end_date });

    // Validate dates
    if (!start_date || !end_date) {
      return res.status(400).json({ 
        message: 'start_date e end_date são obrigatórios' 
      });
    }

    // Revenue by professional with proper numeric handling
    const professionalRevenueQuery = `
      SELECT 
        u.name as professional_name,
        u.percentage as professional_percentage,
        COALESCE(SUM(c.value), 0) as revenue,
        COUNT(c.id) as consultation_count,
        COALESCE(SUM(ROUND((c.value * u.percentage / 100), 2)), 0) as professional_payment,
        COALESCE(SUM(ROUND((c.value * (100 - u.percentage) / 100), 2)), 0) as clinic_revenue
      FROM users u
      LEFT JOIN consultations c ON u.id = c.professional_id 
        AND c.date >= $1::date 
        AND c.date <= $2::date
        AND c.private_patient_id IS NULL
      WHERE u.roles @> '["professional"]'
      GROUP BY u.id, u.name, u.percentage
      HAVING COUNT(c.id) > 0
      ORDER BY revenue DESC
    `;

    const professionalRevenueResult = await pool.query(professionalRevenueQuery, [
      start_date,
      end_date
    ]);

    // Revenue by service with proper numeric handling
    const serviceRevenueQuery = `
      SELECT 
        s.name as service_name,
        COALESCE(SUM(c.value), 0) as revenue,
        COUNT(c.id) as consultation_count
      FROM services s
      LEFT JOIN consultations c ON s.id = c.service_id 
        AND c.date >= $1::date 
        AND c.date <= $2::date
      GROUP BY s.id, s.name
      HAVING COUNT(c.id) > 0
      ORDER BY revenue DESC
    `;

    const serviceRevenueResult = await pool.query(serviceRevenueQuery, [
      start_date,
      end_date
    ]);

    // Calculate total revenue properly
    const totalRevenueQuery = `
      SELECT COALESCE(SUM(value), 0) as total_revenue
      FROM consultations
      WHERE date >= $1::date AND date <= $2::date
    `;

    const totalRevenueResult = await pool.query(totalRevenueQuery, [
      start_date,
      end_date
    ]);

    // Format the response data
    const revenue_by_professional = professionalRevenueResult.rows.map(row => ({
      professional_name: row.professional_name,
      professional_percentage: parseInt(row.professional_percentage) || 50,
      revenue: parseFloat(row.revenue) || 0,
      consultation_count: parseInt(row.consultation_count) || 0,
      professional_payment: parseFloat(row.professional_payment) || 0,
      clinic_revenue: parseFloat(row.clinic_revenue) || 0
    }));

    const revenue_by_service = serviceRevenueResult.rows.map(row => ({
      service_name: row.service_name,
      revenue: parseFloat(row.revenue) || 0,
      consultation_count: parseInt(row.consultation_count) || 0
    }));

    const reportData = {
      total_revenue: parseFloat(totalRevenueResult.rows[0].total_revenue) || 0,
      revenue_by_professional,
      revenue_by_service
    };

    console.log('✅ Admin revenue report generated:', {
      totalRevenue: reportData.total_revenue,
      professionalCount: revenue_by_professional.length,
      serviceCount: revenue_by_service.length
    });

    res.json(reportData);
  } catch (error) {
    console.error('❌ Error generating revenue report:', error);
    res.status(500).json({ 
      message: 'Erro interno do servidor ao gerar relatório',
      error: error.message 
    });
  }
});

// Clients by city report
app.get('/api/reports/clients-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    console.log('🔄 Generating clients by city report');

    const query = `
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
    `;

    const result = await pool.query(query);

    console.log('✅ Clients by city report generated:', result.rows.length, 'cities');

    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error generating clients by city report:', error);
    res.status(500).json({ 
      message: 'Erro interno do servidor',
      error: error.message 
    });
  }
});

// Professionals by city report
app.get('/api/reports/professionals-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    console.log('🔄 Generating professionals by city report');

    const query = `
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
    `;

    const result = await pool.query(query);

    // Process the categories to group by category name
    const processedResult = result.rows.map(row => {
      const categoryMap = new Map();
      
      if (row.categories) {
        row.categories.forEach((cat) => {
          const name = cat.category_name;
          if (categoryMap.has(name)) {
            categoryMap.set(name, categoryMap.get(name) + cat.count);
          } else {
            categoryMap.set(name, cat.count);
          }
        });
      }

      return {
        city: row.city,
        state: row.state,
        total_professionals: parseInt(row.total_professionals),
        categories: Array.from(categoryMap.entries()).map(([category_name, count]) => ({
          category_name,
          count
        }))
      };
    });

    console.log('✅ Professionals by city report generated:', processedResult.length, 'cities');

    res.json(processedResult);
  } catch (error) {
    console.error('❌ Error generating professionals by city report:', error);
    res.status(500).json({ 
      message: 'Erro interno do servidor',
      error: error.message 
    });
  }
});

// ==================== PAYMENT ROUTES ====================

// Create subscription payment
app.post('/api/create-subscription', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { user_id, dependent_ids } = req.body;
    
    // Calculate amount: R$250 for titular + R$50 per dependent
    const dependentCount = dependent_ids ? dependent_ids.length : 0;
    const amount = 250 + (dependentCount * 50);

    console.log('🔄 Creating subscription payment:', { user_id, amount, dependentCount });

    // Here you would integrate with MercadoPago
    // For now, return a mock response
    const mockPreference = {
      id: `subscription_${Date.now()}`,
      init_point: `https://www.mercadopago.com.br/checkout/v1/redirect?pref_id=subscription_${Date.now()}`,
      sandbox_init_point: `https://sandbox.mercadopago.com.br/checkout/v1/redirect?pref_id=subscription_${Date.now()}`
    };

    res.json(mockPreference);
  } catch (error) {
    console.error('❌ Error creating subscription payment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create professional payment
app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor deve ser maior que zero' });
    }

    console.log('🔄 Creating professional payment:', { amount, professional: req.user.name });

    // Here you would integrate with MercadoPago
    // For now, return a mock response
    const mockPreference = {
      id: `professional_payment_${Date.now()}`,
      init_point: `https://www.mercadopago.com.br/checkout/v1/redirect?pref_id=professional_payment_${Date.now()}`,
      sandbox_init_point: `https://sandbox.mercadopago.com.br/checkout/v1/redirect?pref_id=professional_payment_${Date.now()}`
    };

    res.json(mockPreference);
  } catch (error) {
    console.error('❌ Error creating professional payment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== STATIC FILES & CATCH-ALL ====================

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