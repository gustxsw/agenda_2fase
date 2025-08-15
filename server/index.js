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

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:3000',
      'http://localhost:3001',
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

// Serve static files
app.use(express.static('dist'));

// MercadoPago configuration
let mercadopago;
try {
  if (process.env.MP_ACCESS_TOKEN) {
    mercadopago = new MercadoPagoConfig({
      accessToken: process.env.MP_ACCESS_TOKEN,
      options: { timeout: 5000 }
    });
    console.log('✅ MercadoPago configured successfully');
  } else {
    console.warn('⚠️ MercadoPago access token not found');
  }
} catch (error) {
  console.error('❌ Error configuring MercadoPago:', error);
}

// Initialize upload middleware
let upload;
try {
  upload = createUpload();
  console.log('✅ Upload middleware initialized');
} catch (error) {
  console.error('❌ Error initializing upload middleware:', error);
}

// ==================== AUTHENTICATION ROUTES ====================

// Login route
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return res.status(400).json({ message: 'CPF e senha são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    const result = await pool.query(
      'SELECT id, name, cpf, password_hash, roles FROM users WHERE cpf = $1',
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

    const userData = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles || []
    };

    res.json({ user: userData });
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

    const userData = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles,
      currentRole: role
    };

    res.json({ user: userData, token });
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

    const userData = {
      id: req.user.id,
      name: req.user.name,
      cpf: req.user.cpf,
      roles: req.user.roles,
      currentRole: role
    };

    res.json({ user: userData, token });
  } catch (error) {
    console.error('Role switch error:', error);
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
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password_hash, roles,
        subscription_status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW()) 
      RETURNING id, name, cpf, roles`,
      [
        name,
        cleanCpf,
        email || null,
        phone || null,
        birth_date || null,
        address || null,
        address_number || null,
        address_complement || null,
        neighborhood || null,
        city || null,
        state || null,
        hashedPassword,
        ['client'],
        'pending'
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
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Logout route
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

// ==================== USER MANAGEMENT ROUTES ====================

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

    if (req.user.currentRole !== 'admin' && req.user.id !== parseInt(id)) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.cpf, u.email, u.phone, u.birth_date,
        u.address, u.address_number, u.address_complement, 
        u.neighborhood, u.city, u.state, u.roles, u.percentage,
        u.category_id, u.subscription_status, u.subscription_expiry,
        u.created_at, u.photo_url, sc.name as category_name
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

    if (!name || !cpf || !password || !roles || roles.length === 0) {
      return res.status(400).json({ message: 'Nome, CPF, senha e pelo menos uma role são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cleanCpf]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    if (roles.includes('professional') && !category_id) {
      return res.status(400).json({ message: 'Categoria é obrigatória para profissionais' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password_hash, roles,
        percentage, category_id, subscription_status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW())
      RETURNING id, name, cpf, roles`,
      [
        name, cleanCpf, email || null, phone || null, birth_date || null,
        address || null, address_number || null, address_complement || null,
        neighborhood || null, city || null, state || null, hashedPassword,
        roles, percentage || null, category_id || null,
        roles.includes('client') ? 'pending' : null
      ]
    );

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      user: result.rows[0]
    });
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
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, roles,
      percentage, category_id, currentPassword, newPassword
    } = req.body;

    if (req.user.currentRole !== 'admin' && req.user.id !== parseInt(id)) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    let updateFields = [];
    let updateValues = [];
    let paramCount = 1;

    if (name !== undefined) {
      updateFields.push(`name = $${paramCount}`);
      updateValues.push(name);
      paramCount++;
    }

    if (email !== undefined) {
      updateFields.push(`email = $${paramCount}`);
      updateValues.push(email || null);
      paramCount++;
    }

    if (phone !== undefined) {
      updateFields.push(`phone = $${paramCount}`);
      updateValues.push(phone || null);
      paramCount++;
    }

    if (birth_date !== undefined) {
      updateFields.push(`birth_date = $${paramCount}`);
      updateValues.push(birth_date || null);
      paramCount++;
    }

    if (address !== undefined) {
      updateFields.push(`address = $${paramCount}`);
      updateValues.push(address || null);
      paramCount++;
    }

    if (address_number !== undefined) {
      updateFields.push(`address_number = $${paramCount}`);
      updateValues.push(address_number || null);
      paramCount++;
    }

    if (address_complement !== undefined) {
      updateFields.push(`address_complement = $${paramCount}`);
      updateValues.push(address_complement || null);
      paramCount++;
    }

    if (neighborhood !== undefined) {
      updateFields.push(`neighborhood = $${paramCount}`);
      updateValues.push(neighborhood || null);
      paramCount++;
    }

    if (city !== undefined) {
      updateFields.push(`city = $${paramCount}`);
      updateValues.push(city || null);
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

      if (percentage !== undefined) {
        updateFields.push(`percentage = $${paramCount}`);
        updateValues.push(percentage || null);
        paramCount++;
      }

      if (category_id !== undefined) {
        updateFields.push(`category_id = $${paramCount}`);
        updateValues.push(category_id || null);
        paramCount++;
      }
    }

    // Handle password change
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: 'Senha atual é obrigatória' });
      }

      const userResult = await pool.query('SELECT password_hash FROM users WHERE id = $1', [id]);
      if (userResult.rows.length === 0) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
      }

      const isValidPassword = await bcrypt.compare(currentPassword, userResult.rows[0].password_hash);
      if (!isValidPassword) {
        return res.status(400).json({ message: 'Senha atual incorreta' });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      updateFields.push(`password_hash = $${paramCount}`);
      updateValues.push(hashedPassword);
      paramCount++;
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ message: 'Nenhum campo para atualizar' });
    }

    updateFields.push(`updated_at = NOW()`);
    updateValues.push(id);

    const query = `UPDATE users SET ${updateFields.join(', ')} WHERE id = $${paramCount} RETURNING id, name, cpf, roles`;

    const result = await pool.query(query, updateValues);

    res.json({
      message: 'Usuário atualizado com sucesso',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
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

    res.json({ message: 'Usuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting user:', error);
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
      `UPDATE users 
       SET subscription_status = 'active', subscription_expiry = $1, updated_at = NOW()
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

// ==================== SERVICE CATEGORIES ROUTES ====================

// Get all service categories
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, description, created_at FROM service_categories ORDER BY name'
    );
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

    const result = await pool.query(
      'INSERT INTO service_categories (name, description, created_at) VALUES ($1, $2, NOW()) RETURNING *',
      [name, description]
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

// ==================== SERVICES ROUTES ====================

// Get all services
app.get('/api/services', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.id, s.name, s.description, s.base_price, s.category_id, 
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

    const result = await pool.query(
      `INSERT INTO services (name, description, base_price, category_id, is_base_service, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *`,
      [name, description, base_price, category_id || null, is_base_service || false]
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
      `UPDATE services 
       SET name = $1, description = $2, base_price = $3, category_id = $4, 
           is_base_service = $5, updated_at = NOW()
       WHERE id = $6 RETURNING *`,
      [name, description, base_price, category_id || null, is_base_service || false, id]
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

    const result = await pool.query('DELETE FROM services WHERE id = $1 RETURNING id', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    res.json({ message: 'Serviço excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== CONSULTATIONS ROUTES ====================

// Get consultations
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query = `
      SELECT 
        c.id, c.date, c.value, c.status, c.notes, c.created_at,
        COALESCE(u.name, d.name, pp.name) as client_name,
        s.name as service_name,
        prof.name as professional_name,
        CASE 
          WHEN c.dependent_id IS NOT NULL THEN true 
          ELSE false 
        END as is_dependent,
        c.client_id, c.dependent_id, c.private_patient_id, c.professional_id, c.service_id
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users prof ON c.professional_id = prof.id
    `;

    const params = [];

    if (req.user.currentRole === 'client') {
      query += ` WHERE (c.client_id = $1 OR c.dependent_id IN (
        SELECT id FROM dependents WHERE client_id = $1
      ))`;
      params.push(req.user.id);
    } else if (req.user.currentRole === 'professional') {
      query += ` WHERE c.professional_id = $1`;
      params.push(req.user.id);
    }

    query += ` ORDER BY c.date DESC`;

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching consultations:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create consultation
app.post('/api/consultations', authenticate, authorize(['professional', 'admin']), async (req, res) => {
  try {
    const {
      client_id, dependent_id, private_patient_id, service_id,
      location_id, value, date, status, notes
    } = req.body;

    if (!service_id || !value || !date) {
      return res.status(400).json({ message: 'Serviço, valor e data são obrigatórios' });
    }

    if (!client_id && !dependent_id && !private_patient_id) {
      return res.status(400).json({ message: 'É necessário especificar um cliente, dependente ou paciente particular' });
    }

    const professional_id = req.user.currentRole === 'admin' ? req.body.professional_id : req.user.id;

    const result = await pool.query(
      `INSERT INTO consultations (
        client_id, dependent_id, private_patient_id, professional_id, 
        service_id, location_id, value, date, status, notes, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW()) 
      RETURNING *`,
      [
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
app.put('/api/consultations/:id/status', authenticate, authorize(['professional', 'admin']), async (req, res) => {
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

    let whereClause = 'WHERE id = $1';
    const params = [id];

    if (req.user.currentRole === 'professional') {
      whereClause += ' AND professional_id = $2';
      params.push(req.user.id);
    }

    const result = await pool.query(
      `UPDATE consultations SET status = $${params.length + 1}, updated_at = NOW() ${whereClause} RETURNING *`,
      [...params, status]
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

// ==================== DEPENDENTS ROUTES ====================

// Get dependents for a client
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;

    if (req.user.currentRole === 'client' && req.user.id !== parseInt(clientId)) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    const result = await pool.query(
      'SELECT id, name, cpf, birth_date, created_at FROM dependents WHERE client_id = $1 ORDER BY name',
      [clientId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching dependents:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Lookup dependent by CPF
app.get('/api/dependents/lookup', authenticate, authorize(['professional', 'admin']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    const result = await pool.query(`
      SELECT 
        d.id, d.name, d.cpf, d.birth_date,
        d.client_id, u.name as client_name, u.subscription_status as client_subscription_status
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
app.post('/api/dependents', authenticate, async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    if (!client_id || !name || !cpf) {
      return res.status(400).json({ message: 'ID do cliente, nome e CPF são obrigatórios' });
    }

    if (req.user.currentRole === 'client' && req.user.id !== parseInt(client_id)) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
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

    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado como usuário' });
    }

    const result = await pool.query(
      'INSERT INTO dependents (client_id, name, cpf, birth_date, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING *',
      [client_id, name, cleanCpf, birth_date || null]
    );

    res.status(201).json({
      message: 'Dependente criado com sucesso',
      dependent: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update dependent
app.put('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    let whereClause = 'WHERE id = $1';
    const params = [id];

    if (req.user.currentRole === 'client') {
      whereClause += ' AND client_id = $2';
      params.push(req.user.id);
    }

    const result = await pool.query(
      `UPDATE dependents SET name = $${params.length + 1}, birth_date = $${params.length + 2}, updated_at = NOW() ${whereClause} RETURNING *`,
      [...params, name, birth_date || null]
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

    let whereClause = 'WHERE id = $1';
    const params = [id];

    if (req.user.currentRole === 'client') {
      whereClause += ' AND client_id = $2';
      params.push(req.user.id);
    }

    const result = await pool.query(`DELETE FROM dependents ${whereClause} RETURNING id`, params);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json({ message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== PRIVATE PATIENTS ROUTES ====================

// Get private patients for professional
app.get('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, cpf, email, phone, birth_date, address, address_number,
              address_complement, neighborhood, city, state, zip_code, created_at
       FROM private_patients 
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

// Create private patient
app.post('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    // Only name is required
    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    // Validate CPF format only if provided
    if (cpf && !/^\d{11}$/.test(cpf.replace(/\D/g, ''))) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    // Check for duplicate CPF only if CPF is provided
    if (cpf) {
      const cleanCpf = cpf.replace(/\D/g, '');
      const existingPatient = await pool.query(
        'SELECT id FROM private_patients WHERE cpf = $1 AND professional_id = $2',
        [cleanCpf, req.user.id]
      );

      if (existingPatient.rows.length > 0) {
        return res.status(400).json({ message: 'CPF já cadastrado para este profissional' });
      }
    }

    const result = await pool.query(
      `INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date, address,
        address_number, address_complement, neighborhood, city, state, zip_code, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW()) 
      RETURNING *`,
      [
        req.user.id,
        name,
        cpf ? cpf.replace(/\D/g, '') : null,
        email || null,
        phone || null,
        birth_date || null,
        address || null,
        address_number || null,
        address_complement || null,
        neighborhood || null,
        city || null,
        state || null,
        zip_code || null
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
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    const result = await pool.query(
      `UPDATE private_patients 
       SET name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
           address_number = $6, address_complement = $7, neighborhood = $8,
           city = $9, state = $10, zip_code = $11, updated_at = NOW()
       WHERE id = $12 AND professional_id = $13 
       RETURNING *`,
      [
        name, email || null, phone || null, birth_date || null, address || null,
        address_number || null, address_complement || null, neighborhood || null,
        city || null, state || null, zip_code || null, id, req.user.id
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

// ==================== MEDICAL RECORDS ROUTES ====================

// Get medical records for professional
app.get('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT mr.*, pp.name as patient_name
       FROM medical_records mr
       JOIN private_patients pp ON mr.private_patient_id = pp.id
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

    const result = await pool.query(
      `INSERT INTO medical_records (
        professional_id, private_patient_id, chief_complaint, history_present_illness,
        past_medical_history, medications, allergies, physical_examination,
        diagnosis, treatment_plan, notes, vital_signs, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW()) 
      RETURNING *`,
      [
        req.user.id, private_patient_id, chief_complaint || null,
        history_present_illness || null, past_medical_history || null,
        medications || null, allergies || null, physical_examination || null,
        diagnosis || null, treatment_plan || null, notes || null,
        vital_signs || null
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
      chief_complaint, history_present_illness, past_medical_history,
      medications, allergies, physical_examination, diagnosis,
      treatment_plan, notes, vital_signs
    } = req.body;

    const result = await pool.query(
      `UPDATE medical_records 
       SET chief_complaint = $1, history_present_illness = $2, past_medical_history = $3,
           medications = $4, allergies = $5, physical_examination = $6,
           diagnosis = $7, treatment_plan = $8, notes = $9, vital_signs = $10,
           updated_at = NOW()
       WHERE id = $11 AND professional_id = $12 
       RETURNING *`,
      [
        chief_complaint || null, history_present_illness || null,
        past_medical_history || null, medications || null, allergies || null,
        physical_examination || null, diagnosis || null, treatment_plan || null,
        notes || null, vital_signs || null, id, req.user.id
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

    const result = await pool.query(
      `INSERT INTO medical_documents (
        professional_id, private_patient_id, title, document_type, 
        document_url, created_at
      ) VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *`,
      [
        req.user.id,
        null,
        `Prontuário - ${template_data.patientName}`,
        'medical_record',
        documentResult.url
      ]
    );

    res.json({
      message: 'Prontuário gerado com sucesso',
      document: result.rows[0],
      documentUrl: documentResult.url
    });
  } catch (error) {
    console.error('Error generating medical record document:', error);
    res.status(500).json({ message: 'Erro ao gerar prontuário' });
  }
});

// ==================== MEDICAL DOCUMENTS ROUTES ====================

// Get medical documents for professional
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT md.*, 
              COALESCE(pp.name, 'Paciente não identificado') as patient_name
       FROM medical_documents md
       LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
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
    const { title, document_type, private_patient_id, template_data } = req.body;

    if (!title || !document_type || !template_data) {
      return res.status(400).json({ message: 'Título, tipo de documento e dados do template são obrigatórios' });
    }

    const documentResult = await generateDocumentPDF(document_type, template_data);

    const result = await pool.query(
      `INSERT INTO medical_documents (
        professional_id, private_patient_id, title, document_type, 
        document_url, created_at
      ) VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *`,
      [req.user.id, private_patient_id || null, title, document_type, documentResult.url]
    );

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
    const result = await pool.query(
      `SELECT id, name, address, address_number, address_complement,
              neighborhood, city, state, zip_code, phone, is_default, created_at
       FROM attendance_locations 
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

    const result = await pool.query(
      `INSERT INTO attendance_locations (
        professional_id, name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW()) 
      RETURNING *`,
      [
        req.user.id, name, address || null, address_number || null,
        address_complement || null, neighborhood || null, city || null,
        state || null, zip_code || null, phone || null, is_default || false
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
      name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome do local é obrigatório' });
    }

    // If setting as default, remove default from other locations
    if (is_default) {
      await pool.query(
        'UPDATE attendance_locations SET is_default = false WHERE professional_id = $1 AND id != $2',
        [req.user.id, id]
      );
    }

    const result = await pool.query(
      `UPDATE attendance_locations 
       SET name = $1, address = $2, address_number = $3, address_complement = $4,
           neighborhood = $5, city = $6, state = $7, zip_code = $8, phone = $9,
           is_default = $10, updated_at = NOW()
       WHERE id = $11 AND professional_id = $12 
       RETURNING *`,
      [
        name, address || null, address_number || null, address_complement || null,
        neighborhood || null, city || null, state || null, zip_code || null,
        phone || null, is_default || false, id, req.user.id
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

// ==================== CLIENT LOOKUP ROUTES ====================

// Lookup client by CPF
app.get('/api/clients/lookup', authenticate, authorize(['professional', 'admin']), async (req, res) => {
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
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== PROFESSIONALS ROUTES ====================

// Get professionals for clients
app.get('/api/professionals', authenticate, authorize(['client', 'admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone, u.roles, u.address, u.address_number,
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

// Get professionals with scheduling access (admin only)
app.get('/api/admin/professionals-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone, sc.name as category_name,
        u.has_scheduling_access, u.access_expires_at, u.access_granted_by, u.access_granted_at
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

    if (!professional_id || !expires_at) {
      return res.status(400).json({ message: 'ID do profissional e data de expiração são obrigatórios' });
    }

    const result = await pool.query(
      `UPDATE users 
       SET has_scheduling_access = true, access_expires_at = $1, 
           access_granted_by = $2, access_granted_at = NOW(), updated_at = NOW()
       WHERE id = $3 AND 'professional' = ANY(roles)
       RETURNING id, name, has_scheduling_access, access_expires_at`,
      [expires_at, req.user.name, professional_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    res.json({
      message: 'Acesso à agenda concedido com sucesso',
      professional: result.rows[0]
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

    const result = await pool.query(
      `UPDATE users 
       SET has_scheduling_access = false, access_expires_at = NULL, 
           access_granted_by = NULL, access_granted_at = NULL, updated_at = NOW()
       WHERE id = $1 AND 'professional' = ANY(roles)
       RETURNING id, name, has_scheduling_access`,
      [professional_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    res.json({
      message: 'Acesso à agenda revogado com sucesso',
      professional: result.rows[0]
    });
  } catch (error) {
    console.error('Error revoking scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== REPORTS ROUTES ====================

// Revenue report (admin only)
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    // Revenue by professional
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
        AND c.client_id IS NOT NULL
        AND c.status = 'completed'
      GROUP BY u.id, u.name, u.percentage
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    // Revenue by service
    const serviceRevenueResult = await pool.query(`
      SELECT 
        s.name as service_name,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      WHERE c.date >= $1 AND c.date <= $2 
        AND c.client_id IS NOT NULL
        AND c.status = 'completed'
      GROUP BY s.id, s.name
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    // Total revenue
    const totalRevenueResult = await pool.query(`
      SELECT SUM(c.value) as total_revenue
      FROM consultations c
      WHERE c.date >= $1 AND c.date <= $2 
        AND c.client_id IS NOT NULL
        AND c.status = 'completed'
    `, [start_date, end_date]);

    res.json({
      total_revenue: parseFloat(totalRevenueResult.rows[0].total_revenue || 0),
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
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = professionalResult.rows[0]?.percentage || 50;

    // Get consultations summary
    const summaryResult = await pool.query(`
      SELECT 
        SUM(c.value) as total_revenue,
        COUNT(c.id) as consultation_count,
        SUM(c.value * ((100 - $3) / 100.0)) as amount_to_pay
      FROM consultations c
      WHERE c.professional_id = $1 
        AND c.date >= $2 AND c.date <= $4
        AND c.client_id IS NOT NULL
        AND c.status = 'completed'
    `, [req.user.id, start_date, professionalPercentage, end_date]);

    // Get detailed consultations
    const consultationsResult = await pool.query(`
      SELECT 
        c.date,
        COALESCE(u.name, d.name) as client_name,
        s.name as service_name,
        c.value as total_value,
        c.value * ((100 - $3) / 100.0) as amount_to_pay
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      JOIN services s ON c.service_id = s.id
      WHERE c.professional_id = $1 
        AND c.date >= $2 AND c.date <= $4
        AND c.client_id IS NOT NULL
        AND c.status = 'completed'
      ORDER BY c.date DESC
    `, [req.user.id, start_date, professionalPercentage, end_date]);

    const summary = summaryResult.rows[0];

    res.json({
      summary: {
        professional_percentage: professionalPercentage,
        total_revenue: parseFloat(summary.total_revenue || 0),
        consultation_count: parseInt(summary.consultation_count || 0),
        amount_to_pay: parseFloat(summary.amount_to_pay || 0)
      },
      consultations: consultationsResult.rows.map(row => ({
        ...row,
        total_value: parseFloat(row.total_value),
        amount_to_pay: parseFloat(row.amount_to_pay)
      }))
    });
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
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = professionalResult.rows[0]?.percentage || 50;

    // Get detailed summary
    const summaryResult = await pool.query(`
      SELECT 
        COUNT(c.id) as total_consultations,
        COUNT(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        SUM(c.value) as total_revenue,
        SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value ELSE 0 END) as convenio_revenue,
        SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END) as private_revenue,
        SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value * ((100 - $3) / 100.0) ELSE 0 END) as amount_to_pay
      FROM consultations c
      WHERE c.professional_id = $1 
        AND c.date >= $2 AND c.date <= $4
        AND c.status = 'completed'
    `, [req.user.id, start_date, professionalPercentage, end_date]);

    const summary = summaryResult.rows[0];

    res.json({
      summary: {
        total_consultations: parseInt(summary.total_consultations || 0),
        convenio_consultations: parseInt(summary.convenio_consultations || 0),
        private_consultations: parseInt(summary.private_consultations || 0),
        total_revenue: parseFloat(summary.total_revenue || 0),
        convenio_revenue: parseFloat(summary.convenio_revenue || 0),
        private_revenue: parseFloat(summary.private_revenue || 0),
        professional_percentage: professionalPercentage,
        amount_to_pay: parseFloat(summary.amount_to_pay || 0)
      }
    });
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
        u.city, u.state,
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
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== PAYMENT ROUTES ====================

// Create subscription payment
app.post('/api/create-subscription', authenticate, authorize(['client']), async (req, res) => {
  try {
    if (!mercadopago) {
      return res.status(500).json({ message: 'MercadoPago não configurado' });
    }

    const { user_id, dependent_ids } = req.body;

    if (req.user.id !== user_id) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
    }

    // Get dependents count
    const dependentsResult = await pool.query(
      'SELECT COUNT(*) as count FROM dependents WHERE client_id = $1',
      [user_id]
    );

    const dependentCount = parseInt(dependentsResult.rows[0].count);
    const totalAmount = 250 + (dependentCount * 50); // R$250 titular + R$50 per dependent

    const preference = new Preference(mercadopago);

    const preferenceData = {
      items: [
        {
          title: 'Assinatura Convênio Quiro Ferreira',
          description: `Titular + ${dependentCount} dependente(s)`,
          quantity: 1,
          currency_id: 'BRL',
          unit_price: totalAmount
        }
      ],
      payer: {
        name: req.user.name,
        email: 'cliente@quiroferreira.com.br'
      },
      back_urls: {
        success: `${req.protocol}://${req.get('host')}/payment/success`,
        failure: `${req.protocol}://${req.get('host')}/payment/failure`,
        pending: `${req.protocol}://${req.get('host')}/payment/pending`
      },
      auto_return: 'approved',
      external_reference: `subscription_${user_id}_${Date.now()}`,
      notification_url: `${req.protocol}://${req.get('host')}/api/payment/webhook`
    };

    const result = await preference.create({ body: preferenceData });

    res.json({
      id: result.id,
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
    if (!mercadopago) {
      return res.status(500).json({ message: 'MercadoPago não configurado' });
    }

    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor inválido' });
    }

    const preference = new Preference(mercadopago);

    const preferenceData = {
      items: [
        {
          title: 'Repasse ao Convênio Quiro Ferreira',
          description: `Pagamento referente às consultas realizadas`,
          quantity: 1,
          currency_id: 'BRL',
          unit_price: amount
        }
      ],
      payer: {
        name: req.user.name,
        email: 'profissional@quiroferreira.com.br'
      },
      back_urls: {
        success: `${req.protocol}://${req.get('host')}/payment/success`,
        failure: `${req.protocol}://${req.get('host')}/payment/failure`,
        pending: `${req.protocol}://${req.get('host')}/payment/pending`
      },
      auto_return: 'approved',
      external_reference: `professional_payment_${req.user.id}_${Date.now()}`,
      notification_url: `${req.protocol}://${req.get('host')}/api/payment/webhook`
    };

    const result = await preference.create({ body: preferenceData });

    res.json({
      id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point
    });
  } catch (error) {
    console.error('Error creating professional payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento' });
  }
});

// Payment webhook
app.post('/api/payment/webhook', async (req, res) => {
  try {
    console.log('Payment webhook received:', req.body);
    
    const { type, data } = req.body;

    if (type === 'payment') {
      const paymentId = data.id;
      
      // Here you would typically:
      // 1. Verify the payment with MercadoPago API
      // 2. Update the user's subscription status
      // 3. Send confirmation email
      
      console.log('Payment processed:', paymentId);
    }

    res.status(200).json({ message: 'Webhook processed' });
  } catch (error) {
    console.error('Error processing webhook:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== IMAGE UPLOAD ROUTES ====================

// Upload image route
app.post('/api/upload-image', authenticate, (req, res) => {
  if (!upload) {
    return res.status(500).json({ message: 'Upload não configurado' });
  }

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
    } catch (error) {
      console.error('Error updating user photo:', error);
      res.status(500).json({ message: 'Erro ao atualizar foto do usuário' });
    }
  });
});

// ==================== PAYMENT SUCCESS/FAILURE ROUTES ====================

// Payment success page
app.get('/payment/success', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Pagamento Aprovado</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f0f8ff; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            .success { color: #28a745; font-size: 24px; margin-bottom: 20px; }
            .btn { background: #c11c22; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="success">✅ Pagamento Aprovado!</div>
            <p>Seu pagamento foi processado com sucesso.</p>
            <p>Você receberá um email de confirmação em breve.</p>
            <a href="/" class="btn">Voltar ao Sistema</a>
        </div>
    </body>
    </html>
  `);
});

// Payment failure page
app.get('/payment/failure', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Pagamento Rejeitado</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #fff5f5; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            .error { color: #dc3545; font-size: 24px; margin-bottom: 20px; }
            .btn { background: #c11c22; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="error">❌ Pagamento Rejeitado</div>
            <p>Houve um problema com seu pagamento.</p>
            <p>Tente novamente ou entre em contato conosco.</p>
            <a href="/" class="btn">Voltar ao Sistema</a>
        </div>
    </body>
    </html>
  `);
});

// Payment pending page
app.get('/payment/pending', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Pagamento Pendente</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #fffbf0; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            .pending { color: #ffc107; font-size: 24px; margin-bottom: 20px; }
            .btn { background: #c11c22; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="pending">⏳ Pagamento Pendente</div>
            <p>Seu pagamento está sendo processado.</p>
            <p>Você receberá uma confirmação quando for aprovado.</p>
            <a href="/" class="btn">Voltar ao Sistema</a>
        </div>
    </body>
    </html>
  `);
});

// ==================== CATCH-ALL ROUTE ====================

// Serve React app for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'dist', 'index.html'));
});

// ==================== ERROR HANDLING ====================

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  res.status(500).json({ message: 'Erro interno do servidor' });
});

// ==================== SERVER START ====================

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Database: ${process.env.DATABASE_URL ? 'Connected' : 'Not configured'}`);
  console.log(`💳 MercadoPago: ${process.env.MP_ACCESS_TOKEN ? 'Configured' : 'Not configured'}`);
  console.log(`☁️ Cloudinary: ${process.env.CLOUDINARY_CLOUD_NAME ? 'Configured' : 'Not configured'}`);
});