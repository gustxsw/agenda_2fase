import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import path from 'path';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { ensureSignatureColumn } from './database/signatureColumn.js';
import createUpload from './middleware/upload.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// CORS configuration
const corsOptions = {
  origin: [
    'http://localhost:5173',
    'http://localhost:3000',
    'https://www.cartaoquiroferreira.com.br',
    'https://cartaoquiroferreira.com.br'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

// Serve static files from dist directory
app.use(express.static('dist'));

// Initialize upload middleware
let upload;
try {
  upload = createUpload();
  console.log('✅ Upload middleware initialized successfully');
} catch (error) {
  console.error('❌ Failed to initialize upload middleware:', error);
}

// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Error acquiring client:', err.stack);
  } else {
    console.log('✅ Database connected successfully');
    release();
  }
});

// Initialize database schema
ensureSignatureColumn().catch(console.error);

// Auth routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;
    console.log('🔄 Login attempt for CPF:', cpf);

    if (!cpf || !password) {
      return res.status(400).json({ message: 'CPF e senha são obrigatórios' });
    }

    const result = await pool.query(
      'SELECT id, name, cpf, password_hash, roles FROM users WHERE cpf = $1',
      [cpf]
    );

    if (result.rows.length === 0) {
      console.log('❌ User not found for CPF:', cpf);
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password_hash);

    if (!isValidPassword) {
      console.log('❌ Invalid password for CPF:', cpf);
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    console.log('✅ Login successful for user:', user.name);
    console.log('🎯 User roles:', user.roles);

    res.json({
      message: 'Login realizado com sucesso',
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

app.post('/api/auth/select-role', async (req, res) => {
  try {
    const { userId, role } = req.body;
    console.log('🎯 Role selection:', { userId, role });

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

    console.log('✅ Role selected successfully:', { userId, role });

    res.json({
      message: 'Role selecionada com sucesso',
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

app.post('/api/auth/switch-role', authenticate, async (req, res) => {
  try {
    const { role } = req.body;
    const userId = req.user.id;

    console.log('🔄 Role switch request:', { userId, role });

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

    console.log('✅ Role switched successfully:', { userId, role });

    res.json({
      message: 'Role alterada com sucesso',
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

    console.log('🔄 Registration attempt for:', { name, cpf });

    if (!name || !cpf || !password) {
      return res.status(400).json({ message: 'Nome, CPF e senha são obrigatórios' });
    }

    if (!/^\d{11}$/.test(cpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'CPF já cadastrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password_hash, roles,
        subscription_status, subscription_expiry
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) 
      RETURNING id, name, cpf, roles`,
      [
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, hashedPassword, ['client'],
        'pending', null
      ]
    );

    const newUser = result.rows[0];
    console.log('✅ User registered successfully:', newUser.name);

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      user: newUser
    });
  } catch (error) {
    console.error('❌ Registration error:', error);
    if (error.code === '23505') {
      res.status(409).json({ message: 'CPF já cadastrado' });
    } else {
      res.status(500).json({ message: 'Erro interno do servidor' });
    }
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

// Upload routes
app.post('/api/upload-image', authenticate, async (req, res) => {
  console.log('🔄 Image upload request received');
  console.log('🔄 User:', req.user?.name);
  console.log('🔄 Files:', req.files);
  console.log('🔄 Body:', req.body);

  if (!upload) {
    console.error('❌ Upload middleware not initialized');
    return res.status(500).json({ message: 'Serviço de upload não disponível' });
  }

  upload.single('image')(req, res, async (err) => {
    if (err) {
      console.error('❌ Upload error:', err);
      return res.status(400).json({ message: err.message || 'Erro no upload da imagem' });
    }

    if (!req.file) {
      console.error('❌ No file received');
      return res.status(400).json({ message: 'Nenhum arquivo foi enviado' });
    }

    try {
      console.log('✅ File uploaded to Cloudinary:', req.file.path);

      // Update user photo_url in database
      await pool.query(
        'UPDATE users SET photo_url = $1 WHERE id = $2',
        [req.file.path, req.user.id]
      );

      console.log('✅ User photo_url updated in database');

      res.json({
        message: 'Imagem enviada com sucesso',
        imageUrl: req.file.path
      });
    } catch (dbError) {
      console.error('❌ Database error:', dbError);
      res.status(500).json({ message: 'Erro ao salvar URL da imagem no banco de dados' });
    }
  });
});

app.post('/api/upload-signature', authenticate, async (req, res) => {
  console.log('🔄 Signature upload request received');
  console.log('🔄 User:', req.user?.name);
  console.log('🔄 Files:', req.files);
  console.log('🔄 Body:', req.body);

  if (!upload) {
    console.error('❌ Upload middleware not initialized');
    return res.status(500).json({ message: 'Serviço de upload não disponível' });
  }

  upload.single('signature')(req, res, async (err) => {
    if (err) {
      console.error('❌ Signature upload error:', err);
      return res.status(400).json({ message: err.message || 'Erro no upload da assinatura' });
    }

    if (!req.file) {
      console.error('❌ No signature file received');
      return res.status(400).json({ message: 'Nenhum arquivo de assinatura foi enviado' });
    }

    try {
      console.log('✅ Signature uploaded to Cloudinary:', req.file.path);

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
      console.error('❌ Database error updating signature:', dbError);
      res.status(500).json({ message: 'Erro ao salvar URL da assinatura no banco de dados' });
    }
  });
});

// Upload signature route
app.post('/api/upload-signature', authenticate, async (req, res) => {
  console.log('🔄 Signature upload request received');
  console.log('🔄 User:', req.user?.name);
  console.log('🔄 Files:', req.files);
  console.log('🔄 Body:', req.body);

  if (!upload) {
    console.error('❌ Upload middleware not initialized');
    return res.status(500).json({ message: 'Serviço de upload não disponível' });
  }

  upload.single('signature')(req, res, async (err) => {
    if (err) {
      console.error('❌ Signature upload error:', err);
      return res.status(400).json({ message: err.message || 'Erro no upload da assinatura' });
    }

    if (!req.file) {
      console.error('❌ No signature file received');
      return res.status(400).json({ message: 'Nenhum arquivo de assinatura foi enviado' });
    }

    try {
      console.log('✅ Signature uploaded to Cloudinary:', req.file.path);

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
      console.error('❌ Database error updating signature:', dbError);
      res.status(500).json({ message: 'Erro ao salvar URL da assinatura no banco de dados' });
    }
  });
});

// User routes
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    console.log('🔄 Fetching all users');
    
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
    
    console.log('✅ Users fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching users:', error);
    res.status(500).json({ message: 'Erro ao buscar usuários' });
  }
});

app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    console.log('🔄 Fetching user by ID:', id);
    
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.cpf, u.email, u.phone, u.birth_date,
        u.address, u.address_number, u.address_complement, 
        u.neighborhood, u.city, u.state, u.roles, u.percentage,
        u.category_id, u.subscription_status, u.subscription_expiry,
        u.created_at, u.photo_url, u.signature_url, sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE u.id = $1
    `, [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    
    console.log('✅ User found:', result.rows[0].name);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error fetching user:', error);
    res.status(500).json({ message: 'Erro ao buscar usuário' });
  }
});

app.post('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, password, roles,
      percentage, category_id
    } = req.body;

    console.log('🔄 Creating user:', { name, cpf, roles });

    if (!name || !cpf || !password || !roles || roles.length === 0) {
      return res.status(400).json({ message: 'Campos obrigatórios: nome, CPF, senha e pelo menos uma role' });
    }

    if (!/^\d{11}$/.test(cpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cpf]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'CPF já cadastrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password_hash, roles,
        percentage, category_id, subscription_status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
      RETURNING id, name, cpf, roles`,
      [
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, hashedPassword, roles,
        percentage, category_id, roles.includes('client') ? 'pending' : null
      ]
    );

    console.log('✅ User created:', result.rows[0].name);
    res.status(201).json({
      message: 'Usuário criado com sucesso',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error creating user:', error);
    res.status(500).json({ message: 'Erro ao criar usuário' });
  }
});

app.put('/api/users/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, roles,
      percentage, category_id
    } = req.body;

    console.log('🔄 Updating user:', id);

    if (!name || !roles || roles.length === 0) {
      return res.status(400).json({ message: 'Nome e pelo menos uma role são obrigatórios' });
    }

    await pool.query(
      `UPDATE users SET 
        name = $1, email = $2, phone = $3, birth_date = $4,
        address = $5, address_number = $6, address_complement = $7,
        neighborhood = $8, city = $9, state = $10, roles = $11,
        percentage = $12, category_id = $13
      WHERE id = $14`,
      [
        name, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, roles,
        percentage, category_id, id
      ]
    );

    console.log('✅ User updated:', id);
    res.json({ message: 'Usuário atualizado com sucesso' });
  } catch (error) {
    console.error('❌ Error updating user:', error);
    res.status(500).json({ message: 'Erro ao atualizar usuário' });
  }
});

app.put('/api/users/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { expiry_date } = req.body;

    console.log('🔄 Activating client:', { id, expiry_date });

    if (!expiry_date) {
      return res.status(400).json({ message: 'Data de expiração é obrigatória' });
    }

    await pool.query(
      'UPDATE users SET subscription_status = $1, subscription_expiry = $2 WHERE id = $3',
      ['active', expiry_date, id]
    );

    console.log('✅ Client activated:', id);
    res.json({ message: 'Cliente ativado com sucesso' });
  } catch (error) {
    console.error('❌ Error activating client:', error);
    res.status(500).json({ message: 'Erro ao ativar cliente' });
  }
});

app.delete('/api/users/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    console.log('🔄 Deleting user:', id);

    await pool.query('DELETE FROM users WHERE id = $1', [id]);

    console.log('✅ User deleted:', id);
    res.json({ message: 'Usuário excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting user:', error);
    res.status(500).json({ message: 'Erro ao excluir usuário' });
  }
});

// Service categories routes
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    console.log('🔄 Fetching service categories');
    
    const result = await pool.query(
      'SELECT id, name, description FROM service_categories ORDER BY name'
    );
    
    console.log('✅ Service categories fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching service categories:', error);
    res.status(500).json({ message: 'Erro ao buscar categorias de serviço' });
  }
});

app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;
    console.log('🔄 Creating service category:', { name });

    if (!name || !description) {
      return res.status(400).json({ message: 'Nome e descrição são obrigatórios' });
    }

    const result = await pool.query(
      'INSERT INTO service_categories (name, description) VALUES ($1, $2) RETURNING *',
      [name, description]
    );

    console.log('✅ Service category created:', result.rows[0].name);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating service category:', error);
    res.status(500).json({ message: 'Erro ao criar categoria de serviço' });
  }
});

// Services routes
app.get('/api/services', authenticate, async (req, res) => {
  try {
    console.log('🔄 Fetching services');
    
    const result = await pool.query(`
      SELECT 
        s.id, s.name, s.description, s.base_price, s.category_id, s.is_base_service,
        sc.name as category_name
      FROM services s
      LEFT JOIN service_categories sc ON s.category_id = sc.id
      ORDER BY sc.name, s.name
    `);
    
    console.log('✅ Services fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching services:', error);
    res.status(500).json({ message: 'Erro ao buscar serviços' });
  }
});

app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;
    console.log('🔄 Creating service:', { name, base_price });

    if (!name || !description || base_price === undefined) {
      return res.status(400).json({ message: 'Nome, descrição e preço base são obrigatórios' });
    }

    const result = await pool.query(
      `INSERT INTO services (name, description, base_price, category_id, is_base_service) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [name, description, base_price, category_id, is_base_service || false]
    );

    console.log('✅ Service created:', result.rows[0].name);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating service:', error);
    res.status(500).json({ message: 'Erro ao criar serviço' });
  }
});

app.put('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, base_price, category_id, is_base_service } = req.body;
    console.log('🔄 Updating service:', id);

    if (!name || !description || base_price === undefined) {
      return res.status(400).json({ message: 'Nome, descrição e preço base são obrigatórios' });
    }

    await pool.query(
      `UPDATE services SET 
        name = $1, description = $2, base_price = $3, 
        category_id = $4, is_base_service = $5
      WHERE id = $6`,
      [name, description, base_price, category_id, is_base_service || false, id]
    );

    console.log('✅ Service updated:', id);
    res.json({ message: 'Serviço atualizado com sucesso' });
  } catch (error) {
    console.error('❌ Error updating service:', error);
    res.status(500).json({ message: 'Erro ao atualizar serviço' });
  }
});

app.delete('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    console.log('🔄 Deleting service:', id);

    await pool.query('DELETE FROM services WHERE id = $1', [id]);

    console.log('✅ Service deleted:', id);
    res.json({ message: 'Serviço excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting service:', error);
    res.status(500).json({ message: 'Erro ao excluir serviço' });
  }
});

// Professionals routes
app.get('/api/professionals', authenticate, async (req, res) => {
  try {
    console.log('🔄 Fetching professionals');
    
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone, u.address, u.address_number,
        u.address_complement, u.neighborhood, u.city, u.state, u.roles,
        u.photo_url, sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE u.roles @> '["professional"]'
      ORDER BY u.name
    `);
    
    console.log('✅ Professionals fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro ao buscar profissionais' });
  }
});

// Consultations routes
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    console.log('🔄 Fetching consultations for user:', req.user.currentRole);
    
    let query = `
      SELECT 
        c.id, c.date, c.value, c.status, c.notes,
        COALESCE(cl.name, d.name, pp.name) as client_name,
        s.name as service_name,
        prof.name as professional_name,
        CASE WHEN d.id IS NOT NULL THEN true ELSE false END as is_dependent
      FROM consultations c
      LEFT JOIN users cl ON c.client_id = cl.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users prof ON c.professional_id = prof.id
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
    res.status(500).json({ message: 'Erro ao buscar consultas' });
  }
});

app.get('/api/consultations/client/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;
    console.log('🔄 Fetching consultations for client:', clientId);
    
    const result = await pool.query(`
      SELECT 
        c.id, c.date, c.value, c.status, c.notes,
        COALESCE(cl.name, d.name, pp.name) as client_name,
        s.name as service_name,
        prof.name as professional_name,
        CASE WHEN d.id IS NOT NULL THEN true ELSE false END as is_dependent
      FROM consultations c
      LEFT JOIN users cl ON c.client_id = cl.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users prof ON c.professional_id = prof.id
      WHERE c.client_id = $1 OR d.client_id = $1
      ORDER BY c.date DESC
    `, [clientId]);
    
    console.log('✅ Client consultations fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching client consultations:', error);
    res.status(500).json({ message: 'Erro ao buscar consultas do cliente' });
  }
});

app.post('/api/consultations', authenticate, async (req, res) => {
  try {
    const {
      client_id, dependent_id, private_patient_id, service_id,
      location_id, value, date, status, notes
    } = req.body;

    console.log('🔄 Creating consultation:', {
      client_id, dependent_id, private_patient_id, service_id, value, date
    });

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
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
      [
        client_id, dependent_id, private_patient_id, req.user.id,
        service_id, location_id, value, date, status || 'completed', notes
      ]
    );

    console.log('✅ Consultation created:', result.rows[0].id);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating consultation:', error);
    res.status(500).json({ message: 'Erro ao criar consulta' });
  }
});

app.put('/api/consultations/:id/status', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    console.log('🔄 Updating consultation status:', { id, status });

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
      return res.status(404).json({ message: 'Consulta não encontrada ou não autorizada' });
    }

    console.log('✅ Consultation status updated:', { id, status });
    res.json({ message: 'Status atualizado com sucesso', consultation: result.rows[0] });
  } catch (error) {
    console.error('❌ Error updating consultation status:', error);
    res.status(500).json({ message: 'Erro ao atualizar status da consulta' });
  }
});

// Client lookup routes
app.get('/api/clients/lookup', authenticate, async (req, res) => {
  try {
    const { cpf } = req.query;
    console.log('🔄 Looking up client by CPF:', cpf);

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const result = await pool.query(
      'SELECT id, name, cpf, subscription_status FROM users WHERE cpf = $1 AND roles @> \'["client"]\'',
      [cpf]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    console.log('✅ Client found:', result.rows[0].name);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error looking up client:', error);
    res.status(500).json({ message: 'Erro ao buscar cliente' });
  }
});

// Dependents routes
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;
    console.log('🔄 Fetching dependents for client:', clientId);
    
    const result = await pool.query(
      'SELECT id, name, cpf, birth_date, created_at FROM dependents WHERE client_id = $1 ORDER BY name',
      [clientId]
    );
    
    console.log('✅ Dependents fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching dependents:', error);
    res.status(500).json({ message: 'Erro ao buscar dependentes' });
  }
});

app.get('/api/dependents/lookup', authenticate, async (req, res) => {
  try {
    const { cpf } = req.query;
    console.log('🔄 Looking up dependent by CPF:', cpf);

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const result = await pool.query(`
      SELECT 
        d.id, d.name, d.cpf, d.birth_date, d.client_id,
        u.name as client_name, u.subscription_status as client_subscription_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      WHERE d.cpf = $1
    `, [cpf]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    console.log('✅ Dependent found:', result.rows[0].name);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error looking up dependent:', error);
    res.status(500).json({ message: 'Erro ao buscar dependente' });
  }
});

app.post('/api/dependents', authenticate, async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;
    console.log('🔄 Creating dependent:', { client_id, name });

    if (!client_id || !name || !cpf) {
      return res.status(400).json({ message: 'ID do cliente, nome e CPF são obrigatórios' });
    }

    if (!/^\d{11}$/.test(cpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    const existingDependent = await pool.query(
      'SELECT id FROM dependents WHERE cpf = $1',
      [cpf]
    );

    if (existingDependent.rows.length > 0) {
      return res.status(409).json({ message: 'CPF já cadastrado como dependente' });
    }

    const result = await pool.query(
      'INSERT INTO dependents (client_id, name, cpf, birth_date) VALUES ($1, $2, $3, $4) RETURNING *',
      [client_id, name, cpf, birth_date]
    );

    console.log('✅ Dependent created:', result.rows[0].name);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating dependent:', error);
    res.status(500).json({ message: 'Erro ao criar dependente' });
  }
});

app.put('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;
    console.log('🔄 Updating dependent:', id);

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    await pool.query(
      'UPDATE dependents SET name = $1, birth_date = $2 WHERE id = $3',
      [name, birth_date, id]
    );

    console.log('✅ Dependent updated:', id);
    res.json({ message: 'Dependente atualizado com sucesso' });
  } catch (error) {
    console.error('❌ Error updating dependent:', error);
    res.status(500).json({ message: 'Erro ao atualizar dependente' });
  }
});

app.delete('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    console.log('🔄 Deleting dependent:', id);

    await pool.query('DELETE FROM dependents WHERE id = $1', [id]);

    console.log('✅ Dependent deleted:', id);
    res.json({ message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting dependent:', error);
    res.status(500).json({ message: 'Erro ao excluir dependente' });
  }
});

// Private patients routes
app.get('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    console.log('🔄 Fetching private patients for professional:', req.user.id);
    
    const result = await pool.query(`
      SELECT id, name, cpf, email, phone, birth_date, address, address_number,
             address_complement, neighborhood, city, state, zip_code, created_at
      FROM private_patients 
      WHERE professional_id = $1 
      ORDER BY name
    `, [req.user.id]);
    
    console.log('✅ Private patients fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching private patients:', error);
    res.status(500).json({ message: 'Erro ao buscar pacientes particulares' });
  }
});

app.post('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    console.log('🔄 Creating private patient:', { name, cpf });

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    if (cpf && !/^\d{11}$/.test(cpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    if (cpf) {
      const existingPatient = await pool.query(
        'SELECT id FROM private_patients WHERE cpf = $1 AND professional_id = $2',
        [cpf, req.user.id]
      );

      if (existingPatient.rows.length > 0) {
        return res.status(409).json({ message: 'CPF já cadastrado para este profissional' });
      }
    }

    const result = await pool.query(
      `INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date,
        address, address_number, address_complement, neighborhood, city, state, zip_code
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *`,
      [
        req.user.id, name, cpf, email, phone, birth_date,
        address, address_number, address_complement, neighborhood, city, state, zip_code
      ]
    );

    console.log('✅ Private patient created:', result.rows[0].name);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating private patient:', error);
    res.status(500).json({ message: 'Erro ao criar paciente particular' });
  }
});

app.put('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    console.log('🔄 Updating private patient:', id);

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    await pool.query(
      `UPDATE private_patients SET 
        name = $1, email = $2, phone = $3, birth_date = $4,
        address = $5, address_number = $6, address_complement = $7,
        neighborhood = $8, city = $9, state = $10, zip_code = $11
      WHERE id = $12 AND professional_id = $13`,
      [
        name, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, zip_code, id, req.user.id
      ]
    );

    console.log('✅ Private patient updated:', id);
    res.json({ message: 'Paciente particular atualizado com sucesso' });
  } catch (error) {
    console.error('❌ Error updating private patient:', error);
    res.status(500).json({ message: 'Erro ao atualizar paciente particular' });
  }
});

app.delete('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    console.log('🔄 Deleting private patient:', id);

    await pool.query(
      'DELETE FROM private_patients WHERE id = $1 AND professional_id = $2',
      [id, req.user.id]
    );

    console.log('✅ Private patient deleted:', id);
    res.json({ message: 'Paciente particular excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting private patient:', error);
    res.status(500).json({ message: 'Erro ao excluir paciente particular' });
  }
});

// Medical records routes
app.get('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    console.log('🔄 Fetching medical records for professional:', req.user.id);
    
    const result = await pool.query(`
      SELECT 
        mr.id, mr.chief_complaint, mr.history_present_illness, mr.past_medical_history,
        mr.medications, mr.allergies, mr.physical_examination, mr.diagnosis,
        mr.treatment_plan, mr.notes, mr.vital_signs, mr.created_at, mr.updated_at,
        pp.name as patient_name
      FROM medical_records mr
      JOIN private_patients pp ON mr.private_patient_id = pp.id
      WHERE pp.professional_id = $1
      ORDER BY mr.created_at DESC
    `, [req.user.id]);
    
    console.log('✅ Medical records fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching medical records:', error);
    res.status(500).json({ message: 'Erro ao buscar prontuários' });
  }
});

app.post('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      private_patient_id, chief_complaint, history_present_illness,
      past_medical_history, medications, allergies, physical_examination,
      diagnosis, treatment_plan, notes, vital_signs
    } = req.body;

    console.log('🔄 Creating medical record for patient:', private_patient_id);

    if (!private_patient_id) {
      return res.status(400).json({ message: 'ID do paciente é obrigatório' });
    }

    // Verify patient belongs to this professional
    const patientCheck = await pool.query(
      'SELECT id FROM private_patients WHERE id = $1 AND professional_id = $2',
      [private_patient_id, req.user.id]
    );

    if (patientCheck.rows.length === 0) {
      return res.status(403).json({ message: 'Paciente não encontrado ou não autorizado' });
    }

    const result = await pool.query(
      `INSERT INTO medical_records (
        private_patient_id, chief_complaint, history_present_illness,
        past_medical_history, medications, allergies, physical_examination,
        diagnosis, treatment_plan, notes, vital_signs
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [
        private_patient_id, chief_complaint, history_present_illness,
        past_medical_history, medications, allergies, physical_examination,
        diagnosis, treatment_plan, notes, vital_signs
      ]
    );

    console.log('✅ Medical record created:', result.rows[0].id);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating medical record:', error);
    res.status(500).json({ message: 'Erro ao criar prontuário' });
  }
});

// Attendance locations routes
app.get('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    console.log('🔄 Fetching attendance locations for professional:', req.user.id);
    
    const result = await pool.query(
      'SELECT * FROM attendance_locations WHERE professional_id = $1 ORDER BY is_default DESC, name',
      [req.user.id]
    );
    
    console.log('✅ Attendance locations fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching attendance locations:', error);
    res.status(500).json({ message: 'Erro ao buscar locais de atendimento' });
  }
});

app.post('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    } = req.body;

    console.log('🔄 Creating attendance location:', { name, is_default });

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    // If this is being set as default, remove default from others
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
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [
        req.user.id, name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default || false
      ]
    );

    console.log('✅ Attendance location created:', result.rows[0].name);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating attendance location:', error);
    res.status(500).json({ message: 'Erro ao criar local de atendimento' });
  }
});

// Reports routes
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    console.log('🔄 Generating revenue report:', { start_date, end_date });

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Datas de início e fim são obrigatórias' });
    }

    // Get revenue by professional
    const professionalsResult = await pool.query(`
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
        AND c.client_id IS NOT NULL
      GROUP BY prof.id, prof.name, prof.percentage
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    // Get revenue by service
    const servicesResult = await pool.query(`
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
    const totalRevenue = professionalsResult.rows.reduce(
      (sum, row) => sum + parseFloat(row.revenue || 0), 0
    );

    console.log('✅ Revenue report generated');
    res.json({
      total_revenue: totalRevenue,
      revenue_by_professional: professionalsResult.rows,
      revenue_by_service: servicesResult.rows
    });
  } catch (error) {
    console.error('❌ Error generating revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de receita' });
  }
});

app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    console.log('🔄 Generating professional revenue report:', { 
      professional_id: req.user.id, 
      start_date, 
      end_date 
    });

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Datas de início e fim são obrigatórias' });
    }

    // Get professional's percentage
    const profResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = profResult.rows[0]?.percentage || 50;

    // Get consultations for this professional in the date range
    const consultationsResult = await pool.query(`
      SELECT 
        c.date,
        COALESCE(cl.name, d.name, pp.name) as client_name,
        s.name as service_name,
        c.value as total_value,
        CASE 
          WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL 
          THEN c.value * ((100 - $3) / 100.0)
          ELSE 0
        END as amount_to_pay
      FROM consultations c
      LEFT JOIN users cl ON c.client_id = cl.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN services s ON c.service_id = s.id
      WHERE c.professional_id = $1 
        AND c.date >= $2 AND c.date <= $4
      ORDER BY c.date DESC
    `, [req.user.id, start_date, professionalPercentage, end_date]);

    // Calculate summary
    const totalRevenue = consultationsResult.rows.reduce(
      (sum, row) => sum + parseFloat(row.total_value || 0), 0
    );
    const totalAmountToPay = consultationsResult.rows.reduce(
      (sum, row) => sum + parseFloat(row.amount_to_pay || 0), 0
    );

    console.log('✅ Professional revenue report generated');
    res.json({
      summary: {
        professional_percentage: professionalPercentage,
        total_revenue: totalRevenue,
        consultation_count: consultationsResult.rows.length,
        amount_to_pay: totalAmountToPay
      },
      consultations: consultationsResult.rows
    });
  } catch (error) {
    console.error('❌ Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de receita do profissional' });
  }
});

// Catch-all handler for React Router
app.get('*', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'dist', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({ message: 'Erro interno do servidor' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
});