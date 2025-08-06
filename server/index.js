import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from './db.js';

// Load environment variables
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
    'https://www.cartaoquiroferreira.com.br',
    'https://cartaoquiroferreira.com.br'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Serve static files from dist directory
app.use(express.static(path.join(__dirname, '../dist')));

// Helper function to safely parse roles
const parseRoles = (roles) => {
  if (!roles) return [];
  if (Array.isArray(roles)) return roles;
  if (typeof roles === 'string') {
    try {
      return JSON.parse(roles);
    } catch (e) {
      return [roles];
    }
  }
  return [roles];
};

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'Não autorizado' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');

    const result = await pool.query(
      'SELECT id, name, cpf, email, roles FROM users WHERE id = $1',
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];
    const userRoles = parseRoles(user.roles);
    
    req.user = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      email: user.email,
      roles: userRoles,
      currentRole: decoded.currentRole || userRoles[0]
    };

    next();
  } catch (error) {
    console.error('Auth error:', error);
    return res.status(401).json({ message: 'Token inválido' });
  }
};

// Authorization middleware
const authorize = (roles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.currentRole) {
      return res.status(403).json({ message: 'Acesso não autorizado - role não definida' });
    }

    const userRoles = parseRoles(req.user.roles);
    
    if (!userRoles.includes(req.user.currentRole) || !roles.includes(req.user.currentRole)) {
      return res.status(403).json({ message: 'Acesso não autorizado para esta role' });
    }

    next();
  };
};

// ==================== AUTH ROUTES ====================

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return res.status(400).json({ message: 'CPF e senha são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    const result = await pool.query(
      'SELECT id, name, cpf, email, password_hash, roles FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'CPF ou senha inválidos' });
    }

    const user = result.rows[0];

    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'CPF ou senha inválidos' });
    }

    const userRoles = parseRoles(user.roles);

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

// Select role
app.post('/api/auth/select-role', async (req, res) => {
  try {
    const { userId, role } = req.body;

    if (!userId || !role) {
      return res.status(400).json({ message: 'ID do usuário e role são obrigatórios' });
    }

    const result = await pool.query(
      'SELECT id, name, cpf, email, roles FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];
    const userRoles = parseRoles(user.roles);

    if (!userRoles.includes(role)) {
      return res.status(403).json({ message: 'Usuário não possui esta role' });
    }

    const token = jwt.sign(
      { 
        id: user.id, 
        currentRole: role,
        roles: userRoles
      },
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

// Switch role
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

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');

    const result = await pool.query(
      'SELECT id, name, cpf, email, roles FROM users WHERE id = $1',
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];
    const userRoles = parseRoles(user.roles);

    if (!userRoles.includes(role)) {
      return res.status(403).json({ message: 'Usuário não possui esta role' });
    }

    const newToken = jwt.sign(
      { 
        id: user.id, 
        currentRole: role,
        roles: userRoles
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.cookie('token', newToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
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

// Register
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

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const result = await pool.query(
      `INSERT INTO users 
       (name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password_hash, roles, 
        subscription_status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, CURRENT_TIMESTAMP)
       RETURNING id, name, cpf, email, roles`,
      [name, cleanCpf, email, phone, birth_date, address, address_number,
       address_complement, neighborhood, city, state, passwordHash, 
       JSON.stringify(['client']), 'pending']
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

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

// ==================== BASIC ROUTES ====================

// Get all users
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.*, sc.name as category_name 
       FROM users u 
       LEFT JOIN service_categories sc ON u.category_id = sc.id 
       ORDER BY u.created_at DESC`
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get professionals
app.get('/api/professionals', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.phone, u.address, u.address_number, 
              u.address_complement, u.neighborhood, u.city, u.state, u.photo_url,
              sc.name as category_name
       FROM users u
       LEFT JOIN service_categories sc ON u.category_id = sc.id
       WHERE u.roles @> '["professional"]'
       ORDER BY u.name`
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get consultations
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query = `
      SELECT c.*, 
             COALESCE(pp.name, cl.name, d.name) as client_name,
             s.name as service_name,
             p.name as professional_name
      FROM consultations c
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN users cl ON c.client_id = cl.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users p ON c.professional_id = p.id
    `;
    
    const params = [];
    
    if (req.user.currentRole === 'client') {
      query += ' WHERE (c.client_id = $1 OR d.client_id = $1)';
      params.push(req.user.id);
    } else if (req.user.currentRole === 'professional') {
      query += ' WHERE c.professional_id = $1';
      params.push(req.user.id);
    }
    
    query += ' ORDER BY c.date DESC';
    
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
      date
    } = req.body;

    const result = await pool.query(
      `INSERT INTO consultations 
       (professional_id, client_id, dependent_id, private_patient_id, service_id, 
        location_id, value, date, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
       RETURNING *`,
      [req.user.id, client_id, dependent_id, private_patient_id, service_id, 
       location_id, value, date]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get services
app.get('/api/services', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.*, sc.name as category_name 
       FROM services s 
       LEFT JOIN service_categories sc ON s.category_id = sc.id 
       ORDER BY sc.name, s.name`
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get service categories
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM service_categories ORDER BY name'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get dependents
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
    
    const result = await pool.query(
      `SELECT d.*, u.name as client_name, u.subscription_status as client_subscription_status
       FROM dependents d
       JOIN users u ON d.client_id = u.id
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

// Lookup client by CPF
app.get('/api/clients/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;
    
    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }
    
    const cleanCpf = cpf.replace(/\D/g, '');
    
    const result = await pool.query(
      `SELECT id, name, cpf, subscription_status
       FROM users 
       WHERE cpf = $1 AND roles @> '["client"]'`,
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

// Get user by ID
app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Serve React app for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ 
    message: 'Erro interno do servidor',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Database: ${process.env.DATABASE_URL ? 'Connected' : 'Not configured'}`);
});