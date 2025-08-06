import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from '../db.js';

const router = express.Router();

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

// Login endpoint
router.post('/login', async (req, res) => {
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

// Role selection endpoint
router.post('/select-role', async (req, res) => {
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

// Switch role endpoint
router.post('/switch-role', async (req, res) => {
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

// Register endpoint (for clients only)
router.post('/register', async (req, res) => {
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

    // Create user with client role and pending subscription
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

// Logout endpoint
router.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

export default router;