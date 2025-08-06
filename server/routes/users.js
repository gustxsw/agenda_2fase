import express from 'express';
import bcrypt from 'bcryptjs';
import { pool } from '../db.js';
import { authenticate, authorize } from '../middleware/auth.js';

const router = express.Router();

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

// Helper function to safely stringify roles for database
const stringifyRoles = (roles) => {
  if (!roles) return JSON.stringify([]);
  if (Array.isArray(roles)) return JSON.stringify(roles);
  if (typeof roles === 'string') {
    try {
      // Test if it's already valid JSON
      JSON.parse(roles);
      return roles;
    } catch (e) {
      // Convert string to array and stringify
      const rolesArray = roles.includes(',') ? roles.split(',').map(r => r.trim()) : [roles];
      return JSON.stringify(rolesArray);
    }
  }
  return JSON.stringify([roles]);
};

// Get all users
router.get('/', authenticate, authorize(['admin']), async (req, res) => {
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

// Get specific user
router.get('/:id', authenticate, async (req, res) => {
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

// Create new user
router.post('/', authenticate, authorize(['admin']), async (req, res) => {
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

    // Ensure roles is properly formatted
    const rolesArray = Array.isArray(roles) ? roles : [roles];
    const rolesJson = stringifyRoles(rolesArray);

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
       address_complement, neighborhood, city, state, passwordHash, rolesJson,
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

// Update user
router.put('/:id', authenticate, async (req, res) => {
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

    // Handle roles update
    let rolesJson = existingUser.roles;
    if (roles !== undefined) {
      const rolesArray = Array.isArray(roles) ? roles : [roles];
      rolesJson = stringifyRoles(rolesArray);
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
       neighborhood, city, state, rolesJson, percentage, category_id, passwordHash, id]
    );

    const updatedUser = result.rows[0];
    updatedUser.roles = parseRoles(updatedUser.roles);

    res.json(updatedUser);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Activate client subscription
router.put('/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
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

// Delete user
router.delete('/:id', authenticate, authorize(['admin']), async (req, res) => {
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

export default router;