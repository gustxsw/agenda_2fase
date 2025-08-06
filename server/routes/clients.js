import express from 'express';
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

// Lookup client by CPF
router.get('/lookup', authenticate, authorize(['professional']), async (req, res) => {
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
       WHERE cpf = $1 AND roles::jsonb ? 'client'`,
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

// Get all clients (for admin)
router.get('/', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, cpf, email, phone, subscription_status, subscription_expiry, created_at
       FROM users 
       WHERE roles::jsonb ? 'client'
       ORDER BY name`
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching clients:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

export default router;