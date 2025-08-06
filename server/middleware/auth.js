import jwt from 'jsonwebtoken';
import { pool } from '../db.js';

export const authenticate = async (req, res, next) => {
  try {
    // Get token from cookie or Authorization header
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'Não autorizado' });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');

    // Get user from database - FIXED: use roles array instead of role column
    const result = await pool.query(
      'SELECT id, name, cpf, email, roles FROM users WHERE id = $1',
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];

    // Add user to request object with current role from token
    req.user = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      email: user.email,
      roles: Array.isArray(user.roles) ? user.roles : (user.roles ? JSON.parse(user.roles) : []),
      currentRole: decoded.currentRole || (user.roles && user.roles[0])
    };

    next();
  } catch (error) {
    console.error('Auth error:', error);
    return res.status(401).json({ message: 'Token inválido' });
  }
};

export const authorize = (roles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.currentRole) {
      return res.status(403).json({ message: 'Acesso não autorizado - role não definida' });
    }

    // Ensure roles is an array
    const userRoles = Array.isArray(req.user.roles) ? req.user.roles : [];
    
    if (!userRoles.includes(req.user.currentRole) || !roles.includes(req.user.currentRole)) {
      return res.status(403).json({ message: 'Acesso não autorizado para esta role' });
    }

    next();
  };
};