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

// Get all professionals (for clients to view)
router.get('/', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.phone, u.address, u.address_number, 
              u.address_complement, u.neighborhood, u.city, u.state, u.roles, u.photo_url,
              sc.name as category_name
       FROM users u
       LEFT JOIN service_categories sc ON u.category_id = sc.id
       WHERE u.roles::jsonb ? 'professional'
       ORDER BY u.name`
    );

    // Parse roles for each professional
    const professionals = result.rows.map(prof => ({
      ...prof,
      roles: parseRoles(prof.roles)
    }));

    res.json(professionals);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get professionals with scheduling access (for admin)
router.get('/scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         u.id,
         u.name,
         u.email,
         u.phone,
         sc.name as category_name,
         COALESCE(pss.status = 'active' AND pss.expires_at > NOW(), false) as has_scheduling_access,
         pss.expires_at as access_expires_at,
         pss.granted_by as access_granted_by,
         pss.granted_at as access_granted_at
       FROM users u
       LEFT JOIN service_categories sc ON u.category_id = sc.id
       LEFT JOIN professional_scheduling_subscriptions pss ON u.id = pss.professional_id
       WHERE u.roles::jsonb ? 'professional'
       ORDER BY u.name`
    );

    // Parse roles for each professional
    const professionals = result.rows.map(prof => ({
      ...prof,
      roles: parseRoles(prof.roles)
    }));

    res.json(professionals);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

export default router;