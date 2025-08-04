const express = require('express');
const { pool } = require('../db');
const { authenticate, authorize } = require('../middleware/auth');
const router = express.Router();

// Check if professional has admin-granted scheduling access
router.get('/admin-scheduling-access', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        asa.*,
        admin_user.name as granted_by_name
      FROM admin_scheduling_access asa
      LEFT JOIN users admin_user ON asa.granted_by_admin_id = admin_user.id
      WHERE asa.professional_id = $1 AND asa.expires_at > NOW()
      ORDER BY asa.granted_at DESC
      LIMIT 1
    `, [req.user.id]);

    if (result.rows.length === 0) {
      return res.json({
        has_access: false,
        expires_at: null,
        granted_by: null,
        granted_at: null,
        reason: null
      });
    }

    const access = result.rows[0];
    res.json({
      has_access: true,
      expires_at: access.expires_at,
      granted_by: access.granted_by_name,
      granted_at: access.granted_at,
      reason: access.reason
    });
  } catch (error) {
    console.error('Error checking admin scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

module.exports = router;

// Also export as default for ES6 compatibility
module.exports.default = router;