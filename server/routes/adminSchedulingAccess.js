const express = require('express');
const { pool } = require('../db');
const { authenticate, authorize } = require('../middleware/auth');
const router = express.Router();

// Get all professionals with their scheduling access status
router.get('/professionals', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         u.id,
         u.name,
         u.email,
         u.phone,
         sc.name as category_name,
         COALESCE(pss.has_scheduling_subscription, false) as has_scheduling_access,
         pss.expires_at as access_expires_at,
         pss.granted_by as access_granted_by,
         pss.granted_at as access_granted_at
       FROM users u
       LEFT JOIN service_categories sc ON u.category_id = sc.id
       LEFT JOIN professional_scheduling_subscriptions pss ON u.id = pss.professional_id
       WHERE u.roles @> '["professional"]'
       ORDER BY u.name`
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Grant scheduling access to a professional
router.post('/grant-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;

    if (!professional_id || !expires_at) {
      return res.status(400).json({ message: 'ID do profissional e data de expiração são obrigatórios' });
    }

    // Check if professional exists
    const professionalCheck = await pool.query(
      `SELECT id FROM users WHERE id = $1 AND roles @> '["professional"]'`,
      [professional_id]
    );

    if (professionalCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    // Grant or update access
    const result = await pool.query(
      `INSERT INTO professional_scheduling_subscriptions 
       (professional_id, status, expires_at, granted_by, granted_at, reason, is_admin_granted)
       VALUES ($1, 'active', $2, $3, CURRENT_TIMESTAMP, $4, true)
       ON CONFLICT (professional_id) 
       DO UPDATE SET 
         status = 'active',
         expires_at = $2,
         granted_by = $3,
         granted_at = CURRENT_TIMESTAMP,
         reason = $4,
         is_admin_granted = true,
         updated_at = CURRENT_TIMESTAMP
       RETURNING *`,
      [professional_id, expires_at, req.user.name, reason]
    );

    // Update professional schedule settings
    await pool.query(
      `INSERT INTO professional_schedule_settings 
       (professional_id, has_scheduling_subscription)
       VALUES ($1, true)
       ON CONFLICT (professional_id) 
       DO UPDATE SET 
         has_scheduling_subscription = true,
         updated_at = CURRENT_TIMESTAMP`,
      [professional_id]
    );

    res.json({
      message: 'Acesso à agenda concedido com sucesso',
      subscription: result.rows[0]
    });
  } catch (error) {
    console.error('Error granting access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Revoke scheduling access from a professional
router.post('/revoke-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id } = req.body;

    if (!professional_id) {
      return res.status(400).json({ message: 'ID do profissional é obrigatório' });
    }

    // Update subscription status
    await pool.query(
      `UPDATE professional_scheduling_subscriptions 
       SET status = 'revoked', 
           revoked_by = $1,
           revoked_at = CURRENT_TIMESTAMP,
           updated_at = CURRENT_TIMESTAMP
       WHERE professional_id = $2`,
      [req.user.name, professional_id]
    );

    // Update professional schedule settings
    await pool.query(
      `UPDATE professional_schedule_settings 
       SET has_scheduling_subscription = false,
           updated_at = CURRENT_TIMESTAMP
       WHERE professional_id = $1`,
      [professional_id]
    );

    res.json({ message: 'Acesso à agenda revogado com sucesso' });
  } catch (error) {
    console.error('Error revoking access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get access history for a professional
router.get('/history/:professional_id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id } = req.params;

    const result = await pool.query(
      `SELECT 
         pss.*,
         u.name as professional_name
       FROM professional_scheduling_subscriptions pss
       JOIN users u ON pss.professional_id = u.id
       WHERE pss.professional_id = $1
       ORDER BY pss.created_at DESC`,
      [professional_id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching access history:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

module.exports = router;