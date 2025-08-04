const express = require('express');
const { pool } = require('../db');
const { authenticate, authorize } = require('../middleware/auth');
const router = express.Router();

// Get all professionals with their scheduling access status
router.get('/professionals-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id,
        u.name,
        u.email,
        u.phone,
        sc.name as category_name,
        pss.subscription_status,
        pss.expires_at as subscription_expiry,
        CASE 
          WHEN asa.id IS NOT NULL AND asa.expires_at > NOW() THEN true
          ELSE false
        END as has_admin_access,
        asa.expires_at as admin_access_expiry,
        admin_user.name as admin_access_granted_by,
        asa.granted_at as admin_access_granted_at
      FROM users u
      INNER JOIN unnest(u.roles) as role_elem ON role_elem = 'professional'
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      LEFT JOIN professional_scheduling_subscriptions pss ON u.id = pss.professional_id
      LEFT JOIN admin_scheduling_access asa ON u.id = asa.professional_id AND asa.expires_at > NOW()
      LEFT JOIN users admin_user ON asa.granted_by_admin_id = admin_user.id
      ORDER BY u.name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get active scheduling accesses granted by admin
router.get('/scheduling-accesses', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        asa.id,
        asa.professional_id,
        u.name as professional_name,
        asa.expires_at,
        admin_user.name as granted_by_name,
        asa.granted_at,
        CASE WHEN asa.expires_at > NOW() THEN true ELSE false END as is_active
      FROM admin_scheduling_access asa
      INNER JOIN users u ON asa.professional_id = u.id
      INNER JOIN users admin_user ON asa.granted_by_admin_id = admin_user.id
      ORDER BY asa.granted_at DESC
      LIMIT 20
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching scheduling accesses:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Grant scheduling access to a professional
router.post('/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;

    // Validate input
    if (!professional_id || !expires_at) {
      return res.status(400).json({ message: 'ID do profissional e data de expiração são obrigatórios' });
    }

    // Check if professional exists and has professional role
    const professionalCheck = await pool.query(
      `SELECT id, name, roles FROM users WHERE id = $1`,
      [professional_id]
    );

    if (professionalCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professional = professionalCheck.rows[0];
    if (!professional.roles || !professional.roles.includes('professional')) {
      return res.status(400).json({ message: 'Usuário não é um profissional' });
    }

    // Check if expiry date is in the future
    const expiryDate = new Date(expires_at);
    if (expiryDate <= new Date()) {
      return res.status(400).json({ message: 'Data de expiração deve ser no futuro' });
    }

    // Insert or update admin scheduling access
    const result = await pool.query(`
      INSERT INTO admin_scheduling_access 
      (professional_id, granted_by_admin_id, expires_at, reason)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (professional_id) 
      DO UPDATE SET 
        granted_by_admin_id = $2,
        expires_at = $3,
        reason = $4,
        granted_at = CURRENT_TIMESTAMP
      RETURNING *
    `, [professional_id, req.user.id, expires_at, reason]);

    // Update professional schedule settings to enable scheduling
    await pool.query(`
      INSERT INTO professional_schedule_settings 
      (professional_id, has_scheduling_subscription)
      VALUES ($1, true)
      ON CONFLICT (professional_id) 
      DO UPDATE SET has_scheduling_subscription = true
    `, [professional_id]);

    console.log(`✅ Admin ${req.user.name} granted scheduling access to professional ${professional.name} until ${expires_at}`);

    res.status(201).json({
      message: 'Acesso à agenda concedido com sucesso',
      access: result.rows[0]
    });
  } catch (error) {
    console.error('Error granting scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Revoke scheduling access from a professional
router.delete('/revoke-scheduling-access/:professionalId', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professionalId } = req.params;

    // Check if professional exists
    const professionalCheck = await pool.query(
      `SELECT id, name FROM users WHERE id = $1`,
      [professionalId]
    );

    if (professionalCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professional = professionalCheck.rows[0];

    // Delete admin scheduling access
    const deleteResult = await pool.query(
      `DELETE FROM admin_scheduling_access WHERE professional_id = $1 RETURNING *`,
      [professionalId]
    );

    if (deleteResult.rows.length === 0) {
      return res.status(404).json({ message: 'Acesso não encontrado para este profissional' });
    }

    // Check if professional has paid subscription
    const subscriptionCheck = await pool.query(`
      SELECT * FROM professional_scheduling_subscriptions 
      WHERE professional_id = $1 AND status = 'active' AND expires_at > NOW()
    `, [professionalId]);

    // If no paid subscription, disable scheduling access
    if (subscriptionCheck.rows.length === 0) {
      await pool.query(`
        UPDATE professional_schedule_settings 
        SET has_scheduling_subscription = false
        WHERE professional_id = $1
      `, [professionalId]);
    }

    console.log(`✅ Admin ${req.user.name} revoked scheduling access from professional ${professional.name}`);

    res.json({ message: 'Acesso à agenda revogado com sucesso' });
  } catch (error) {
    console.error('Error revoking scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get scheduling access statistics
router.get('/scheduling-access-stats', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        COUNT(*) as total_professionals,
        COUNT(CASE WHEN asa.id IS NOT NULL AND asa.expires_at > NOW() THEN 1 END) as with_admin_access,
        COUNT(CASE WHEN pss.id IS NOT NULL AND pss.status = 'active' AND pss.expires_at > NOW() THEN 1 END) as with_paid_access,
        COUNT(CASE WHEN asa.id IS NOT NULL AND asa.expires_at <= NOW() THEN 1 END) as expired_admin_access
      FROM users u
      INNER JOIN unnest(u.roles) as role_elem ON role_elem = 'professional'
      LEFT JOIN admin_scheduling_access asa ON u.id = asa.professional_id
      LEFT JOIN professional_scheduling_subscriptions pss ON u.id = pss.professional_id
    `);

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching scheduling access stats:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

module.exports = router;