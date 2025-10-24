import { pool } from '../db.js';

/**
 * Middleware to check if professional has active scheduling access
 */
export const checkSchedulingAccess = async (req, res, next) => {
  try {
    // Only check for professionals
    if (!req.user || !req.user.roles || !req.user.roles.includes('professional')) {
      return next();
    }

    console.log('🔍 [SCHEDULING-ACCESS] Checking access for professional:', req.user.id);

    // Check if professional has active scheduling access
    const accessResult = await pool.query(
      `SELECT 
        id, expires_at, reason, is_active
       FROM scheduling_access 
       WHERE professional_id = $1 
         AND is_active = true 
         AND expires_at > CURRENT_TIMESTAMP
       ORDER BY created_at DESC 
       LIMIT 1`,
      [req.user.id]
    );

    if (accessResult.rows.length === 0) {
      console.log('❌ [SCHEDULING-ACCESS] No active access found for professional:', req.user.id);
      return res.status(403).json({ 
        message: 'Acesso à agenda não autorizado',
        code: 'NO_SCHEDULING_ACCESS',
        details: {
          hasAccess: false,
          reason: 'Você não possui acesso ativo à agenda. Assine por R$ 24,99/mês para ter acesso completo.'
        }
      });
    }

    const access = accessResult.rows[0];
    console.log('✅ [SCHEDULING-ACCESS] Active access found, expires at:', access.expires_at);

    // Add access info to request for use in routes
    req.schedulingAccess = {
      hasAccess: true,
      expiresAt: access.expires_at,
      reason: access.reason
    };

    next();
  } catch (error) {
    console.error('❌ [SCHEDULING-ACCESS] Error checking scheduling access:', error);
    res.status(500).json({ message: 'Erro ao verificar acesso à agenda' });
  }
};

/**
 * Get scheduling access status for a professional
 */
export const getSchedulingAccessStatus = async (professionalId) => {
  try {
    const accessResult = await pool.query(
      `SELECT 
        id, expires_at, reason, is_active,
        CASE 
          WHEN expires_at > CURRENT_TIMESTAMP AND is_active = true THEN true
          ELSE false
        END as has_active_access
       FROM scheduling_access 
       WHERE professional_id = $1 
         AND is_active = true
       ORDER BY created_at DESC 
       LIMIT 1`,
      [professionalId]
    );

    if (accessResult.rows.length === 0) {
      return {
        hasAccess: false,
        expiresAt: null,
        reason: null
      };
    }

    const access = accessResult.rows[0];
    return {
      hasAccess: access.has_active_access,
      expiresAt: access.expires_at,
      reason: access.reason
    };
  } catch (error) {
    console.error('Error getting scheduling access status:', error);
    return {
      hasAccess: false,
      expiresAt: null,
      reason: null
    };
  }
};