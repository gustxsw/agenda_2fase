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

// Get revenue report for admin
router.get('/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    // Get total revenue
    const totalRevenueResult = await pool.query(
      `SELECT COALESCE(SUM(value), 0) as total_revenue
       FROM consultations 
       WHERE date >= $1 AND date <= $2`,
      [start_date, end_date]
    );

    const totalRevenue = parseFloat(totalRevenueResult.rows[0].total_revenue) || 0;

    // Get revenue by professional
    const professionalRevenueResult = await pool.query(
      `SELECT 
         p.name as professional_name,
         p.percentage as professional_percentage,
         COALESCE(SUM(c.value), 0) as revenue,
         COUNT(c.id) as consultation_count,
         COALESCE(SUM(c.value * (p.percentage / 100.0)), 0) as professional_payment,
         COALESCE(SUM(c.value * ((100 - p.percentage) / 100.0)), 0) as clinic_revenue
       FROM users p
       LEFT JOIN consultations c ON c.professional_id = p.id 
         AND c.date >= $1 AND c.date <= $2
       WHERE p.roles::jsonb ? 'professional'
       GROUP BY p.id, p.name, p.percentage
       ORDER BY revenue DESC`,
      [start_date, end_date]
    );

    // Get revenue by service
    const serviceRevenueResult = await pool.query(
      `SELECT 
         s.name as service_name,
         COALESCE(SUM(c.value), 0) as revenue,
         COUNT(c.id) as consultation_count
       FROM services s
       LEFT JOIN consultations c ON c.service_id = s.id 
         AND c.date >= $1 AND c.date <= $2
       GROUP BY s.id, s.name
       HAVING COUNT(c.id) > 0
       ORDER BY revenue DESC`,
      [start_date, end_date]
    );

    res.json({
      total_revenue: totalRevenue,
      revenue_by_professional: professionalRevenueResult.rows,
      revenue_by_service: serviceRevenueResult.rows,
    });
  } catch (error) {
    console.error('Error generating revenue report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get professional revenue report
router.get('/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    // Get professional's percentage
    const professionalResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    if (professionalResult.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professionalPercentage = professionalResult.rows[0].percentage || 50;

    // Get consultations for the professional in the date range
    const consultationsResult = await pool.query(
      `SELECT 
         c.date,
         COALESCE(u.name, d.name, pp.name) as client_name,
         s.name as service_name,
         c.value as total_value,
         CASE 
           WHEN pp.id IS NOT NULL THEN c.value
           ELSE c.value * ((100 - $3) / 100.0)
         END as amount_to_pay
       FROM consultations c
       LEFT JOIN users u ON c.client_id = u.id
       LEFT JOIN dependents d ON c.dependent_id = d.id
       LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
       LEFT JOIN services s ON c.service_id = s.id
       WHERE c.professional_id = $1 
       AND c.date >= $2 AND c.date <= $4
       ORDER BY c.date DESC`,
      [req.user.id, start_date, professionalPercentage, end_date]
    );

    // Calculate summary
    const consultations = consultationsResult.rows;
    const totalRevenue = consultations.reduce((sum, c) => sum + parseFloat(c.total_value), 0);
    const totalAmountToPay = consultations.reduce((sum, c) => sum + parseFloat(c.amount_to_pay), 0);

    res.json({
      summary: {
        professional_percentage: professionalPercentage,
        total_revenue: totalRevenue,
        consultation_count: consultations.length,
        amount_to_pay: totalAmountToPay,
      },
      consultations: consultations,
    });
  } catch (error) {
    console.error('Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get detailed professional report
router.get('/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    // Get professional's percentage
    const professionalResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    if (professionalResult.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professionalPercentage = professionalResult.rows[0].percentage || 50;

    // Get consultations breakdown
    const consultationsResult = await pool.query(
      `SELECT 
         COUNT(*) as total_consultations,
         COUNT(CASE WHEN private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
         COUNT(CASE WHEN (client_id IS NOT NULL OR dependent_id IS NOT NULL) THEN 1 END) as convenio_consultations,
         COALESCE(SUM(value), 0) as total_revenue,
         COALESCE(SUM(CASE WHEN private_patient_id IS NOT NULL THEN value ELSE 0 END), 0) as private_revenue,
         COALESCE(SUM(CASE WHEN (client_id IS NOT NULL OR dependent_id IS NOT NULL) THEN value ELSE 0 END), 0) as convenio_revenue
       FROM consultations 
       WHERE professional_id = $1 
       AND date >= $2 AND date <= $3`,
      [req.user.id, start_date, end_date]
    );

    const summary = consultationsResult.rows[0];
    
    // Calculate amount to pay (only for convenio consultations)
    const amountToPay = parseFloat(summary.convenio_revenue) * ((100 - professionalPercentage) / 100.0);

    res.json({
      summary: {
        total_consultations: parseInt(summary.total_consultations),
        convenio_consultations: parseInt(summary.convenio_consultations),
        private_consultations: parseInt(summary.private_consultations),
        total_revenue: parseFloat(summary.total_revenue),
        convenio_revenue: parseFloat(summary.convenio_revenue),
        private_revenue: parseFloat(summary.private_revenue),
        professional_percentage: professionalPercentage,
        amount_to_pay: amountToPay,
      }
    });
  } catch (error) {
    console.error('Error generating detailed professional report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get clients by city report
router.get('/clients-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         city,
         state,
         COUNT(*) as client_count,
         COUNT(CASE WHEN subscription_status = 'active' THEN 1 END) as active_clients,
         COUNT(CASE WHEN subscription_status = 'pending' THEN 1 END) as pending_clients,
         COUNT(CASE WHEN subscription_status = 'expired' THEN 1 END) as expired_clients
       FROM users 
       WHERE roles::jsonb ? 'client' 
       AND city IS NOT NULL 
       AND city != ''
       GROUP BY city, state
       ORDER BY client_count DESC, city`
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error generating clients by city report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get professionals by city report
router.get('/professionals-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         u.city,
         u.state,
         COUNT(*) as total_professionals,
         json_agg(
           json_build_object(
             'category_name', COALESCE(sc.name, 'Sem categoria'),
             'count', 1
           )
         ) as categories_raw
       FROM users u
       LEFT JOIN service_categories sc ON u.category_id = sc.id
       WHERE u.roles::jsonb ? 'professional' 
       AND u.city IS NOT NULL 
       AND u.city != ''
       GROUP BY u.city, u.state
       ORDER BY total_professionals DESC, u.city`
    );

    // Process the data to group categories properly
    const processedData = result.rows.map(row => {
      const categoryMap = new Map();
      
      row.categories_raw.forEach((cat) => {
        const name = cat.category_name;
        if (categoryMap.has(name)) {
          categoryMap.set(name, categoryMap.get(name) + 1);
        } else {
          categoryMap.set(name, 1);
        }
      });

      const categories = Array.from(categoryMap.entries()).map(([name, count]) => ({
        category_name: name,
        count: count
      }));

      return {
        city: row.city,
        state: row.state,
        total_professionals: parseInt(row.total_professionals),
        categories: categories
      };
    });

    res.json(processedData);
  } catch (error) {
    console.error('Error generating professionals by city report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

export default router;