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
    console.error('Error fetching clients by city:', error);
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
         COUNT(*) as professional_count,
         sc.name as category_name,
         COUNT(*) as count_by_category
       FROM users u
       LEFT JOIN service_categories sc ON u.category_id = sc.id
       WHERE u.roles::jsonb ? 'professional' 
       AND u.city IS NOT NULL 
       AND u.city != ''
       GROUP BY u.city, u.state, sc.name
       ORDER BY professional_count DESC, u.city, sc.name`
    );

    // Group by city for better presentation
    const groupedData = result.rows.reduce((acc, row) => {
      const key = `${row.city}, ${row.state}`;
      if (!acc[key]) {
        acc[key] = {
          city: row.city,
          state: row.state,
          total_professionals: 0,
          categories: []
        };
      }
      
      acc[key].total_professionals += row.count_by_category;
      if (row.category_name) {
        acc[key].categories.push({
          category_name: row.category_name,
          count: row.count_by_category
        });
      }
      
      return acc;
    }, {});

    const finalData = Object.values(groupedData).sort((a, b) => b.total_professionals - a.total_professionals);

    res.json(finalData);
  } catch (error) {
    console.error('Error fetching professionals by city:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get revenue report for admin
router.get('/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Datas de início e fim são obrigatórias' });
    }

    // Get revenue by professional
    const professionalRevenueResult = await pool.query(
      `SELECT 
         p.name as professional_name,
         p.percentage as professional_percentage,
         SUM(c.value) as total_revenue,
         COUNT(*) as consultation_count,
         SUM(c.value * (p.percentage / 100.0)) as professional_payment,
         SUM(c.value * ((100 - p.percentage) / 100.0)) as clinic_revenue
        FROM consultations c
        JOIN users p ON c.professional_id = p.id
        LEFT JOIN services s ON c.service_id = s.id
        WHERE p.roles::jsonb ? 'professional'
        AND c.date >= $1 AND c.date <= $2
        GROUP BY p.id, p.name, p.percentage
        ORDER BY total_revenue DESC`,
      [start_date, end_date]
    );

    // Calculate revenue by service
    const serviceRevenueResult = await pool.query(
      `SELECT 
         s.name as service_name,
         SUM(c.value) as revenue,
         COUNT(*) as consultation_count
       FROM consultations c
       JOIN services s ON c.service_id = s.id
       WHERE c.date >= $1 AND c.date <= $2
       GROUP BY s.id, s.name
       ORDER BY revenue DESC`,
      [start_date, end_date]
    );

    const totalRevenue = professionalRevenueResult.rows.reduce((sum, row) => sum + parseFloat(row.total_revenue), 0);

    res.json({
      total_revenue: totalRevenue,
      revenue_by_professional: professionalRevenueResult.rows.map(row => ({
        professional_name: row.professional_name,
        professional_percentage: parseInt(row.professional_percentage),
        revenue: parseFloat(row.total_revenue),
        consultation_count: parseInt(row.consultation_count),
        professional_payment: parseFloat(row.professional_payment),
        clinic_revenue: parseFloat(row.clinic_revenue)
      })),
      revenue_by_service: serviceRevenueResult.rows.map(row => ({
        service_name: row.service_name,
        revenue: parseFloat(row.revenue),
        consultation_count: parseInt(row.consultation_count)
      }))
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
      return res.status(400).json({ message: 'Datas de início e fim são obrigatórias' });
    }

    // Get professional's percentage
    const professionalResult = await pool.query(
      `SELECT percentage FROM users WHERE id = $1`,
      [req.user.id]
    );

    const professionalPercentage = professionalResult.rows[0]?.percentage || 50;

    // Get consultations for the period
    const consultationsResult = await pool.query(
      `SELECT 
         c.date,
         c.value,
         COALESCE(pp.name, u.name, d.name) as client_name,
         s.name as service_name,
         CASE 
           WHEN c.private_patient_id IS NOT NULL THEN c.value
           ELSE c.value * ($1 / 100.0)
         END as professional_payment,
         CASE 
           WHEN c.private_patient_id IS NOT NULL THEN 0
           ELSE c.value * ((100 - $1) / 100.0)
         END as amount_to_pay
       FROM consultations c
       LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
       LEFT JOIN users u ON c.client_id = u.id
       LEFT JOIN dependents d ON c.dependent_id = d.id
       LEFT JOIN services s ON c.service_id = s.id
       WHERE c.professional_id = $2
       AND c.date >= $3 AND c.date <= $4
       ORDER BY c.date DESC`,
      [professionalPercentage, req.user.id, start_date, end_date]
    );

    const consultations = consultationsResult.rows;
    
    // Calculate summary
    const summary = {
      professional_percentage: professionalPercentage,
      total_revenue: consultations.reduce((sum, c) => sum + parseFloat(c.value), 0),
      consultation_count: consultations.length,
      amount_to_pay: consultations.reduce((sum, c) => sum + parseFloat(c.amount_to_pay), 0)
    };

    res.json({
      summary,
      consultations: consultations.map(c => ({
        date: c.date,
        client_name: c.client_name,
        service_name: c.service_name,
        total_value: parseFloat(c.value),
        amount_to_pay: parseFloat(c.amount_to_pay)
      }))
    });
  } catch (error) {
    console.error('Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

export default router;