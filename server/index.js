import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

// CORS configuration
const corsOptions = {
  origin: [
    'http://localhost:5173',
    'http://localhost:3000',
    'https://cartaoquiroferreira.com.br',
    'https://www.cartaoquiroferreira.com.br'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// TODO: Add your API routes here inline

// Professional revenue report
app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    const professionalId = req.user.id;

    console.log('🔄 Generating professional revenue report for:', {
      professionalId,
      start_date,
      end_date
    });

    // Validate dates
    if (!start_date || !end_date) {
      return res.status(400).json({ 
        message: 'start_date e end_date são obrigatórios' 
      });
    }

    // Get professional percentage
    const professionalQuery = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [professionalId]
    );

    if (professionalQuery.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professionalPercentage = professionalQuery.rows[0].percentage || 50;

    // 🔥 FIXED: Get consultations with proper type casting and null handling
    const consultationsQuery = `
      SELECT 
        c.id,
        c.date,
        COALESCE(cl.name, d.name, pp.name) as client_name,
        s.name as service_name,
        c.value::numeric as total_value,
        CASE 
          WHEN c.private_patient_id IS NOT NULL THEN 0::numeric
          ELSE ROUND((c.value::numeric * (100 - $3::numeric) / 100), 2)
        END as amount_to_pay
      FROM consultations c
      LEFT JOIN users cl ON c.client_id = cl.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN services s ON c.service_id = s.id
      WHERE c.professional_id = $1
        AND c.date >= $2::date
        AND c.date <= $4::date
      ORDER BY c.date DESC
    `;

    const consultationsResult = await pool.query(consultationsQuery, [
      professionalId,
      start_date,
      professionalPercentage,
      end_date
    ]);

    console.log('📊 Found consultations:', consultationsResult.rows.length);

    // 🔥 FIXED: Calculate summary with proper numeric handling
    const consultations = consultationsResult.rows;
    
    const summary = {
      professional_percentage: professionalPercentage,
      total_revenue: consultations.reduce((sum, c) => sum + parseFloat(c.total_value || 0), 0),
      consultation_count: consultations.length,
      amount_to_pay: consultations.reduce((sum, c) => sum + parseFloat(c.amount_to_pay || 0), 0)
    };

    // 🔥 FIXED: Format consultations data properly
    const formattedConsultations = consultations.map(c => ({
      date: c.date,
      client_name: c.client_name || 'N/A',
      service_name: c.service_name || 'N/A',
      total_value: parseFloat(c.total_value || 0),
      amount_to_pay: parseFloat(c.amount_to_pay || 0)
    }));

    const reportData = {
      summary,
      consultations: formattedConsultations
    };

    console.log('✅ Professional revenue report generated:', {
      consultationCount: summary.consultation_count,
      totalRevenue: summary.total_revenue,
      amountToPay: summary.amount_to_pay
    });

    res.json(reportData);
  } catch (error) {
    console.error('❌ Error generating professional revenue report:', error);
    res.status(500).json({ 
      message: 'Erro interno do servidor ao gerar relatório',
      error: error.message 
    });
  }
});

// Detailed professional report
app.get('/api/reports/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    const professionalId = req.user.id;

    console.log('🔄 Generating detailed professional report for:', {
      professionalId,
      start_date,
      end_date
    });

    // Validate dates
    if (!start_date || !end_date) {
      return res.status(400).json({ 
        message: 'start_date e end_date são obrigatórios' 
      });
    }

    // Get professional percentage
    const professionalQuery = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [professionalId]
    );

    if (professionalQuery.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professionalPercentage = professionalQuery.rows[0].percentage || 50;

    // 🔥 FIXED: Get detailed consultation breakdown
    const detailedQuery = `
      SELECT 
        COUNT(CASE WHEN c.private_patient_id IS NULL THEN 1 END)::integer as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END)::integer as private_consultations,
        COUNT(*)::integer as total_consultations,
        COALESCE(SUM(CASE WHEN c.private_patient_id IS NULL THEN c.value::numeric ELSE 0 END), 0) as convenio_revenue,
        COALESCE(SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value::numeric ELSE 0 END), 0) as private_revenue,
        COALESCE(SUM(c.value::numeric), 0) as total_revenue,
        COALESCE(SUM(CASE 
          WHEN c.private_patient_id IS NOT NULL THEN 0::numeric
          ELSE ROUND((c.value::numeric * (100 - $3::numeric) / 100), 2)
        END), 0) as amount_to_pay
      FROM consultations c
      WHERE c.professional_id = $1
        AND c.date >= $2::date
        AND c.date <= $4::date
    `;

    const detailedResult = await pool.query(detailedQuery, [
      professionalId,
      start_date,
      professionalPercentage,
      end_date
    ]);

    const row = detailedResult.rows[0];

    const summary = {
      total_consultations: parseInt(row.total_consultations) || 0,
      convenio_consultations: parseInt(row.convenio_consultations) || 0,
      private_consultations: parseInt(row.private_consultations) || 0,
      total_revenue: parseFloat(row.total_revenue) || 0,
      convenio_revenue: parseFloat(row.convenio_revenue) || 0,
      private_revenue: parseFloat(row.private_revenue) || 0,
      professional_percentage: professionalPercentage,
      amount_to_pay: parseFloat(row.amount_to_pay) || 0
    };

    console.log('✅ Detailed professional report generated:', summary);

    res.json({ summary });
  } catch (error) {
    console.error('❌ Error generating detailed professional report:', error);
    res.status(500).json({ 
      message: 'Erro interno do servidor ao gerar relatório detalhado',
      error: error.message 
    });
  }
});

// Revenue report for admin
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    console.log('🔄 Generating admin revenue report for period:', { start_date, end_date });

    // Validate dates
    if (!start_date || !end_date) {
      return res.status(400).json({ 
        message: 'start_date e end_date são obrigatórios' 
      });
    }

    // 🔥 FIXED: Revenue by professional with proper numeric handling
    const professionalRevenueQuery = `
      SELECT 
        u.name as professional_name,
        u.percentage as professional_percentage,
        COALESCE(SUM(c.value::numeric), 0) as revenue,
        COUNT(c.id)::integer as consultation_count,
        COALESCE(SUM(ROUND((c.value::numeric * u.percentage::numeric / 100), 2)), 0) as professional_payment,
        COALESCE(SUM(ROUND((c.value::numeric * (100 - u.percentage::numeric) / 100), 2)), 0) as clinic_revenue
      FROM users u
      LEFT JOIN consultations c ON u.id = c.professional_id 
        AND c.date >= $1::date 
        AND c.date <= $2::date
        AND c.private_patient_id IS NULL
      WHERE u.roles @> '["professional"]'
      GROUP BY u.id, u.name, u.percentage
      HAVING COUNT(c.id) > 0
      ORDER BY revenue DESC
    `;

    const professionalRevenueResult = await pool.query(professionalRevenueQuery, [
      start_date,
      end_date
    ]);

    // 🔥 FIXED: Revenue by service with proper numeric handling
    const serviceRevenueQuery = `
      SELECT 
        s.name as service_name,
        COALESCE(SUM(c.value::numeric), 0) as revenue,
        COUNT(c.id)::integer as consultation_count
      FROM services s
      LEFT JOIN consultations c ON s.id = c.service_id 
        AND c.date >= $1::date 
        AND c.date <= $2::date
      GROUP BY s.id, s.name
      HAVING COUNT(c.id) > 0
      ORDER BY revenue DESC
    `;

    const serviceRevenueResult = await pool.query(serviceRevenueQuery, [
      start_date,
      end_date
    ]);

    // 🔥 FIXED: Calculate total revenue properly
    const totalRevenueQuery = `
      SELECT COALESCE(SUM(value::numeric), 0) as total_revenue
      FROM consultations
      WHERE date >= $1::date AND date <= $2::date
    `;

    const totalRevenueResult = await pool.query(totalRevenueQuery, [
      start_date,
      end_date
    ]);

    // Format the response data
    const revenue_by_professional = professionalRevenueResult.rows.map(row => ({
      professional_name: row.professional_name,
      professional_percentage: parseInt(row.professional_percentage) || 50,
      revenue: parseFloat(row.revenue) || 0,
      consultation_count: parseInt(row.consultation_count) || 0,
      professional_payment: parseFloat(row.professional_payment) || 0,
      clinic_revenue: parseFloat(row.clinic_revenue) || 0
    }));

    const revenue_by_service = serviceRevenueResult.rows.map(row => ({
      service_name: row.service_name,
      revenue: parseFloat(row.revenue) || 0,
      consultation_count: parseInt(row.consultation_count) || 0
    }));

    const reportData = {
      total_revenue: parseFloat(totalRevenueResult.rows[0].total_revenue) || 0,
      revenue_by_professional,
      revenue_by_service
    };

    console.log('✅ Admin revenue report generated:', {
      totalRevenue: reportData.total_revenue,
      professionalCount: revenue_by_professional.length,
      serviceCount: revenue_by_service.length
    });

    res.json(reportData);
  } catch (error) {
    console.error('❌ Error generating revenue report:', error);
    res.status(500).json({ 
      message: 'Erro interno do servidor ao gerar relatório',
      error: error.message 
    });
  }
});

// Clients by city report
app.get('/api/reports/clients-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    console.log('🔄 Generating clients by city report');

    const query = `
      SELECT 
        city,
        state,
        COUNT(*)::integer as client_count,
        COUNT(CASE WHEN subscription_status = 'active' THEN 1 END)::integer as active_clients,
        COUNT(CASE WHEN subscription_status = 'pending' THEN 1 END)::integer as pending_clients,
        COUNT(CASE WHEN subscription_status = 'expired' THEN 1 END)::integer as expired_clients
      FROM users 
      WHERE roles @> '["client"]' 
        AND city IS NOT NULL 
        AND city != ''
      GROUP BY city, state
      ORDER BY client_count DESC, city
    `;

    const result = await pool.query(query);

    console.log('✅ Clients by city report generated:', result.rows.length, 'cities');

    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error generating clients by city report:', error);
    res.status(500).json({ 
      message: 'Erro interno do servidor',
      error: error.message 
    });
  }
});

// Professionals by city report
app.get('/api/reports/professionals-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    console.log('🔄 Generating professionals by city report');

    const query = `
      SELECT 
        u.city,
        u.state,
        COUNT(u.id)::integer as total_professionals,
        json_agg(
          json_build_object(
            'category_name', COALESCE(sc.name, 'Sem categoria'),
            'count', 1
          )
        ) as categories
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE u.roles @> '["professional"]' 
        AND u.city IS NOT NULL 
        AND u.city != ''
      GROUP BY u.city, u.state
      ORDER BY total_professionals DESC, u.city
    `;

    const result = await pool.query(query);

    // Process the categories to group by category name
    const processedResult = result.rows.map(row => {
      const categoryMap = new Map();
      
      if (row.categories) {
        row.categories.forEach((cat) => {
          const name = cat.category_name;
          if (categoryMap.has(name)) {
            categoryMap.set(name, categoryMap.get(name) + cat.count);
          } else {
            categoryMap.set(name, cat.count);
          }
        });
      }

      return {
        city: row.city,
        state: row.state,
        total_professionals: row.total_professionals,
        categories: Array.from(categoryMap.entries()).map(([category_name, count]) => ({
          category_name,
          count
        }))
      };
    });

    console.log('✅ Professionals by city report generated:', processedResult.length, 'cities');

    res.json(processedResult);
  } catch (error) {
    console.error('❌ Error generating professionals by city report:', error);
    res.status(500).json({ 
      message: 'Erro interno do servidor',
      error: error.message 
    });
  }
});
// Serve static files from the dist directory
app.use(express.static(path.join(__dirname, '../dist')));

// Handle React Router routes - serve index.html for all non-API routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Global error handler:', err);
  res.status(500).json({ 
    message: 'Erro interno do servidor',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Erro interno'
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});