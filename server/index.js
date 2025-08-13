e >= $2 AND c.date <= $4
      ORDER BY c.date DESC
    `, [req.user.id, start_date, professionalPercentage, end_date]);

    // Calculate summary
    const summaryResult = await pool.query(`
      SELECT 
        COUNT(*) as total_consultations,
        COUNT(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        SUM(c.value) as total_revenue,
        SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value ELSE 0 END) as convenio_revenue,
        SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END) as private_revenue,
        SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value * ((100 - $2) / 100) ELSE 0 END) as amount_to_pay
      FROM consultations c
      WHERE c.professional_id = $1 
        AND c.date >= $3 AND c.date <= $4
    `, [req.user.id, professionalPercentage, start_date, end_date]);

    const summary = summaryResult.rows[0];

    res.json({
      summary: {
        professional_percentage: professionalPercentage,
        total_consultations: parseInt(summary.total_consultations || 0),
        convenio_consultations: parseInt(summary.convenio_consultations || 0),
        private_consultations: parseInt(summary.private_consultations || 0),
        total_revenue: parseFloat(summary.total_revenue || 0),
        convenio_revenue: parseFloat(summary.convenio_revenue || 0),
        private_revenue: parseFloat(summary.private_revenue || 0),
        amount_to_pay: parseFloat(summary.amount_to_pay || 0)
      },
      consultations: consultationsResult.rows
    });
  } catch (error) {
    console.error('Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
  }
});

app.get('/api/reports/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Datas de início e fim são obrigatórias' });
    }

    // Get professional's percentage
    const userResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = userResult.rows[0]?.percentage || 50;

    // Calculate detailed summary
    const summaryResult = await pool.query(`
      SELECT 
        COUNT(*) as total_consultations,
        COUNT(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        SUM(c.value) as total_revenue,
        SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value ELSE 0 END) as convenio_revenue,
        SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END) as private_revenue,
        SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value * ((100 - $2) / 100) ELSE 0 END) as amount_to_pay
      FROM consultations c
      WHERE c.professional_id = $1 
        AND c.date >= $3 AND c.date <= $4
    `, [req.user.id, professionalPercentage, start_date, end_date]);

    const summary = summaryResult.rows[0];

    res.json({
      summary: {
        professional_percentage: professionalPercentage,
        total_consultations: parseInt(summary.total_consultations || 0),
        convenio_consultations: parseInt(summary.convenio_consultations || 0),
        private_consultations: parseInt(summary.private_consultations || 0),
        total_revenue: parseFloat(summary.total_revenue || 0),
        convenio_revenue: parseFloat(summary.convenio_revenue || 0),
        private_revenue: parseFloat(summary.private_revenue || 0),
        amount_to_pay: parseFloat(summary.amount_to_pay || 0)
      }
    });
  } catch (error) {
    console.error('Error generating detailed professional report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório detalhado' });
  }
});

app.get('/api/reports/clients-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        city,
        state,
        COUNT(*) as client_count,
        COUNT(CASE WHEN subscription_status = 'active\' THEN 1 END) as active_clients,
        COUNT(CASE WHEN subscription_status = 'pending\' THEN 1 END) as pending_clients,
        COUNT(CASE WHEN subscription_status = 'expired\' THEN 1 END) as expired_clients
      FROM users 
      WHERE 'client' = ANY(roles) 
        AND city IS NOT NULL 
        AND city != ''
      GROUP BY city, state
      ORDER BY client_count DESC, city
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error generating clients by city report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
  }
});

app.get('/api/reports/professionals-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.city,
        u.state,
        COUNT(*) as total_professionals,
        json_agg(
          json_build_object(
            'category_name', COALESCE(sc.name, 'Sem categoria'),
            'count', 1
          )
        ) as categories
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE 'professional' = ANY(u.roles) 
        AND u.city IS NOT NULL 
        AND u.city != ''
      GROUP BY u.city, u.state
      ORDER BY total_professionals DESC, u.city
    `);

    // Process the aggregated data
    const processedData = result.rows.map(row => {
      const categoryMap = new Map();
      
      row.categories.forEach((cat) => {
        const name = cat.category_name;
        categoryMap.set(name, (categoryMap.get(name) || 0) + 1);
      });

      return {
        city: row.city,
        state: row.state,
        total_professionals: parseInt(row.total_professionals),
        categories: Array.from(categoryMap.entries()).map(([category_name, count]) => ({
          category_name,
          count
        }))
      };
    });

    res.json(processedData);
  } catch (error) {
    console.error('Error generating professionals by city report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
  }
});

// Payment routes
app.post('/api/create-subscription', authenticate, async (req, res) => {
  try {
    if (!mercadopagoEnabled || !preferenceClient) {
      return res.status(503).json({ message: 'Serviço de pagamento temporariamente indisponível' });
    }
    
    const { user_id, dependent_ids } = req.body;

    if (!user_id) {
      return res.status(400).json({ message: 'User ID é obrigatório' });
    }

    // Calculate total amount
    const baseAmount = 250; // R$250 for titular
    const dependentAmount = (dependent_ids?.length || 0) * 50; // R$50 per dependent
    const totalAmount = baseAmount + dependentAmount;

    console.log('🔄 Creating subscription payment preference...');
    console.log('💰 Total amount:', totalAmount);
    
    const preferenceData = {
      items: [
        {
          title: 'Assinatura Cartão Quiro Ferreira Saúde',
          unit_price: totalAmount,
          quantity: 1,
          currency_id: 'BRL'
        }
      ],
      payer: {
        email: 'cliente@quiroferreira.com.br',
        name: 'Cliente Quiro Ferreira'
      },
      back_urls: {
        success: `${req.protocol}://${req.get('host')}/payment/success`,
        failure: `${req.protocol}://${req.get('host')}/payment/failure`,
        pending: `${req.protocol}://${req.get('host')}/payment/pending`
      },
      auto_return: 'approved',
      external_reference: `subscription_${user_id}_${Date.now()}`,
      notification_url: `${req.protocol}://${req.get('host')}/api/webhooks/mercadopago`,
      statement_descriptor: 'QUIRO FERREIRA'
    };

    const response = await preferenceClient.create({ body: preferenceData });
    
    console.log('✅ Payment preference created successfully');
    console.log('🔗 Init point:', response.init_point);
    
    res.json({ 
      init_point: response.init_point,
      preference_id: response.id 
    });
  } catch (error) {
    console.error('Error creating subscription payment:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento',
      details: error.message 
    });
  }
});

app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    if (!mercadopagoEnabled || !preferenceClient) {
      return res.status(503).json({ message: 'Serviço de pagamento temporariamente indisponível' });
    }
    
    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor deve ser maior que zero' });
    }

    console.log('🔄 Creating professional payment preference...');
    console.log('💰 Amount:', amount);
    console.log('👤 Professional:', req.user.name);
    
    const preferenceData = {
      items: [
        {
          title: `Repasse ao Convênio Quiro Ferreira - ${req.user.name}`,
          unit_price: parseFloat(amount),
          quantity: 1,
          currency_id: 'BRL'
        }
      ],
      payer: {
        email: 'profissional@quiroferreira.com.br',
        name: req.user.name || 'Profissional Quiro Ferreira'
      },
      back_urls: {
        success: `${req.protocol}://${req.get('host')}/payment/success`,
        failure: `${req.protocol}://${req.get('host')}/payment/failure`,
        pending: `${req.protocol}://${req.get('host')}/payment/pending`
      },
      auto_return: 'approved',
      external_reference: `professional_payment_${req.user.id}_${Date.now()}`,
      notification_url: `${req.protocol}://${req.get('host')}/api/webhooks/mercadopago`,
      statement_descriptor: 'QUIRO FERREIRA'
    };

    const response = await preferenceClient.create({ body: preferenceData });
    
    console.log('✅ Professional payment preference created successfully');
    console.log('🔗 Init point:', response.init_point);
    
    res.json({ 
      init_point: response.init_point,
      preference_id: response.id 
    });
  } catch (error) {
    console.error('Error creating professional payment:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento',
      details: error.message 
    });
  }
});

// 🔥 NEW: MercadoPago webhook endpoint for payment notifications
app.post('/api/webhooks/mercadopago', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    console.log('🔔 MercadoPago webhook received');
    console.log('📦 Webhook data:', req.body);
    
    // For now, just acknowledge the webhook
    // In the future, you can process payment status updates here
    res.status(200).send('OK');
  } catch (error) {
    console.error('❌ Error processing MercadoPago webhook:', error);
    res.status(500).send('Error');
  }
});

// Payment result pages
app.get('/payment/success', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Pagamento Aprovado</title>
      <meta charset="UTF-8">
      <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f0f9ff; }
        .container { max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .success { color: #059669; font-size: 24px; margin-bottom: 20px; }
        .button { background: #c11c22; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; margin-top: 20px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="success">✅ Pagamento Aprovado!</div>
        <p>Seu pagamento foi processado com sucesso.</p>
        <a href="/" class="button">Voltar ao Sistema</a>
      </div>
    </body>
    </html>
  `);
});

app.get('/payment/failure', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Pagamento Rejeitado</title>
      <meta charset="UTF-8">
      <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #fef2f2; }
        .container { max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .error { color: #dc2626; font-size: 24px; margin-bottom: 20px; }
        .button { background: #c11c22; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; margin-top: 20px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="error">❌ Pagamento Rejeitado</div>
        <p>Houve um problema com seu pagamento. Tente novamente.</p>
        <a href="/" class="button">Voltar ao Sistema</a>
      </div>
    </body>
    </html>
  `);
});

app.get('/payment/pending', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Pagamento Pendente</title>
      <meta charset="UTF-8">
      <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #fffbeb; }
        .container { max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .pending { color: #d97706; font-size: 24px; margin-bottom: 20px; }
        .button { background: #c11c22; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; margin-top: 20px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="pending">⏳ Pagamento Pendente</div>
        <p>Seu pagamento está sendo processado. Aguarde a confirmação.</p>
        <a href="/" class="button">Voltar ao Sistema</a>
      </div>
    </body>
    </html>
  `);
});

// Catch-all route for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'dist', 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ message: 'Erro interno do servidor' });
});

// 🔥 INITIALIZE DATABASE AND START SERVER
const startServer = async () => {
  try {
    console.log('🚀 Starting Convênio Quiro Ferreira Server...');
    
    // Setup database first
    await setupDatabase();
    
    // Start server
    app.listen(PORT, () => {
      console.log(`✅ Server running on port ${PORT}`);
      console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`📊 Database: Connected and configured`);
      console.log(`🔒 CORS enabled for production domains`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();