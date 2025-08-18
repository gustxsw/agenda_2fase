tations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        SUM(c.value * ((100 - COALESCE(u.percentage, 50)) / 100)) as amount_to_pay
      FROM consultations c
      JOIN users u ON c.professional_id = u.id
      WHERE c.professional_id = $1 AND c.date BETWEEN $2 AND $3
      GROUP BY u.percentage`,
      [req.user.id, start_date, end_date]
    );

    const summary = result.rows[0] || {
      professional_percentage: 50,
      total_revenue: 0,
      total_consultations: 0,
      convenio_revenue: 0,
      private_revenue: 0,
      convenio_consultations: 0,
      private_consultations: 0,
      amount_to_pay: 0,
    };

    res.json({
      summary: {
        professional_percentage: parseFloat(summary.professional_percentage) || 50,
        total_revenue: parseFloat(summary.total_revenue) || 0,
        total_consultations: parseInt(summary.total_consultations) || 0,
        convenio_revenue: parseFloat(summary.convenio_revenue) || 0,
        private_revenue: parseFloat(summary.private_revenue) || 0,
        convenio_consultations: parseInt(summary.convenio_consultations) || 0,
        private_consultations: parseInt(summary.private_consultations) || 0,
        amount_to_pay: parseFloat(summary.amount_to_pay) || 0,
      },
    });
  } catch (error) {
    console.error("Error generating detailed professional report:", error);
    res.status(500).json({ message: "Erro ao gerar relatório detalhado" });
  }
});

app.get("/api/reports/clients-by-city", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        city,
        state,
        COUNT(*) as client_count,
        COUNT(CASE WHEN subscription_status = 'active' THEN 1 END) as active_clients,
        COUNT(CASE WHEN subscription_status = 'pending' THEN 1 END) as pending_clients,
        COUNT(CASE WHEN subscription_status = 'expired' THEN 1 END) as expired_clients
      FROM users 
      WHERE 'client' = ANY(roles) AND city IS NOT NULL AND city != ''
      GROUP BY city, state
      ORDER BY client_count DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("Error generating clients by city report:", error);
    res.status(500).json({ message: "Erro ao gerar relatório de clientes por cidade" });
  }
});

app.get("/api/reports/professionals-by-city", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        city,
        state,
        COUNT(*) as total_professionals,
        json_agg(
          json_build_object(
            'category_name', COALESCE(category_name, 'Sem categoria'),
            'count', 1
          )
        ) as categories
      FROM users 
      WHERE 'professional' = ANY(roles) AND city IS NOT NULL AND city != ''
      GROUP BY city, state
      ORDER BY total_professionals DESC
    `);

    const processedResult = result.rows.map(row => ({
      ...row,
      categories: Object.values(
        row.categories.reduce((acc, cat) => {
          const key = cat.category_name;
          if (acc[key]) {
            acc[key].count += cat.count;
          } else {
            acc[key] = { ...cat };
          }
          return acc;
        }, {})
      ),
    }));

    res.json(processedResult);
  } catch (error) {
    console.error("Error generating professionals by city report:", error);
    res.status(500).json({ message: "Erro ao gerar relatório de profissionais por cidade" });
  }
});

// MercadoPago payment routes
app.post("/api/create-subscription", authenticate, async (req, res) => {
  try {
    const { user_id } = req.body;

    if (!user_id) {
      return res.status(400).json({ message: "User ID é obrigatório" });
    }

    if (!mercadoPagoClient) {
      return res.status(500).json({ message: "MercadoPago não configurado" });
    }

    const preference = new Preference(mercadoPagoClient);

    const preferenceData = {
      items: [
        {
          title: "Assinatura Convênio Quiro Ferreira - Titular",
          quantity: 1,
          unit_price: 250,
          currency_id: "BRL",
        },
      ],
      payer: {
        email: "cliente@quiroferreira.com.br",
      },
      back_urls: {
        success: `${req.protocol}://${req.get("host")}/client?payment=success&type=subscription`,
        failure: `${req.protocol}://${req.get("host")}/client?payment=failure&type=subscription`,
        pending: `${req.protocol}://${req.get("host")}/client?payment=pending&type=subscription`,
      },
      auto_return: "approved",
      external_reference: `subscription_${user_id}`,
      notification_url: `${req.protocol}://${req.get("host")}/api/webhooks/mercadopago`,
    };

    const response = await preference.create({ body: preferenceData });

    res.json({
      id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point,
    });
  } catch (error) {
    console.error("Error creating subscription payment:", error);
    res.status(500).json({ message: "Erro ao criar pagamento da assinatura" });
  }
});

app.post("/api/dependents/:id/create-payment", authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    if (!mercadoPagoClient) {
      return res.status(500).json({ message: "MercadoPago não configurado" });
    }

    const dependentResult = await pool.query(
      "SELECT id, name, cpf, client_id, billing_amount FROM dependents WHERE id = $1",
      [id]
    );

    if (dependentResult.rows.length === 0) {
      return res.status(404).json({ message: "Dependente não encontrado" });
    }

    const dependent = dependentResult.rows[0];

    if (req.user.currentRole !== "admin" && req.user.id !== dependent.client_id) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    const preference = new Preference(mercadoPagoClient);

    const preferenceData = {
      items: [
        {
          title: `Ativação de Dependente - ${dependent.name}`,
          quantity: 1,
          unit_price: dependent.billing_amount || 50,
          currency_id: "BRL",
        },
      ],
      payer: {
        email: "cliente@quiroferreira.com.br",
      },
      back_urls: {
        success: `${req.protocol}://${req.get("host")}/client?payment=success&type=dependent`,
        failure: `${req.protocol}://${req.get("host")}/client?payment=failure&type=dependent`,
        pending: `${req.protocol}://${req.get("host")}/client?payment=pending&type=dependent`,
      },
      auto_return: "approved",
      external_reference: `dependent_${id}`,
      notification_url: `${req.protocol}://${req.get("host")}/api/webhooks/mercadopago`,
    };

    const response = await preference.create({ body: preferenceData });

    res.json({
      id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point,
    });
  } catch (error) {
    console.error("Error creating dependent payment:", error);
    res.status(500).json({ message: "Erro ao criar pagamento do dependente" });
  }
});

app.post("/api/professional/create-payment", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: "Valor deve ser maior que zero" });
    }

    if (!mercadoPagoClient) {
      return res.status(500).json({ message: "MercadoPago não configurado" });
    }

    const preference = new Preference(mercadoPagoClient);

    const preferenceData = {
      items: [
        {
          title: `Repasse ao Convênio - ${req.user.name}`,
          quantity: 1,
          unit_price: parseFloat(amount),
          currency_id: "BRL",
        },
      ],
      payer: {
        email: "profissional@quiroferreira.com.br",
      },
      back_urls: {
        success: `${req.protocol}://${req.get("host")}/professional?payment=success`,
        failure: `${req.protocol}://${req.get("host")}/professional?payment=failure`,
        pending: `${req.protocol}://${req.get("host")}/professional?payment=pending`,
      },
      auto_return: "approved",
      external_reference: `professional_payment_${req.user.id}_${Date.now()}`,
      notification_url: `${req.protocol}://${req.get("host")}/api/webhooks/mercadopago`,
    };

    const response = await preference.create({ body: preferenceData });

    res.json({
      id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point,
    });
  } catch (error) {
    console.error("Error creating professional payment:", error);
    res.status(500).json({ message: "Erro ao criar pagamento profissional" });
  }
});

// Webhook route for MercadoPago
app.post("/api/webhooks/mercadopago", async (req, res) => {
  try {
    console.log("🔔 MercadoPago webhook received:", req.body);

    const { type, data } = req.body;

    if (type === "payment") {
      const paymentId = data.id;
      console.log("💳 Processing payment:", paymentId);

      // Here you would typically:
      // 1. Fetch payment details from MercadoPago API
      // 2. Update subscription status based on external_reference
      // 3. Send confirmation emails, etc.

      console.log("✅ Payment webhook processed successfully");
    }

    res.status(200).json({ message: "Webhook processed" });
  } catch (error) {
    console.error("Error processing webhook:", error);
    res.status(500).json({ message: "Erro ao processar webhook" });
  }
});

// Catch-all route for SPA
app.get("*", (req, res) => {
  res.sendFile(path.join(process.cwd(), "dist", "index.html"));
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error("Unhandled error:", error);
  res.status(500).json({ message: "Erro interno do servidor" });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || "development"}`);
});